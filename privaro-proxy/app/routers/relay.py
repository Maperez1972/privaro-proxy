"""
Relay Router — POST /v1/relay/complete

Full-cycle endpoint:
    1. Receive prompt + pipeline_id + provider config
    2. Detect & tokenise PII (same as /v1/proxy/protect)
    3. Route tokenised messages to the configured LLM provider
    4. Optionally de-tokenise the LLM response
    5. Return protected prompt + LLM response + audit trail

This is the "one-shot" endpoint for ISVs who want Privaro to handle
both the privacy layer AND the LLM call transparently.

Supported providers: anthropic | openai | mistral | gemini
"""
import time
import uuid
import hashlib
import os
import base64
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

from app.services.auth import verify_api_key_or_dev
from app.services import supabase as db
from app.services import ibs
from app.services import detector
from app.services import policy_engine as pe
from app.services.key_manager import resolve_encryption_key, get_org_default_key_id
from app.services.llm_router import route, LLMRouterError, list_providers
from app.config import settings

router = APIRouter(prefix="/v1/relay", tags=["relay"])


class RelayMessage(BaseModel):
    role: str = Field(..., description="user | assistant | system")
    content: str = Field(..., min_length=1, max_length=50000)


class RelayOptions(BaseModel):
    mode: str = "tokenise"              # tokenise | anonymise | block
    detokenise_response: bool = True    # Replace tokens in LLM response
    include_detections: bool = True
    max_tokens: int = 2048
    temperature: float = 0.7
    system_prompt: Optional[str] = None


class RelayRequest(BaseModel):
    pipeline_id: str
    messages: List[RelayMessage] = Field(..., min_items=1, max_items=50)
    provider: Optional[str] = None      # Override pipeline provider
    model: Optional[str] = None         # Override pipeline model
    customer_api_key: Optional[str] = None  # Customer-provided LLM key
    options: RelayOptions = RelayOptions()
    conversation_id: Optional[str] = None


class RelayResponse(BaseModel):
    request_id: str
    provider: str
    model: str
    # Privacy layer results
    protected_messages: List[Dict]      # Messages sent to LLM (tokenised)
    pii_detected: int
    pii_masked: int
    risk_score: float
    gdpr_compliant: bool
    # LLM response
    response: str                       # Final response (de-tokenised if requested)
    response_raw: Optional[str] = None  # Raw LLM response with tokens (if detokenise=True)
    # Audit
    audit_log_id: Optional[str] = None
    tokens_replaced: int = 0
    usage: Dict[str, Any] = {}
    processing_ms: int = 0


@router.post("/complete", response_model=RelayResponse)
async def relay_complete(
    body: RelayRequest,
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Full-cycle privacy relay:
    Detect PII → Tokenise → Call LLM → De-tokenise → Return

    The LLM never sees raw PII. Every interaction is audit-logged and
    blockchain-certified via iBS.
    """
    t0 = time.monotonic()
    request_id = f"relay_{uuid.uuid4().hex[:12]}"

    # ── 1. Validate pipeline ──────────────────────────────────────────────────
    pipeline = await db.get_pipeline(body.pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    org_id = pipeline["org_id"]
    provider = body.provider or pipeline.get("llm_provider", "anthropic")
    model = body.model or pipeline.get("llm_model")

    # ── 2. Protect all messages ───────────────────────────────────────────────
    protected_messages = []
    all_detections = []
    token_map: Dict[str, str] = {}  # token → original (for de-tokenisation)
    enc_key = None
    enc_key_id = None
    
    # Resolve encryption key once for all messages
    enc_key_id = await get_org_default_key_id(org_id)
    try:
        enc_key = await resolve_encryption_key(enc_key_id, org_id)
    except Exception:
        from app.services.key_manager import _get_managed_key
        enc_key = _get_managed_key()
        enc_key_id = "key-v1"

    policies = await db.get_policy_rules(org_id, pipeline_id=body.pipeline_id) or []
    provider_trust = await db.get_provider_trust(provider, org_id)
    provider_risk_level = (provider_trust or {}).get("provider_risk_level", "medium")

    policy_context = {
        "provider": provider,
        "user_role": key_record.get("role", "developer"),
        "data_region": (provider_trust or {}).get("data_region", "EU"),
        "agent_mode": False,
        "pipeline_sector": pipeline.get("sector", "general"),
        "default_action": body.options.mode,
    }

    for msg in body.messages:
        detections = detector.detect(msg.content)
        
        if detections and policies:
            detections = pe.apply_policies(detections, policies, policy_context)
        elif detections:
            for d in detections:
                d.action = body.options.mode if body.options.mode in ("tokenise", "anonymise", "block") else "tokenised"

        protected_content = msg.content
        counters: Dict[str, int] = {}

        for d in reversed(detections):
            if d.start is None or d.end is None:
                continue
            original_value = msg.content[d.start:d.end]

            if d.action in ("tokenised", "pseudonymised", "tokenise"):
                entity_type = d.type
                counters[entity_type] = counters.get(entity_type, 0) + 1
                prefix_map = {
                    "full_name": "NM", "dni": "ID", "nie": "ID", "iban": "BK",
                    "credit_card": "CC", "email": "EM", "phone": "PH",
                    "health_record": "HC", "ip_address": "IP", "date_of_birth": "DT",
                }
                prefix = prefix_map.get(entity_type, entity_type[:2].upper())
                token = f"[{prefix}-{counters[entity_type]:04d}]"
                d.token = token
                d.action = "tokenised"
                # Store reverse mapping for de-tokenisation
                token_map[token] = original_value
                protected_content = protected_content[:d.start] + token + protected_content[d.end:]

            elif d.action in ("anonymised", "anonymise"):
                d.action = "anonymised"
                protected_content = protected_content[:d.start] + f"[{d.type.upper()}]" + protected_content[d.end:]

        all_detections.extend(detections)
        protected_messages.append({"role": msg.role, "content": protected_content})

    risk_score = pe.compute_risk_score(all_detections, provider_risk_level, False, 0)
    pii_detected = len(all_detections)
    pii_masked = sum(1 for d in all_detections if d.action in ("tokenised", "anonymised"))
    gdpr_compliant = all(d.action != "blocked" for d in all_detections)

    # ── 3. Call LLM provider ──────────────────────────────────────────────────
    try:
        llm_result = await route(
            provider=provider,
            messages=protected_messages,
            model=model,
            customer_api_key=body.customer_api_key,
            max_tokens=body.options.max_tokens,
            temperature=body.options.temperature,
            system=body.options.system_prompt,
        )
    except LLMRouterError as e:
        raise HTTPException(
            status_code=e.status_code or 502,
            detail={"error": "llm_provider_error", "message": str(e), "provider": e.provider}
        )

    # ── 4. De-tokenise response ───────────────────────────────────────────────
    raw_response = llm_result["content"]
    final_response = raw_response
    tokens_replaced = 0

    if body.options.detokenise_response and token_map:
        for token, original in sorted(token_map.items(), key=lambda x: len(x[0]), reverse=True):
            if token in final_response:
                final_response = final_response.replace(token, original)
                tokens_replaced += 1

    processing_ms = int((time.monotonic() - t0) * 1000)

    # ── 5. Audit log ──────────────────────────────────────────────────────────
    primary_msg = body.messages[0].content if body.messages else ""
    audit_log_id = await db.insert_audit_log({
        "org_id": org_id,
        "pipeline_id": body.pipeline_id,
        "event_type": "relay_complete",
        "entity_type": all_detections[0].type if all_detections else "none",
        "entity_category": pe._get_category(all_detections[0].type) if all_detections else "none",
        "action_taken": "tokenised" if pii_masked > 0 else "passed",
        "severity": "high" if risk_score > 0.7 else "medium" if risk_score > 0.4 else "low",
        "prompt_hash": hashlib.sha256(primary_msg.encode()).hexdigest(),
        "pipeline_stage": "relay",
        "processing_ms": processing_ms,
        "ibs_status": "pending",
        "source": "relay",
        "risk_score": risk_score,
        "agent_mode": False,
        "conversation_id": body.conversation_id,
        "metadata": {
            "request_id": request_id,
            "provider": provider,
            "model": llm_result["model"],
            "total_detected": pii_detected,
            "total_masked": pii_masked,
            "tokens_replaced_in_response": tokens_replaced,
            "usage": llm_result.get("usage", {}),
        },
    })

    if audit_log_id:
        background_tasks.add_task(ibs.certify_audit_log, audit_log_id, org_id, {
            "request_id": request_id, "provider": provider
        })

    return RelayResponse(
        request_id=request_id,
        provider=llm_result["provider"],
        model=llm_result["model"],
        protected_messages=protected_messages,
        pii_detected=pii_detected,
        pii_masked=pii_masked,
        risk_score=round(risk_score, 4),
        gdpr_compliant=gdpr_compliant,
        response=final_response,
        response_raw=raw_response if body.options.detokenise_response and tokens_replaced > 0 else None,
        audit_log_id=audit_log_id,
        tokens_replaced=tokens_replaced,
        usage=llm_result.get("usage", {}),
        processing_ms=processing_ms,
    )


@router.get("/providers")
async def get_providers(
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """List supported LLM providers and their available models."""
    return {"providers": list_providers()}
