"""
Relay Router — POST /v1/relay/complete

Full-cycle endpoint:
    1. Receive messages + pipeline_id
    2. Detect & tokenise PII (same as /v1/proxy/protect)
    3. Fetch customer API key from llm_providers (decrypted in-memory)
    4. Route tokenised messages to configured LLM provider
    5. Optionally de-tokenise LLM response
    6. Return response + audit trail + iBS certification

The customer configures their LLM provider API keys at /app/admin/providers.
Privaro stores them encrypted and decrypts them only at request time.
"""
import time
import uuid
import hashlib
import os
import base64
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

from app.services.auth import verify_api_key_or_dev
from app.services import supabase as db
from app.services import ibs
from app.services import detector
from app.services import policy_engine as pe
from app.services import quota as quota_svc
from app.services.key_manager import resolve_encryption_key, get_org_default_key_id
from app.services.llm_router import route, route_stream, LLMRouterError, list_providers

router = APIRouter(prefix="/v1/relay", tags=["relay"])

PREFIX_MAP = {
    "full_name": "NM", "dni": "ID", "nie": "ID", "iban": "BK",
    "credit_card": "CC", "email": "EM", "phone": "PH",
    "health_record": "HC", "ip_address": "IP", "date_of_birth": "DT",
}


async def _protect_messages(messages, org_id, pipeline_id, provider, sector, user_role, mode, conversation_id=None):
    """
    Shared PII-protection logic for both /complete and /stream. Factored out
    2026-07 when adding streaming, so both paths run exactly the same
    detection/tokenisation instead of it drifting between two copies.

    Cross-turn token consistency added 2026-07-23 (roadmap item — Robin/
    Octupus need the same PII value to get the SAME token across turns of
    the same conversation, not a fresh [EM-0001] every single call). This
    endpoint previously had NO token persistence at all — /v1/proxy/protect
    did, but it turned out to be broken there too (see find_existing_token's
    fix in supabase.py: it compared AES-GCM ciphertext, which has a random
    nonce and can never match itself twice). Both are now fixed together
    using a deterministic SHA-256 hash of the plaintext as the lookup key.

    Returns (protected_messages, all_detections, token_map, provider_risk_level, token_rows).
    token_rows is what the caller should background-task into tokens_vault —
    already excludes anything that was found and reused from an earlier turn.
    """
    policies = await db.get_policy_rules(org_id, pipeline_id=pipeline_id) or []
    provider_trust = await db.get_provider_trust(provider, org_id)
    provider_risk_level = (provider_trust or {}).get("provider_risk_level", "medium")

    policy_context = {
        "provider": provider,
        "user_role": user_role,
        "data_region": (provider_trust or {}).get("data_region", "EU"),
        "agent_mode": False,
        "pipeline_sector": sector,
        "default_action": mode,
    }

    enc_key = None
    enc_key_id = None
    if conversation_id:
        enc_key_id = await get_org_default_key_id(org_id)
        try:
            enc_key = await resolve_encryption_key(enc_key_id, org_id)
        except Exception as e:
            print(f"[Vault] Key resolution failed, falling back to managed: {e}")
            from app.services.key_manager import _get_managed_key
            enc_key = _get_managed_key()
            enc_key_id = "key-v1"

    protected_messages = []
    all_detections = []
    token_map: Dict[str, str] = {}
    token_rows: List[Dict[str, Any]] = []

    for msg in messages:
        detections = detector.detect(msg.content)
        if detections and policies:
            detections = pe.apply_policies(detections, policies, policy_context)
        elif detections:
            for d in detections:
                d.action = mode if mode in ("tokenise", "anonymise", "block") else "tokenised"

        protected_content = msg.content
        counters: Dict[str, int] = {}

        for d in reversed(detections):
            if d.start is None or d.end is None:
                continue
            original_value = msg.content[d.start:d.end]

            if d.action in ("tokenised", "pseudonymised", "tokenise"):
                entity_type = d.type
                reused_token = None

                if conversation_id and enc_key:
                    original_hash = hashlib.sha256(original_value.encode("utf-8")).hexdigest()
                    existing = await db.find_existing_token(
                        org_id=org_id, conversation_id=conversation_id,
                        entity_type=entity_type, original_value_hash=original_hash,
                    )
                    if existing:
                        reused_token = existing["token_value"]

                if reused_token:
                    token = reused_token
                else:
                    counters[entity_type] = counters.get(entity_type, 0) + 1
                    prefix = PREFIX_MAP.get(entity_type, entity_type[:2].upper())
                    token = f"[{prefix}-{counters[entity_type]:04d}]"

                    if conversation_id and enc_key:
                        try:
                            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                            aesgcm = AESGCM(enc_key)
                            nonce = os.urandom(12)
                            ciphertext = aesgcm.encrypt(nonce, original_value.encode("utf-8"), None)
                            encrypted = base64.b64encode(nonce + ciphertext).decode("utf-8")
                            token_rows.append({
                                "org_id": org_id, "pipeline_id": pipeline_id,
                                "entity_type": entity_type, "token_value": token,
                                "encrypted_original": encrypted,
                                "original_value_hash": hashlib.sha256(original_value.encode("utf-8")).hexdigest(),
                                "encryption_key_id": enc_key_id, "is_reversible": True,
                                "access_roles": ["admin", "dpo"], "conversation_id": conversation_id,
                            })
                        except Exception as e:
                            print(f"[Vault] Encryption error (relay): {e}")

                d.token = token
                d.action = "tokenised"
                token_map[token] = original_value
                protected_content = protected_content[:d.start] + token + protected_content[d.end:]
            elif d.action in ("anonymised", "anonymise"):
                d.action = "anonymised"
                protected_content = (protected_content[:d.start] +
                                     f"[{d.type.upper()}]" + protected_content[d.end:])

        all_detections.extend(detections)
        protected_messages.append({"role": msg.role, "content": protected_content})

    return protected_messages, all_detections, token_map, provider_risk_level, token_rows


class RelayMessage(BaseModel):
    role: str = Field(..., description="user | assistant | system")
    content: str = Field(..., min_length=1, max_length=50000)


class RelayOptions(BaseModel):
    mode: str = "tokenise"
    detokenise_response: bool = True
    include_detections: bool = True
    max_tokens: int = 2048
    temperature: float = 0.7
    system_prompt: Optional[str] = None


class RelayRequest(BaseModel):
    pipeline_id: str
    messages: List[RelayMessage] = Field(..., min_items=1, max_items=50)
    provider: Optional[str] = None      # Override pipeline provider
    model: Optional[str] = None         # Override pipeline model
    options: RelayOptions = RelayOptions()
    conversation_id: Optional[str] = None


class RelayResponse(BaseModel):
    request_id: str
    provider: str
    model: str
    protected_messages: List[Dict]
    pii_detected: int
    pii_masked: int
    risk_score: float
    gdpr_compliant: bool
    response: str
    response_raw: Optional[str] = None
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
    Full-cycle privacy relay.

    Privaro fetches the customer's LLM API key from their provider config
    (/app/admin/providers), decrypts it in-memory, and routes the tokenised
    request to their LLM. The key is never logged or stored beyond the request.
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

    # ── 1b. Quota check (was missing here before 2026-07 — /relay/complete
    # is a real LLM call path, it must be metered like /proxy/protect) ──────
    await quota_svc.check_and_increment(org_id)

    # ── 2. Protect all messages ───────────────────────────────────────────────
    protected_messages, all_detections, token_map, provider_risk_level, token_rows = await _protect_messages(
        body.messages, org_id, body.pipeline_id, provider,
        pipeline.get("sector", "general"), key_record.get("role", "developer"), body.options.mode,
        conversation_id=body.conversation_id,
    )
    if token_rows:
        background_tasks.add_task(db.insert_tokens_batch, token_rows)

    risk_score = pe.compute_risk_score(all_detections, provider_risk_level, False, 0)
    pii_detected = len(all_detections)
    pii_masked = sum(1 for d in all_detections if d.action in ("tokenised", "anonymised"))
    gdpr_compliant = all(d.action != "blocked" for d in all_detections)

    # ── 3. Call LLM — key fetched from customer's provider config ────────────
    try:
        llm_result = await route(
            provider=provider,
            messages=protected_messages,
            org_id=org_id,          # ← key resolved from llm_providers table
            model=model,
            max_tokens=body.options.max_tokens,
            temperature=body.options.temperature,
            system=body.options.system_prompt,
        )
    except LLMRouterError as e:
        raise HTTPException(
            status_code=e.status_code or 502,
            detail={
                "error": "llm_provider_error",
                "message": str(e),
                "provider": e.provider,
                "hint": "Configure your LLM provider API key at /app/admin/providers"
            }
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
        background_tasks.add_task(ibs.certify_audit_log, audit_log_id, org_id,
                                   {"request_id": request_id, "provider": provider})

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


# ── /v1/relay/stream — added 2026-07 ────────────────────────────────────────
# Same contract as /complete, but streams the LLM's response back as it's
# generated (SSE), for chat products that show responses token-by-token.
# Gated by organizations.streaming_enabled (default true) — an admin can
# turn this off from their dashboard (Billing → Security Configuration) if
# they'd rather every response go through the non-streaming /complete path.

import json as _json


def _find_safe_flush_point(buf: str) -> int:
    """
    Index up to which `buf` is safe to emit without risking cutting a
    [XX-NNNN] token in half across two stream chunks. Looks for the last
    unclosed '[' — if found, everything from there onward is held back
    until a matching ']' arrives in a later chunk.
    """
    last_open = buf.rfind("[")
    if last_open == -1:
        return len(buf)
    if "]" in buf[last_open:]:
        return len(buf)
    return last_open


def _detokenise(text: str, token_map: Dict[str, str]) -> str:
    for token, original in sorted(token_map.items(), key=lambda x: len(x[0]), reverse=True):
        if token in text:
            text = text.replace(token, original)
    return text


@router.post("/stream")
async def relay_stream(
    body: RelayRequest,
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    t0 = time.monotonic()
    request_id = f"relaystream_{uuid.uuid4().hex[:12]}"
    audit_log_id = str(uuid.uuid4())

    pipeline = await db.get_pipeline(body.pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    org_id = pipeline["org_id"]

    org = await db.get_organization(org_id)
    if org and org.get("streaming_enabled") is False:
        raise HTTPException(
            status_code=403,
            detail={"error": "streaming_disabled",
                    "message": "Streaming is turned off for this organization. "
                               "An admin can enable it from Billing → Security "
                               "Configuration, or use /v1/relay/complete instead."},
        )

    await quota_svc.check_and_increment(org_id)

    provider = body.provider or pipeline.get("llm_provider", "anthropic")
    model = body.model or pipeline.get("llm_model")

    protected_messages, all_detections, token_map, provider_risk_level, token_rows = await _protect_messages(
        body.messages, org_id, body.pipeline_id, provider,
        pipeline.get("sector", "general"), key_record.get("role", "developer"), body.options.mode,
        conversation_id=body.conversation_id,
    )
    if token_rows:
        background_tasks.add_task(db.insert_tokens_batch, token_rows)
    risk_score = pe.compute_risk_score(all_detections, provider_risk_level, False, 0)
    pii_detected = len(all_detections)
    pii_masked = sum(1 for d in all_detections if d.action in ("tokenised", "anonymised"))

    async def event_generator():
        buf = ""
        full_response_parts = []
        try:
            async for chunk in route_stream(
                provider=provider, messages=protected_messages, org_id=org_id,
                model=model, max_tokens=body.options.max_tokens,
                temperature=body.options.temperature, system=body.options.system_prompt,
            ):
                buf += chunk
                safe_point = _find_safe_flush_point(buf)
                if safe_point > 0:
                    to_emit = buf[:safe_point]
                    buf = buf[safe_point:]
                    if body.options.detokenise_response:
                        to_emit = _detokenise(to_emit, token_map)
                    full_response_parts.append(to_emit)
                    yield f"data: {_json.dumps({'delta': to_emit})}\n\n"
        except LLMRouterError as e:
            yield f"data: {_json.dumps({'error': str(e), 'provider': e.provider})}\n\n"
            yield "data: [DONE]\n\n"
            return

        if buf:
            if body.options.detokenise_response:
                buf = _detokenise(buf, token_map)
            full_response_parts.append(buf)
            yield f"data: {_json.dumps({'delta': buf})}\n\n"

        yield "data: [DONE]\n\n"

        # Best-effort audit log after the stream completes — never blocks
        # or delays anything the caller sees, same philosophy as /protect.
        processing_ms = int((time.monotonic() - t0) * 1000)
        primary_msg = body.messages[0].content if body.messages else ""
        await db.insert_audit_log({
            "id": audit_log_id,
            "org_id": org_id, "pipeline_id": body.pipeline_id,
            "event_type": "relay_stream",
            "entity_type": all_detections[0].type if all_detections else "none",
            "entity_category": pe._get_category(all_detections[0].type) if all_detections else "none",
            "action_taken": "tokenised" if pii_masked > 0 else "passed",
            "severity": "high" if risk_score > 0.7 else "medium" if risk_score > 0.4 else "low",
            "prompt_hash": hashlib.sha256(primary_msg.encode()).hexdigest(),
            "pipeline_stage": "relay_stream",
            "processing_ms": processing_ms,
            "ibs_status": "pending", "source": "relay_stream",
            "risk_score": risk_score, "agent_mode": False,
            "conversation_id": body.conversation_id,
            "metadata": {"request_id": request_id, "provider": provider, "model": model,
                         "total_detected": pii_detected, "total_masked": pii_masked},
        })
        await ibs.certify_audit_log(audit_log_id, org_id, {"request_id": request_id, "provider": provider})

    return StreamingResponse(event_generator(), media_type="text/event-stream")
