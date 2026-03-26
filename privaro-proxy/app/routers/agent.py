"""
Agent API — Phase 8
Endpoints for AI agent governance:
  POST /v1/agent/run/start  — create an agent run, returns agent_run_id
  POST /v1/agent/protect    — protect a step (prompt + optional tool outputs)
  POST /v1/agent/reveal     — detokenise a full run for final output
  POST /v1/agent/run/end    — close a run and finalise counters

Authentication: X-Privaro-Key header (same as /v1/proxy/protect)
"""
import time
import uuid
import hashlib
import os
import base64
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import app.services.supabase as db
import app.services.policy_engine as pe
import app.services.detector as detector
from app.services.auth import verify_api_key_or_dev
from app.config import settings

router = APIRouter(prefix="/v1/agent", tags=["agent"])


# ── Request / Response models ──────────────────────────────────────────────────

class AgentRunStartRequest(BaseModel):
    pipeline_id: str
    agent_name: Optional[str] = None
    agent_framework: Optional[str] = None
    external_run_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}


class AgentRunStartResponse(BaseModel):
    agent_run_id: str
    pipeline_id: str
    status: str = "running"
    message: str = "Agent run started. Use agent_run_id in subsequent /agent/protect calls."


class AgentMessage(BaseModel):
    role: str = Field(..., description="user|assistant|tool|system")
    content: str = Field(..., min_length=1, max_length=100000)
    step_type: str = Field("prompt", description="prompt|tool_output|system|observation")
    tool_name: Optional[str] = None


class AgentProtectRequest(BaseModel):
    agent_run_id: str
    messages: List[AgentMessage] = Field(..., min_items=1, max_items=50)
    step_index: Optional[int] = None
    mode: str = Field("tokenise", description="tokenise|anonymise|block")


class ProtectedMessage(BaseModel):
    role: str
    content: str
    step_type: str
    pii_count: int
    tokens_created: int


class AgentProtectResponse(BaseModel):
    request_id: str
    agent_run_id: str
    step_index: int
    protected_messages: List[ProtectedMessage]
    total_pii_detected: int
    total_pii_masked: int
    risk_score: float
    gdpr_compliant: bool
    audit_step_id: Optional[str] = None


class AgentRevealRequest(BaseModel):
    agent_run_id: str
    text: str = Field(..., description="Text containing [TYPE-XXXX] tokens to detokenise")


class AgentRevealResponse(BaseModel):
    agent_run_id: str
    revealed_text: str
    tokens_replaced: int


class AgentRunEndRequest(BaseModel):
    agent_run_id: str
    status: str = Field("completed", description="completed|failed|cancelled")


class AgentRunEndResponse(BaseModel):
    agent_run_id: str
    status: str
    step_count: int
    total_pii_detected: int
    total_pii_masked: int
    max_risk_score: float
    gdpr_compliant: bool


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/run/start", response_model=AgentRunStartResponse)
async def agent_run_start(
    body: AgentRunStartRequest,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """Create an agent run. Returns agent_run_id for subsequent /agent/protect calls."""
    pipeline = await db.get_pipeline(body.pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    run_id = await db.create_agent_run(
        org_id=pipeline["org_id"],
        pipeline_id=body.pipeline_id,
        api_key_id=key_record.get("id"),
        agent_name=body.agent_name,
        agent_framework=body.agent_framework,
        external_run_id=body.external_run_id,
        metadata=body.metadata or {},
    )
    if not run_id:
        raise HTTPException(status_code=500, detail={"error": "failed_to_create_run"})

    return AgentRunStartResponse(agent_run_id=run_id, pipeline_id=body.pipeline_id)


@router.post("/protect", response_model=AgentProtectResponse)
async def agent_protect(
    body: AgentProtectRequest,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Protect a step in an agent run.
    Accepts an array of messages (prompt + tool outputs).
    Returns the same array with PII tokenised/anonymised.
    Tokens are scoped to agent_run_id — same PII = same token throughout the run.
    """
    t0 = time.monotonic()
    request_id = f"agnt_{uuid.uuid4().hex[:12]}"

    run = await db.get_agent_run(body.agent_run_id, key_record["org_id"])
    if not run:
        raise HTTPException(status_code=404, detail={"error": "agent_run_not_found"})
    if run["status"] != "running":
        raise HTTPException(status_code=409, detail={"error": "agent_run_not_active", "status": run["status"]})

    pipeline = await db.get_pipeline(run["pipeline_id"])
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})

    org_id = pipeline["org_id"]
    step_index = body.step_index if body.step_index is not None else run.get("step_count", 0)

    policies = await db.get_policy_rules(org_id, pipeline_id=run["pipeline_id"]) or []
    provider_trust = await db.get_provider_trust(pipeline.get("llm_provider", ""), org_id)
    provider_risk_level = (provider_trust or {}).get("provider_risk_level", "medium")

    policy_context = {
        "provider": pipeline.get("llm_provider", ""),
        "user_role": key_record.get("role", "developer"),
        "data_region": (provider_trust or {}).get("data_region", "EU"),
        "agent_mode": True,
        "pipeline_sector": pipeline.get("sector", "general"),
        "default_action": body.mode,
    }

    protected_messages = []
    all_detections = []
    total_created = 0

    for msg in body.messages:
        detections = detector.detect(msg.content)
        protected_content = msg.content
        tokens_created_msg = 0

        if detections:
            if policies:
                detections = pe.apply_policies(detections, policies, policy_context)
            protected_content, tokens_created_msg = await _apply_agent_tokenisation(
                text=msg.content,
                detections=detections,
                org_id=org_id,
                pipeline_id=run["pipeline_id"],
                agent_run_id=body.agent_run_id,
            )

        all_detections.extend(detections)
        total_created += tokens_created_msg
        protected_messages.append(ProtectedMessage(
            role=msg.role,
            content=protected_content,
            step_type=msg.step_type,
            pii_count=len(detections),
            tokens_created=tokens_created_msg,
        ))

    risk_score = pe.compute_risk_score(all_detections, provider_risk_level, True, 0)
    pii_detected = len(all_detections)
    pii_masked = sum(1 for d in all_detections if d.action in ("tokenised", "anonymised", "blocked"))
    gdpr_ok = all(d.action != "blocked" or d.severity != "critical" for d in all_detections)
    processing_ms = int((time.monotonic() - t0) * 1000)

    step_id = await db.create_agent_step(
        agent_run_id=body.agent_run_id,
        org_id=org_id,
        step_index=step_index,
        role=body.messages[0].role if body.messages else "user",
        step_type=body.messages[0].step_type if body.messages else "prompt",
        prompt_hash=hashlib.sha256(" ".join(m.content for m in body.messages).encode()).hexdigest()[:32],
        pii_detected=pii_detected,
        pii_masked=pii_masked,
        risk_score=risk_score,
        gdpr_compliant=gdpr_ok,
        processing_ms=processing_ms,
    )

    return AgentProtectResponse(
        request_id=request_id,
        agent_run_id=body.agent_run_id,
        step_index=step_index,
        protected_messages=protected_messages,
        total_pii_detected=pii_detected,
        total_pii_masked=pii_masked,
        risk_score=round(risk_score, 4),
        gdpr_compliant=gdpr_ok,
        audit_step_id=step_id,
    )


@router.post("/reveal", response_model=AgentRevealResponse)
async def agent_reveal(
    body: AgentRevealRequest,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Detokenise text using the token map of an agent run.
    Fetches all reversible tokens from vault, decrypts originals with
    AES-256-GCM using the same ENCRYPTION_KEY as /v1/proxy/protect,
    and replaces [TYPE-XXXX] tokens in the text with real values.
    """
    run = await db.get_agent_run(body.agent_run_id, key_record["org_id"])
    if not run:
        raise HTTPException(status_code=404, detail={"error": "agent_run_not_found"})

    # Fetch raw vault rows (token_value + encrypted_original)
    vault_rows = await db.get_agent_run_vault_rows(
        agent_run_id=body.agent_run_id,
        org_id=key_record["org_id"],
    )

    if not vault_rows:
        return AgentRevealResponse(
            agent_run_id=body.agent_run_id,
            revealed_text=body.text,
            tokens_replaced=0,
        )

    # Decrypt each token's original value
    enc_key = _get_encryption_key()
    token_map: Dict[str, str] = {}

    for row in vault_rows:
        token_value = row.get("token_value")
        encrypted_original = row.get("encrypted_original")
        if not token_value or not encrypted_original:
            continue
        try:
            original = _decrypt_aes_gcm(encrypted_original, enc_key)
            token_map[token_value] = original
        except Exception as e:
            print(f"[Reveal] Failed to decrypt token {token_value}: {e}")
            continue

    # Replace tokens in text (longest token first to avoid partial matches)
    revealed = body.text
    count = 0
    for token_value, original in sorted(token_map.items(), key=lambda x: len(x[0]), reverse=True):
        if token_value in revealed:
            revealed = revealed.replace(token_value, original)
            count += 1

    return AgentRevealResponse(
        agent_run_id=body.agent_run_id,
        revealed_text=revealed,
        tokens_replaced=count,
    )


@router.post("/run/end", response_model=AgentRunEndResponse)
async def agent_run_end(
    body: AgentRunEndRequest,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """Close an agent run. Updates status and finalises aggregated counters."""
    run = await db.get_agent_run(body.agent_run_id, key_record["org_id"])
    if not run:
        raise HTTPException(status_code=404, detail={"error": "agent_run_not_found"})

    closed = await db.close_agent_run(body.agent_run_id, body.status)
    if not closed:
        raise HTTPException(status_code=500, detail={"error": "failed_to_close_run"})

    run = await db.get_agent_run(body.agent_run_id, key_record["org_id"])
    return AgentRunEndResponse(
        agent_run_id=body.agent_run_id,
        status=run["status"],
        step_count=run.get("step_count", 0),
        total_pii_detected=run.get("total_pii_detected", 0),
        total_pii_masked=run.get("total_pii_masked", 0),
        max_risk_score=run.get("max_risk_score", 0.0),
        gdpr_compliant=run.get("gdpr_compliant", True),
    )


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def _get_encryption_key() -> bytes:
    """Return AES-256 key from settings. Same key used in /v1/proxy/protect."""
    try:
        return bytes.fromhex(settings.ENCRYPTION_KEY)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail={"error": "encryption_key_not_configured"}
        )


def _decrypt_aes_gcm(encrypted_b64: str, key: bytes) -> str:
    """
    Decrypt AES-256-GCM ciphertext.
    Format: base64(nonce[12] + ciphertext + tag[16])
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(encrypted_b64)
    nonce = raw[:12]
    ciphertext = raw[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


# ── Tokenisation helper ────────────────────────────────────────────────────────

def _make_token(entity_type: str, counter: int) -> str:
    """Generate a token like [NM-0001], [ID-0002], etc."""
    PREFIX_MAP = {
        "full_name": "NM", "dni": "ID", "nie": "ID", "email": "EM",
        "phone": "PH", "iban": "BK", "credit_card": "CC",
        "ip_address": "IP", "date_of_birth": "DT", "health_record": "HR",
    }
    prefix = PREFIX_MAP.get(entity_type, entity_type[:2].upper())
    return f"[{prefix}-{counter:04d}]"


async def _apply_agent_tokenisation(
    text: str,
    detections: list,
    org_id: str,
    pipeline_id: str,
    agent_run_id: str,
) -> tuple:
    """
    Apply tokenisation with agent_run_id scope — BYOK-aware.
    Resolves org encryption key via key_manager (BYOK if configured).
    Returns (protected_text, tokens_created_count).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from app.services.key_manager import resolve_encryption_key, get_org_default_key_id

    # Resolve org encryption key — BYOK or managed
    enc_key_id = await get_org_default_key_id(org_id)
    try:
        enc_key = await resolve_encryption_key(enc_key_id, org_id)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"[Agent] Key resolution failed, using managed: {e}")
        from app.services.key_manager import _get_managed_key
        enc_key = _get_managed_key()
        enc_key_id = "key-v1"

    protected_text = text
    counters: dict = {}
    token_rows = []

    def _is_valid_name(d) -> bool:
        if d.type != "full_name":
            return True
        if d.start is None or d.end is None:
            return False
        original = text[d.start:d.end]
        if not original or not original[0].isupper() or len(original) < 3:
            return False
        if d.confidence < 0.75:
            return False
        return True

    sorted_dets = sorted(
        [d for d in detections
         if d.start is not None and d.end is not None and _is_valid_name(d)],
        key=lambda d: d.start,
        reverse=True,
    )

    for d in sorted_dets:
        if d.action == "anonymised":
            protected_text = protected_text[:d.start] + "[REDACTED]" + protected_text[d.end:]
            continue
        if d.action == "blocked":
            protected_text = protected_text[:d.start] + "[BLOCKED]" + protected_text[d.end:]
            continue
        if d.action not in ("tokenised", "pseudonymised"):
            continue

        original_value = text[d.start:d.end]
        entity_type = d.type
        counters[entity_type] = counters.get(entity_type, 0) + 1

        PREFIX_MAP = {
            "full_name": "NM", "dni": "ID", "nie": "ID", "email": "EM",
            "phone": "PH", "iban": "BK", "credit_card": "CC",
            "ip_address": "IP", "date_of_birth": "DT", "health_record": "HR",
        }
        prefix = PREFIX_MAP.get(entity_type, entity_type[:2].upper())
        token = f"[{prefix}-{counters[entity_type]:04d}]"
        d.token = token
        protected_text = protected_text[:d.start] + token + protected_text[d.end:]

        # Encrypt with org key (BYOK or managed)
        import os, base64
        nonce = os.urandom(12)
        aesgcm = AESGCM(enc_key)
        ciphertext = aesgcm.encrypt(nonce, original_value.encode("utf-8"), None)
        encrypted = base64.b64encode(nonce + ciphertext).decode("utf-8")

        token_rows.append({
            "org_id": org_id,
            "pipeline_id": pipeline_id,
            "agent_run_id": agent_run_id,
            "conversation_id": None,
            "entity_type": entity_type,
            "token_value": token,
            "encrypted_original": encrypted,
            "encryption_key_id": enc_key_id,   # ← BYOK-aware
            "is_reversible": True,
        })

    if token_rows:
        import app.services.supabase as db
        await db.insert_tokens_batch(token_rows)

    return protected_text, len(token_rows)
