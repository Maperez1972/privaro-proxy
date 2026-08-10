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
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from app.models.schemas import _validate_conversation_id
from typing import Dict, Any, List, Optional

from app.services.auth import verify_api_key_or_internal
from app.services import supabase as db
from app.services import ibs
from app.services import detector
from app.services import policy_engine as pe
from app.services import quota as quota_svc
from app.services.key_manager import resolve_encryption_key, get_org_default_key_id
from app.services.llm_router import route, route_stream, LLMRouterError, list_providers
from app.services.context_optimizer import compress_with_timeout

router = APIRouter(prefix="/v1/relay", tags=["relay"])

PREFIX_MAP = {
    "full_name": "NM", "dni": "ID", "nie": "ID", "iban": "BK",
    "credit_card": "CC", "email": "EM", "phone": "PH",
    "health_record": "HC", "ip_address": "IP", "date_of_birth": "DT",
    "ssn": "SS", "passport": "PP",
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
                # Same root-cause fix as proxy.py's _apply_tokenization and
                # this file's own _scan_output_for_pii (2026-08): silently
                # skipping here left the detection unmasked in the text
                # that actually went to the LLM, with nothing ever
                # recording it — why total_leaked read 0 everywhere.
                d.action = "leaked"
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
                # Fixed 2026-08-07 — same bug as proxy.py's
                # _apply_tokenization: raw entity_type.upper() exposed
                # internal English identifiers ("[HEALTH_RECORD]") instead
                # of following the [XX-0001]-style convention.
                label = PREFIX_MAP.get(d.type, d.type[:2].upper())
                protected_content = (protected_content[:d.start] +
                                     f"[{label}-REDACTED]" + protected_content[d.end:])

        all_detections.extend(detections)
        protected_messages.append({"role": msg.role, "content": protected_content})

    return protected_messages, all_detections, token_map, provider_risk_level, token_rows


async def _scan_output_for_pii(
    raw_response: str,
    org_id: str,
    pipeline_id: str,
    provider: str,
    sector: str,
    user_role: str,
    mode: str,
    shadow: bool,
    conversation_id: Optional[str] = None,
) -> "OutputScanResult":
    """
    Added 2026-08 — output-direction PII detection.

    Confirmed via a direct audit of production data before writing this:
    conversation_messages had 1,175 PII detections across 76 user-role
    (input) messages and ZERO across 78 assistant-role (output) messages;
    pipelines.total_leaked was 0 across every single pipeline. The
    detector was never invoked on what the LLM sends back — only on what
    goes in. This closes that gap for the /v1/relay/* path, which is the
    one place Privaro already has the raw LLM response in hand (customers
    using /v1/proxy/protect standalone get the equivalent via the new
    POST /v1/proxy/protect-output endpoint, since Privaro never sees
    their LLM's response on that path).

    Runs the SAME regex/NLP detector used on input against the model's
    RAW response — i.e. BEFORE de-tokenising the caller's own [XX-0001]
    placeholders back to real values. Those placeholders never match a
    PII pattern, so this only ever flags genuinely NEW sensitive data
    that surfaced in the response itself: RAG/tool-call context leakage,
    cross-tenant contamination, or model memorisation — never data the
    caller already authorised earlier in the same conversation.

    Gated by pipeline.output_scanning_enabled (default false in the DB) —
    deploying this code changes nothing for any existing pipeline until a
    customer is explicitly opted in. output_scanning_mode='shadow'
    (the default once enabled) detects and audit-logs without altering
    the response, for safe validation before flipping to 'enforce'.
    """
    policies = await db.get_policy_rules(org_id, pipeline_id=pipeline_id) or []
    provider_trust = await db.get_provider_trust(provider, org_id)
    policy_context = {
        "provider": provider,
        "user_role": user_role,
        "data_region": (provider_trust or {}).get("data_region", "EU"),
        "agent_mode": False,
        "pipeline_sector": sector,
        "default_action": mode,
        "direction": "output",
    }

    detections = detector.detect(raw_response)
    if detections and policies:
        detections = pe.apply_policies(detections, policies, policy_context)
    elif detections:
        for d in detections:
            d.action = mode if mode in ("tokenise", "anonymise", "block") else "tokenised"

    if not detections:
        return OutputScanResult(raw_response, [], False, [])

    if shadow:
        # Detect + classify for audit purposes only. Response text returned
        # unmodified — this is the safe default for a pipeline's first
        # output-scanning period.
        return OutputScanResult(raw_response, detections, False, [])

    scanned = raw_response
    counters: Dict[str, int] = {}
    vault_rows: List[Dict[str, Any]] = []
    enc_key = None
    enc_key_id = None
    if conversation_id and any(d.action in ("tokenised", "pseudonymised", "tokenise") for d in detections):
        enc_key_id = await get_org_default_key_id(org_id)
        try:
            enc_key = await resolve_encryption_key(enc_key_id, org_id)
        except Exception as e:
            print(f"[Vault] Key resolution failed (output scan), falling back to managed: {e}")
            from app.services.key_manager import _get_managed_key
            enc_key = _get_managed_key()
            enc_key_id = "key-v1"

    for d in reversed(detections):
        if d.start is None or d.end is None:
            # Detected but couldn't be masked (no reliable span) — this IS
            # a real leak, not a silent no-op. Root-cause fix alongside
            # this feature: previously such detections were just skipped
            # with no state change at all, which is exactly why
            # pipelines.total_leaked has read 0 everywhere in production —
            # nothing ever set this action, on input OR output.
            d.action = "leaked"
            continue

        original_value = raw_response[d.start:d.end]

        if d.action in ("tokenised", "pseudonymised", "tokenise"):
            entity_type = d.type
            counters[entity_type] = counters.get(entity_type, 0) + 1
            prefix = PREFIX_MAP.get(entity_type, entity_type[:2].upper())
            token = f"[{prefix}-{counters[entity_type]:04d}]"
            d.token = token
            d.action = "tokenised"
            scanned = scanned[:d.start] + token + scanned[d.end:]

            if enc_key:
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    aesgcm = AESGCM(enc_key)
                    nonce = os.urandom(12)
                    ciphertext = aesgcm.encrypt(nonce, original_value.encode("utf-8"), None)
                    encrypted = base64.b64encode(nonce + ciphertext).decode("utf-8")
                    vault_rows.append({
                        "org_id": org_id, "pipeline_id": pipeline_id,
                        "entity_type": entity_type, "token_value": token,
                        "encrypted_original": encrypted,
                        "original_value_hash": hashlib.sha256(original_value.encode("utf-8")).hexdigest(),
                        "encryption_key_id": enc_key_id, "is_reversible": True,
                        "access_roles": ["admin", "dpo"], "conversation_id": conversation_id,
                    })
                except Exception as e:
                    print(f"[Vault] Encryption error (output scan): {e}")
        elif d.action in ("anonymised", "anonymise"):
            d.action = "anonymised"
            label = PREFIX_MAP.get(d.type, d.type[:2].upper())
            scanned = scanned[:d.start] + f"[{label}-REDACTED]" + scanned[d.end:]
        elif d.action == "blocked":
            # Span-level redaction, not whole-response blocking: unlike
            # /protect (a prompt with a hole is useless — you can't send a
            # half-prompt to an LLM), a response is already generated, so
            # masking just the offending span keeps the rest of an
            # otherwise-fine answer usable rather than discarding it
            # entirely.
            scanned = scanned[:d.start] + f"[BLOCKED:{d.type.upper()}]" + scanned[d.end:]
        # else: passed / no-op — leave text as-is

    return OutputScanResult(scanned, detections, True, vault_rows)


class OutputScanResult:
    """Small typed tuple substitute — keeps the 4 return values self-documenting
    at every call site instead of an anonymous tuple."""
    __slots__ = ("text", "detections", "modified", "vault_rows")

    def __init__(self, text, detections, modified, vault_rows):
        self.text = text
        self.detections = detections
        self.modified = modified
        self.vault_rows = vault_rows


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
    optimize_context: bool = False  # opt-in: compress tokenised messages before the LLM call


class RelayRequest(BaseModel):
    pipeline_id: str
    messages: List[RelayMessage] = Field(..., min_items=1, max_items=50)
    provider: Optional[str] = None      # Override pipeline provider
    model: Optional[str] = None         # Override pipeline model
    options: RelayOptions = RelayOptions()
    conversation_id: Optional[str] = None

    # Fixed 2026-07-24 — same fix as ProtectRequest/DetokenizeRequest/
    # ProtectStructuredRequest in schemas.py: conversation_id is stored in
    # a Postgres uuid column, so a non-UUID value here would silently
    # fail to save in the background token-insert task, same as it did
    # for /protect before this fix.
    _validate_conv_id = field_validator("conversation_id")(_validate_conversation_id)


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
    compression_stats: Dict[str, Any] = {}
    # Added 2026-08 — output-direction PII scan. All zero/None/false when
    # the pipeline hasn't opted into output_scanning_enabled (the default),
    # so existing integrations parsing this response see no shape change.
    output_pii_detected: int = 0
    output_pii_masked: int = 0
    output_pii_leaked: int = 0
    output_scan_mode: Optional[str] = None
    output_response_modified: bool = False
    output_audit_log_id: Optional[str] = None


@router.post("/complete", response_model=RelayResponse)
async def relay_complete(
    body: RelayRequest,
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_internal),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
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

    # Idempotency (roadmap #5) — this endpoint calls a REAL LLM, so a cache
    # hit here also saves the partner from paying for a duplicate LLM call
    # on retry, not just re-doing detection. Checked before quota so a
    # retry never counts twice. Only successful completions are cached (see
    # below) — an LLM-side failure must still be retryable for real.
    if idempotency_key:
        cached = await db.get_idempotent_response(org_id, idempotency_key, "relay_complete")
        if cached:
            return RelayResponse(**cached["response_body"])

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

    # ── Context Optimization (opt-in, gated by options.optimize_context) ────
    # Runs strictly AFTER tokenisation, never before. Privaro tokens
    # ([XX-0001]) are shielded from the compressor and their exact presence
    # is verified post-compression; on any mismatch or internal error this
    # fails open and returns protected_messages unmodified — same
    # philosophy as the rest of this proxy (never let an optimization
    # become a correctness incident).
    #
    # Fixed 2026-08-07 — CRITICAL, same finding as proxy.py: this called
    # compress_protected_messages() directly (sync, no await, no
    # executor), blocking the entire asyncio event loop for the whole
    # duration of a real transformer model's CPU inference (30+ seconds
    # observed on a ~14K char document) — freezing every other
    # concurrent request on this worker, not just this one. Now uses
    # compress_with_timeout(), offloaded to a thread pool with a bounded
    # worst-case latency (fails open past the timeout).
    compression_stats: Dict[str, Any] = {"tokens_saved": 0, "compression_ratio": 0.0, "skipped_reason": "disabled"}
    if getattr(body.options, "optimize_context", False):
        protected_messages, compression_stats = await compress_with_timeout(
            protected_messages, model=model,
        )

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

    # ── 3b. Output-direction PII scan (added 2026-08) ─────────────────────────
    # Runs on the RAW response, BEFORE de-tokenising — see _scan_output_for_pii
    # docstring. Strictly opt-in per pipeline (output_scanning_enabled), so
    # this is a no-op for every pipeline that hasn't been explicitly migrated.
    raw_response = llm_result["content"]
    output_detections: List = []
    output_scan_modified = False
    output_vault_rows: List[Dict[str, Any]] = []
    scanned_response = raw_response

    if pipeline.get("output_scanning_enabled"):
        shadow = pipeline.get("output_scanning_mode", "shadow") != "enforce"
        scan_result = await _scan_output_for_pii(
            raw_response, org_id, body.pipeline_id, provider,
            pipeline.get("sector", "general"), key_record.get("role", "developer"),
            body.options.mode, shadow=shadow, conversation_id=body.conversation_id,
        )
        scanned_response = scan_result.text
        output_detections = scan_result.detections
        output_scan_modified = scan_result.modified
        output_vault_rows = scan_result.vault_rows
        if output_vault_rows:
            background_tasks.add_task(db.insert_tokens_batch, output_vault_rows)

    # ── 4. De-tokenise response ───────────────────────────────────────────────
    # Runs on scanned_response (post output-scan) rather than the raw LLM
    # text, so a caller's own [XX-0001] placeholders are restored to real
    # values as before, while anything the output scan just masked stays
    # masked.
    final_response = scanned_response
    tokens_replaced = 0

    if body.options.detokenise_response and token_map:
        for token, original in sorted(token_map.items(), key=lambda x: len(x[0]), reverse=True):
            if token in final_response:
                final_response = final_response.replace(token, original)
                tokens_replaced += 1

    processing_ms = int((time.monotonic() - t0) * 1000)

    # ── 4b. Output-scan audit log (separate row, direction='output') ─────────
    # Kept distinct from the primary relay_complete audit_log below (which
    # stays exactly as it was, direction='input') so existing dashboards/
    # DPO reports that already read that row's shape are unaffected.
    output_audit_log_id: Optional[str] = None
    if output_detections:
        output_stats = detector.build_stats(output_detections, 0)
        output_risk_score = pe.compute_risk_score(output_detections, provider_risk_level, False, output_stats["leaked"])
        output_event_type = "output_pii_leaked" if output_stats["leaked"] > 0 else "output_pii_detected"
        output_audit_log_id = await db.insert_audit_log({
            "org_id": org_id,
            "pipeline_id": body.pipeline_id,
            "event_type": output_event_type,
            "entity_type": output_detections[0].type,
            "entity_category": pe._get_category(output_detections[0].type),
            "action_taken": output_detections[0].action,
            "severity": "high" if output_risk_score > 0.7 else "medium" if output_risk_score > 0.4 else "low",
            "prompt_hash": hashlib.sha256(raw_response.encode()).hexdigest(),
            "pipeline_stage": "relay_output",
            "processing_ms": processing_ms,
            "ibs_status": "pending",
            "source": "relay",
            "direction": "output",
            "risk_score": output_risk_score,
            "agent_mode": False,
            "conversation_id": body.conversation_id,
            "metadata": {
                "request_id": request_id,
                "provider": provider,
                "model": llm_result["model"],
                "total_detected": output_stats["total_detected"],
                "total_masked": output_stats["total_masked"],
                "leaked": output_stats["leaked"],
                "by_type": output_stats["by_type"],
                "scan_mode": pipeline.get("output_scanning_mode", "shadow"),
                "response_modified": output_scan_modified,
            },
        })
        if output_audit_log_id:
            background_tasks.add_task(
                db.insert_pii_detections,
                [{
                    "audit_log_id": output_audit_log_id,
                    "org_id": org_id,
                    "entity_type": d.type,
                    "original_length": (d.end - d.start) if d.start is not None else None,
                    "token_ref": d.token,
                    "start_offset": d.start,
                    "end_offset": d.end,
                    "confidence_score": d.confidence,
                    "detector_used": d.detector,
                    "detector_version": "regex-v1",
                    "direction": "output",
                    "risk_score": pe.ENTITY_RISK_WEIGHTS.get(d.type, 0.3),
                    "conversation_id": body.conversation_id,
                    "decision_reason": f"Output scan: {d.action} for {d.type} (mode={pipeline.get('output_scanning_mode', 'shadow')})",
                } for d in output_detections],
            )
            background_tasks.add_task(ibs.certify_audit_log, output_audit_log_id, org_id, {"request_id": request_id})
        background_tasks.add_task(
            db.increment_pipeline_counters,
            body.pipeline_id,
            output_stats["total_detected"],
            output_stats["total_masked"],
            output_stats["leaked"],
            0,
        )

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
            "compression_stats": compression_stats,
        },
    })

    if audit_log_id:
        background_tasks.add_task(ibs.certify_audit_log, audit_log_id, org_id,
                                   {"request_id": request_id, "provider": provider})

    final_relay_response = RelayResponse(
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
        compression_stats=compression_stats,
        output_pii_detected=len(output_detections),
        output_pii_masked=sum(1 for d in output_detections if d.action in ("tokenised", "anonymised", "blocked")),
        output_pii_leaked=sum(1 for d in output_detections if d.action == "leaked"),
        output_scan_mode=pipeline.get("output_scanning_mode") if pipeline.get("output_scanning_enabled") else None,
        output_response_modified=output_scan_modified,
        output_audit_log_id=output_audit_log_id,
    )

    if idempotency_key:
        background_tasks.add_task(
            db.save_idempotent_response, org_id, idempotency_key, "relay_complete",
            200, final_relay_response.model_dump(),
        )

    return final_relay_response


@router.get("/providers")
async def get_providers(
    key_record: Dict[str, Any] = Depends(verify_api_key_or_internal),
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
    key_record: Dict[str, Any] = Depends(verify_api_key_or_internal),
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
