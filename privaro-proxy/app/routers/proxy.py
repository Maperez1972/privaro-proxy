"""
Privacy Proxy Router — Core of the product.

POST /v1/proxy/detect  — Detect PII without masking (analysis mode)
POST /v1/proxy/protect — Detect + mask + audit log + contextual policy (Phase 7b)
GET  /v1/proxy/test    — Health check with sample detection
"""
import time
import uuid
import os
import re
import base64
import hashlib
import asyncio
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Header
from typing import Dict, Any, Optional

from app.models.schemas import (
    ProtectRequest, ProtectResponse,
    DetectRequest, DetectResponse,
    DetokenizeRequest, DetokenizeResponse,
    ProtectStructuredRequest, ProtectStructuredResponse,
    Detection,
)
from app.services import detector
from app.services.auth import verify_api_key_or_dev, verify_api_key_or_internal
from app.services import supabase as db
from app.services import ibs
from app.services import policy_engine as pe
from app.services.key_manager import resolve_encryption_key, get_org_default_key_id, _decrypt_aes_gcm
from app.services.context_optimizer import compress_with_timeout
from app.config import settings
from app.services import quota as quota_svc

router = APIRouter()


# ── Resilience helper — added 2026-07 ───────────────────────────────────────
# Privaro sits in the caller's critical path (every LLM call from Robin/
# Octupus goes through here first). An internal slowdown or bug in the
# detector/policy engine must never become an outage for the partner's own
# product. This wraps the blocking detection step with a hard timeout and
# fails OPEN (passes the original prompt through unmodified) rather than
# raising a 500 — consistent with the existing soft-cap quota philosophy
# ("never block the caller's traffic"). The event is still logged (see
# callers) so this is never a silent bypass from a compliance standpoint.

class DegradedModeError(Exception):
    def __init__(self, reason: str):
        self.reason = reason


async def _detect_with_timeout(prompt: str, custom_rules: Optional[list] = None) -> list:
    """Runs the (synchronous, potentially slow) detector in a thread with a
    hard timeout. Raises DegradedModeError on timeout or internal failure —
    callers must catch this and fail open."""
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, detector.detect, prompt, True, custom_rules),
            timeout=settings.PROTECT_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise DegradedModeError("detector_timeout")
    except Exception as e:
        print(f"[Resilience] Detector error, failing open: {e}")
        raise DegradedModeError("detector_error")


# ── /proxy/detect ────────────────────────────────────────────────────────────

@router.post("/detect", response_model=DetectResponse)
async def detect_pii(
    body: DetectRequest,
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_internal),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    """Analysis mode: detect PII without masking or storing."""
    t0 = time.monotonic()

    pipeline = await db.get_pipeline(body.pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    org_id = pipeline["org_id"]

    # Idempotency (roadmap #5) — a retried call with the same key gets back
    # the exact response already computed, without re-detecting or
    # re-incrementing quota. Added after Octupus reported a real 6.6% error
    # rate on their calls, which makes retries routine.
    if idempotency_key:
        cached = await db.get_idempotent_response(org_id, idempotency_key, "detect")
        if cached:
            return DetectResponse(**cached["response_body"])

    # Quota check — previously missing on /detect, meaning it was unmetered.
    # Soft-cap: never blocks, just counts (see quota.py).
    await quota_svc.check_and_increment(org_id)

    policies = await db.get_policy_rules(org_id, pipeline_id=body.pipeline_id) or []
    custom_pattern_rules = [r for r in policies if r.get("custom_pattern")]

    try:
        detections = await _detect_with_timeout(body.prompt, custom_pattern_rules)
    except DegradedModeError as e:
        # /detect is analysis-only (nothing to protect/mask) — on failure,
        # just return zero detections rather than fail the whole request.
        print(f"[Resilience] /detect degraded ({e.reason}) org={org_id}")
        detections = []
    processing_ms = int((time.monotonic() - t0) * 1000)

    response = DetectResponse(
        request_id=f"req_{uuid.uuid4().hex[:8]}",
        detections=detections,
        stats=detector.build_stats(detections, processing_ms),
    )

    if idempotency_key:
        background_tasks.add_task(
            db.save_idempotent_response, org_id, idempotency_key, "detect",
            200, response.model_dump(),
        )

    return response


# ── /proxy/protect ───────────────────────────────────────────────────────────

def _apply_tokenization(text: str, detections: list, counters: Dict[str, int]) -> str:
    """
    Applies tokenisation/anonymisation replacements to `text` per each
    detection's resolved .action, back-to-front to preserve offsets.
    Mutates each detection's .token/.action in place. `counters` is shared
    across calls within the same request so token numbering stays
    consistent (e.g. across multiple fields in /protect-structured).

    Extracted 2026-07-24 from /protect's inline loop so /protect-structured
    can reuse the exact same tokenisation behavior per-field instead of
    duplicating it.
    """
    for detection in reversed(detections):
        if detection.start is None or detection.end is None:
            continue
        entity_type = detection.type

        if detection.action in ("tokenised", "pseudonymised"):
            counters[entity_type] = counters.get(entity_type, 0) + 1
            token = _make_token(entity_type, counters[entity_type])
            detection.token = token
            detection.action = "tokenised"
            replacement = token
        elif detection.action in ("anonymised", "anonymise", "anonymise_irreversible"):
            detection.action = "anonymised"
            # Fixed 2026-08-07 — real finding: this used the raw internal
            # entity_type identifier verbatim (e.g. "[HEALTH_RECORD]"),
            # an English snake_case string with no relation to the
            # [XX-0001] token convention used everywhere else — visibly
            # inconsistent (and oddly English) in the middle of a Spanish
            # document, and it exposes Privaro's internal naming rather
            # than looking like an intentional, professional redaction
            # marker. Anonymise is deliberately irreversible (no numbered
            # token, since there's nothing to reverse), but the label
            # itself should still follow the same TOKEN_PREFIX convention.
            replacement = f"[{TOKEN_PREFIX.get(entity_type, entity_type[:2].upper())}-REDACTED]"
        elif detection.action == "blocked":
            # Fixed 2026-07-24 — real bug found via live testing: a policy
            # rule that resolves to "block" for a SPECIFIC entity (not the
            # whole request) fell through to the "else" branch below and
            # got silently tokenised instead of blocked — a DPO-configured
            # block policy (e.g. "never let health_record leave this
            # pipeline") was not actually being honored. No token is
            # generated (nothing to reverse for data that was refused).
            replacement = f"[BLOCKED:{entity_type.upper()}]"
        else:
            detection.action = "tokenised"
            counters[entity_type] = counters.get(entity_type, 0) + 1
            token = _make_token(entity_type, counters[entity_type])
            detection.token = token
            replacement = token

        text = text[:detection.start] + replacement + text[detection.end:]
    return text


async def _build_vault_rows(
    text: str,
    detections: list,
    org_id: str,
    pipeline_id: str,
    conversation_id: Optional[str],
    enc_key: bytes,
    enc_key_id: str,
) -> list:
    """
    Same encryption/token-consistency logic as /protect's inline Step 8,
    extracted 2026-07-24 so /protect-structured can reuse it per-field
    without duplicating the AES-GCM + conversation-reuse logic. /protect
    itself is left untouched (still inline) to avoid re-touching that
    endpoint's already-verified behavior.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    token_rows = []
    for d in detections:
        if d.action == "tokenised" and d.token and d.start is not None and d.end is not None:
            original_value = text[d.start:d.end]
            original_hash = hashlib.sha256(original_value.encode("utf-8")).hexdigest()
            try:
                aesgcm = AESGCM(enc_key)
                nonce = os.urandom(12)
                ciphertext = aesgcm.encrypt(nonce, original_value.encode("utf-8"), None)
                encrypted = base64.b64encode(nonce + ciphertext).decode("utf-8")
            except Exception as e:
                print(f"[Vault] Encryption error: {e}")
                continue

            if conversation_id:
                existing = await db.find_existing_token(
                    org_id=org_id,
                    conversation_id=conversation_id,
                    entity_type=d.type,
                    original_value_hash=original_hash,
                )
                if existing:
                    d.token = existing["token_value"]
                    continue

            token_rows.append({
                "org_id": org_id,
                "pipeline_id": pipeline_id,
                "entity_type": d.type,
                "token_value": d.token,
                "encrypted_original": encrypted,
                "original_value_hash": original_hash,
                "encryption_key_id": enc_key_id,
                "is_reversible": True,
                "access_roles": ["admin", "dpo"],
                "conversation_id": conversation_id,
            })
    return token_rows


@router.post("/protect", response_model=ProtectResponse)
async def protect_prompt(
    body: ProtectRequest,
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_internal),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
):
    """
    CORE endpoint — Phase 7b: Contextual Policy Engine + Risk Scoring.

    Flow:
    1. Validate pipeline + org
    2. Detect PII
    3. Load policy rules + provider trust posture
    4. Apply contextual policy (entity × provider × role × region × agent_mode)
    5. Compute risk_score
    6. Apply tokenisation based on resolved actions
    7. INSERT audit_log with risk_score
    8. INSERT pii_detections (with detector metadata)
    9. INSERT tokens_vault (AES-256-GCM) — BYOK-aware
    10. Return to client ~50ms
    11. BACKGROUND: iBS certification
    """
    t0 = time.monotonic()
    request_id = f"req_{uuid.uuid4().hex[:12]}"

    # ── Step 1: Validate pipeline ────────────────────────────────────────────
    pipeline = await db.get_pipeline(body.pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    org_id = pipeline["org_id"]

    # Idempotency (roadmap #5) — checked BEFORE quota so a retry with the
    # same key never counts twice against the partner's tier. Added after
    # Octupus reported a real 6.6% error rate on their calls, which makes
    # retries routine, not an edge case.
    if idempotency_key:
        cached = await db.get_idempotent_response(org_id, idempotency_key, "protect")
        if cached:
            return ProtectResponse(**cached["response_body"])

    # ── Step 1b: Quota check ─────────────────────────────────────────────────
    # Soft-cap: atomically increments the request counter (rolled up to the
    # partner's billing_account for sub_account orgs). Never raises/blocks —
    # once the limit is hit, requests continue and are counted as overage.
    # Enterprise plans are unlimited (bypassed inside the RPC).
    await quota_svc.check_and_increment(org_id)

    agent_mode = body.options.agent_mode if hasattr(body.options, "agent_mode") else False

    # Pre-generate the audit log id so we can (a) include it in the response
    # and (b) insert the actual row as a background task without blocking
    # the caller on it — see Step 6 below.
    audit_log_id = str(uuid.uuid4())

    # Moved earlier (2026-07-24, was after detection): policies must be loaded
    # BEFORE detection now, since rules carrying a custom_pattern feed directly
    # into the detector (Tier 1.5) instead of only shaping post-detection
    # action. See detector.detect()'s custom_rules parameter.
    policies = await db.get_policy_rules(org_id, pipeline_id=body.pipeline_id) or []
    custom_pattern_rules = [r for r in policies if r.get("custom_pattern")]

    # ── Step 2: Detect PII (resilient — fails open on timeout/error) ────────
    try:
        detections = await _detect_with_timeout(body.prompt, custom_pattern_rules)
    except DegradedModeError as e:
        # Detector failed or timed out. Privaro is in the critical path of
        # every call Robin/Octupus makes to their LLM — we must not turn an
        # internal hiccup into their outage. Pass the ORIGINAL prompt through
        # unmodified (fail open), but log this as a distinct, high-severity
        # audit event so the DPO can see that unprotected data may have gone
        # out. This is not a silent bypass.
        processing_ms = int((time.monotonic() - t0) * 1000)
        print(f"[Resilience] /protect degraded ({e.reason}) org={org_id} pipeline={body.pipeline_id}")
        background_tasks.add_task(db.insert_audit_log, {
            "id": audit_log_id,
            "org_id": org_id, "pipeline_id": body.pipeline_id,
            "event_type": "degraded_bypass",
            "entity_type": "unknown", "entity_category": "system",
            "action_taken": "passthrough_unprotected", "severity": "critical",
            "prompt_hash": hashlib.sha256(body.prompt.encode()).hexdigest(),
            "pipeline_stage": "proxy", "processing_ms": processing_ms,
            "ibs_status": "pending", "source": "proxy",
            "risk_score": None, "agent_mode": agent_mode,
            "conversation_id": body.conversation_id if body.conversation_id else None,
            "metadata": {"request_id": request_id, "degraded_reason": e.reason},
        })
        # Deliberately NOT saved to the idempotency cache: this is a
        # transient internal failure, not a "real" result. Caching it would
        # freeze the degraded response for 24h on retry, even if the
        # detector would have worked fine on the next attempt.
        return ProtectResponse(
            request_id=request_id,
            protected_prompt=body.prompt,  # unmodified — fail open
            detections=[],
            stats={"total_detected": 0, "total_masked": 0, "leaked": 0,
                   "coverage_pct": 0.0, "processing_ms": processing_ms, "by_type": {}, "risk_score": None},
            audit_log_id=audit_log_id,
            gdpr_compliant=False,
            degraded_mode=True,
            degraded_reason=e.reason,
        )

    # ── Step 3: Load provider trust (policies already loaded above, pre-detection) ──
    provider_trust = await db.get_provider_trust(pipeline.get("llm_provider", ""), org_id)

    policy_context = {
        "provider": pipeline.get("llm_provider", ""),
        "user_role": key_record.get("role", "developer"),
        "data_region": provider_trust.get("data_region", "EU") if provider_trust else "EU",
        "agent_mode": agent_mode,
        "pipeline_sector": pipeline.get("sector", "general"),
        "default_action": body.options.mode.value,
    }
    provider_risk_level = (provider_trust or {}).get("provider_risk_level", "medium")

    # ── Step 4: Apply contextual policy ──────────────────────────────────────
    if policies and detections:
        detections = pe.apply_policies(detections, policies, policy_context)
    else:
        for d in detections:
            d.action = "tokenised" if body.options.mode.value == "tokenise" else body.options.mode.value

    # ── Step 5: Apply tokenisation to text ───────────────────────────────────
    protected_prompt = body.prompt
    counters: Dict[str, int] = {}

    # Check if any detection is blocked — if all blocked, return blocked response
    if all(d.action == "blocked" for d in detections) and detections:
        processing_ms = int((time.monotonic() - t0) * 1000)
        risk_score = pe.compute_risk_score(detections, provider_risk_level, agent_mode, len(detections))
        background_tasks.add_task(db.insert_audit_log, {
            "id": audit_log_id,
            "org_id": org_id, "pipeline_id": body.pipeline_id,
            "event_type": "request_blocked", "entity_type": detections[0].type,
            "entity_category": pe._get_category(detections[0].type),
            "action_taken": "blocked", "severity": "critical",
            "prompt_hash": hashlib.sha256(body.prompt.encode()).hexdigest(),
            "pipeline_stage": "proxy", "processing_ms": processing_ms,
            "ibs_status": "pending", "source": "proxy",
            "risk_score": risk_score, "agent_mode": agent_mode,
            "conversation_id": body.conversation_id if body.conversation_id else None,
            "metadata": {"request_id": request_id, "mode": body.options.mode.value,
                         "total_detected": len(detections), "total_masked": 0, "by_type": {}},
        })
        background_tasks.add_task(ibs.certify_audit_log, audit_log_id, org_id,
                                   {"request_id": request_id})
        blocked_response = ProtectResponse(
            request_id=request_id,
            protected_prompt="[BLOCKED: Policy violation — PII detected that cannot be processed]",
            detections=detections if body.options.include_detections else [],
            stats={"total_detected": len(detections), "total_masked": 0,
                   "leaked": len(detections), "coverage_pct": 0.0,
                   "processing_ms": processing_ms, "by_type": {}, "risk_score": risk_score},
            audit_log_id=audit_log_id,
            gdpr_compliant=False,
        )
        if idempotency_key:
            background_tasks.add_task(
                db.save_idempotent_response, org_id, idempotency_key, "protect",
                200, blocked_response.model_dump(),
            )
        return blocked_response

    # Apply replacements back-to-front to preserve offsets
    protected_prompt = _apply_tokenization(protected_prompt, detections, counters)

    # ── Context Optimization (opt-in, gated by options.optimize_context) ────
    # Added 2026-07-30 — this endpoint (/v1/proxy/protect) is what the
    # dashboard Sandbox actually calls (via the proxy-bridge Edge
    # Function), not /v1/relay/complete. Compression was previously only
    # wired into relay.py, leaving this the missing half of PR #1. Same
    # fail-open contract as relay.py: any integrity mismatch or internal
    # error discards the compression result and returns protected_prompt
    # unmodified.
    #
    # Fixed 2026-08-07 — CRITICAL: this used to call
    # compress_protected_messages() directly (sync, no await, no
    # executor) inside this async endpoint. Kompress is a real CPU
    # transformer model; on a ~14K char document it took 30+ seconds,
    # during which it blocked the entire asyncio event loop for this
    # worker — freezing every OTHER concurrent request, not just this
    # one. Now uses compress_with_timeout(), which offloads to a thread
    # pool and bounds worst-case latency (fails open past the timeout).
    compression_stats: Dict[str, Any] = {"tokens_saved": 0, "compression_ratio": 0.0, "skipped_reason": "disabled"}
    if getattr(body.options, "optimize_context", False):
        compressed_messages, compression_stats = await compress_with_timeout(
            [{"role": "user", "content": protected_prompt}],
            model=pipeline.get("llm_model", "claude-sonnet-4-6"),
        )
        protected_prompt = compressed_messages[0]["content"]

    processing_ms = int((time.monotonic() - t0) * 1000)
    stats = detector.build_stats(detections, processing_ms)

    # ── Step 5: Compute risk_score ────────────────────────────────────────────
    risk_score = pe.compute_risk_score(
        detections,
        provider_risk_level=provider_risk_level,
        agent_mode=agent_mode,
        leaked_count=stats["leaked"],
    )
    stats["risk_score"] = risk_score

    # ── Step 6: Build primary event ───────────────────────────────────────────
    if not detections:
        event_type, severity, entity_type, action_taken = "request_clean", "low", "none", "passed"
    else:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        primary = min(detections, key=lambda d: severity_order.get(d.severity, 99))
        event_type = "pii_detected"
        severity = primary.severity
        entity_type = primary.type
        action_taken = primary.action
        if stats["leaked"] > 0:
            event_type = "pii_leaked"

    prompt_hash = hashlib.sha256(body.prompt.encode()).hexdigest()

    audit_payload = {
        "id": audit_log_id,
        "org_id": org_id,
        "pipeline_id": body.pipeline_id,
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_category": pe._get_category(entity_type),
        "action_taken": action_taken,
        "severity": severity,
        "prompt_hash": prompt_hash,
        "pipeline_stage": "proxy",
        "processing_ms": processing_ms,
        "ibs_status": "pending",
        "source": "proxy",
        "risk_score": risk_score,
        "agent_mode": agent_mode,
        "conversation_id": body.conversation_id if body.conversation_id else None,
        "metadata": {
            "request_id": request_id,
            "total_detected": stats["total_detected"],
            "total_masked": stats["total_masked"],
            "by_type": stats["by_type"],
            "mode": body.options.mode.value,
            "risk_score": risk_score,
            "conversation_id": body.conversation_id if body.conversation_id else None,
            "provider": pipeline.get("llm_provider", ""),
            "provider_risk_level": provider_risk_level,
        },
    }

    # Was a blocking `await db.insert_audit_log(...)` — moved to a background
    # task now that audit_log_id is pre-generated client-side (see top of
    # this function). Supabase being slow no longer adds latency to every
    # single request, and a transient Supabase failure here no longer turns
    # into a 500 for a request Privaro actually protected successfully.
    background_tasks.add_task(db.insert_audit_log, audit_payload)

    # ── Step 7: INSERT pii_detections ─────────────────────────────────────────
    if detections and audit_log_id:
        detection_rows = [
            {
                "audit_log_id": audit_log_id,
                "org_id": org_id,
                "entity_type": d.type,
                "original_length": (d.end - d.start) if d.start is not None else None,
                "token_ref": d.token,
                "start_offset": d.start,
                "end_offset": d.end,
                "confidence_score": d.confidence,
                "detector_used": d.detector,
                "detector_version": "regex-v1",
                "risk_score": pe.ENTITY_RISK_WEIGHTS.get(d.type, 0.3),
                "conversation_id": body.conversation_id if body.conversation_id else None,
                "decision_reason": f"Policy: {d.action} for {d.type} in context provider={policy_context['provider']} role={policy_context['user_role']}",
            }
            for d in detections
        ]
        background_tasks.add_task(db.insert_pii_detections, detection_rows)

    # ── Step 8: INSERT tokens_vault — BYOK-aware ──────────────────────────────
    if detections and audit_log_id and body.options.reversible:
        # Resolve org encryption key (BYOK if configured, managed otherwise)
        enc_key_id = await get_org_default_key_id(org_id)
        try:
            enc_key = await resolve_encryption_key(enc_key_id, org_id)
        except Exception as e:
            print(f"[Vault] Key resolution failed, falling back to managed: {e}")
            from app.services.key_manager import _get_managed_key
            enc_key = _get_managed_key()
            enc_key_id = "key-v1"

        conversation_id = body.conversation_id

        token_rows = []
        for d in detections:
            if d.action == "tokenised" and d.token and d.start is not None and d.end is not None:
                original_value = body.prompt[d.start:d.end]
                # Deterministic hash for cross-turn matching — fixed 2026-07-23.
                # NEVER use encrypted_original for this: AES-GCM's random nonce
                # means the same plaintext never re-encrypts to the same bytes.
                original_hash = hashlib.sha256(original_value.encode("utf-8")).hexdigest()
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    aesgcm = AESGCM(enc_key)
                    nonce = os.urandom(12)
                    ciphertext = aesgcm.encrypt(nonce, original_value.encode("utf-8"), None)
                    encrypted = base64.b64encode(nonce + ciphertext).decode("utf-8")
                except Exception as e:
                    print(f"[Vault] Encryption error: {e}")
                    continue

                # Token consistency: reuse existing token within conversation
                if conversation_id:
                    existing = await db.find_existing_token(
                        org_id=org_id,
                        conversation_id=conversation_id,
                        entity_type=d.type,
                        original_value_hash=original_hash,
                    )
                    if existing:
                        d.token = existing["token_value"]
                        print(f"[Vault] Reusing token {d.token} for {d.type} in conv {conversation_id[:8]}")
                        continue

                token_rows.append({
                    "org_id": org_id,
                    "pipeline_id": body.pipeline_id,
                    "entity_type": d.type,
                    "token_value": d.token,
                    "encrypted_original": encrypted,
                    "original_value_hash": original_hash,
                    "encryption_key_id": enc_key_id,   # ← BYOK-aware key_id
                    "is_reversible": True,
                    "access_roles": ["admin", "dpo"],
                    "conversation_id": conversation_id,
                })

        if token_rows:
            background_tasks.add_task(db.insert_tokens_batch, token_rows)
            # Track key usage (fire and forget)
            background_tasks.add_task(
                db.increment_encryption_key_usage, enc_key_id, len(token_rows)
            )

    # ── Step 9: iBS certification ─────────────────────────────────────────────
    if audit_log_id:
        background_tasks.add_task(
            ibs.certify_audit_log,
            audit_log_id,
            org_id,
            audit_payload.get("metadata", {}),
        )

    # ── Step 10: Update pipeline counters ────────────────────────────────────
    background_tasks.add_task(
        db.increment_pipeline_counters,
        body.pipeline_id,
        stats["total_detected"],
        stats["total_masked"],
        stats["leaked"],
        processing_ms,
    )

    final_response = ProtectResponse(
        request_id=request_id,
        protected_prompt=protected_prompt,
        detections=detections if body.options.include_detections else [],
        stats=stats,
        audit_log_id=audit_log_id,
        gdpr_compliant=stats["leaked"] == 0,
        compression_stats=compression_stats,
    )

    if idempotency_key:
        background_tasks.add_task(
            db.save_idempotent_response, org_id, idempotency_key, "protect",
            200, final_response.model_dump(),
        )

    return final_response


# ── /proxy/test ──────────────────────────────────────────────────────────────

@router.get("/test")
async def proxy_test(
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    from app.services.nlp_engine import is_available as nlp_available
    sample = "Paciente: María García, DNI 34521789X, IBAN ES91 2100 0418 4502 0005 1332, email: maria.garcia@clinica.es"
    protected, detections = detector.protect(sample, mode="tokenise")
    tier1 = [d for d in detections if d.detector == "regex"]
    tier2 = [d for d in detections if d.detector == "presidio"]
    return {
        "status": "ok",
        "detector": "hybrid-v1",
        "tier1_regex": "active",
        "tier2_nlp": "active" if nlp_available() else "unavailable",
        "sample_input": sample,
        "protected_output": protected,
        "entities_detected": len(detections),
        "tier1_detections": len(tier1),
        "tier2_detections": len(tier2),
        "risk_score": pe.compute_risk_score(detections),
        "detections": [d.model_dump() for d in detections],
    }


# ── Token helpers ─────────────────────────────────────────────────────────────

TOKEN_PREFIX = {
    "full_name": "NM", "dni": "ID", "nie": "ID", "iban": "BK",
    "credit_card": "CC", "email": "EM", "phone": "PH",
    "health_record": "HC", "ip_address": "IP", "date_of_birth": "DT", "ssn": "SS",
    "passport": "PP",
    "money": "MN",
}

def _make_token(entity_type: str, counter: int) -> str:
    prefix = TOKEN_PREFIX.get(entity_type, "XX")
    return f"[{prefix}-{counter:04d}]"


def _get_category(entity_type: str) -> str:
    return pe._get_category(entity_type)


# ── /proxy/detokenize ─────────────────────────────────────────────────────────
# Added 2026-07-24 following the Octupus/Robin AI (Odoo copilot) analysis.
#
# reveal-token (see privaro-7938a3bd) is a human-facing flow: a DPO/admin
# re-enters their password to reveal ONE token at a time in the dashboard UI.
# That doesn't fit an agentic write-back flow — e.g. an ERP copilot whose
# LLM decided (via function-calling) to create a delivery note using data
# it only ever saw as tokens; the actual Odoo write needs the real values,
# automatically, with no human in the loop for every single field.
#
# This endpoint finds every Privaro-format token ([XX-0001]) in a body of
# text and reverses all of them in one call, authenticated the same way as
# /protect and /detect (the caller's own org API key) — never a password,
# but STRICTLY scoped to tokens belonging to that same org_id, applying
# the same discipline that fixed reveal-token's cross-tenant bug earlier
# today: a caller can only ever be authenticated as one org, so only that
# org's tokens are ever looked up or decrypted.

TOKEN_PATTERN = re.compile(r'\[[A-Z]{2,4}-\d{4}\]')


@router.post("/detokenize", response_model=DetokenizeResponse)
async def detokenize_text(
    body: DetokenizeRequest,
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_internal),
):
    """Bulk, automated reversal of every Privaro token found in `text`,
    scoped to the caller's own organization."""
    t0 = time.monotonic()
    request_id = f"req_{uuid.uuid4().hex[:12]}"

    pipeline = await db.get_pipeline(body.pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    org_id = pipeline["org_id"]

    found_tokens = sorted(set(TOKEN_PATTERN.findall(body.text)))
    if not found_tokens:
        return DetokenizeResponse(
            request_id=request_id,
            detokenized_text=body.text,
            tokens_reversed=0,
            tokens_not_found=[],
        )

    vault_rows = await db.get_tokens_by_values(org_id, found_tokens, body.conversation_id)
    rows_by_token = {r["token_value"]: r for r in vault_rows}

    detokenized_text = body.text
    reversed_count = 0
    reversal_updates = []

    for token_value in found_tokens:
        row = rows_by_token.get(token_value)
        if not row:
            continue  # not found for this org — left as-is, reported below
        try:
            enc_key = await resolve_encryption_key(row["encryption_key_id"], org_id)
            original_value = _decrypt_aes_gcm(row["encrypted_original"], enc_key)
        except Exception as e:
            print(f"[Detokenize] Decrypt failed for {token_value}: {e}")
            continue
        detokenized_text = detokenized_text.replace(token_value, original_value)
        reversed_count += 1
        reversal_updates.append({"id": row["id"], "reversal_count": row.get("reversal_count") or 0})

    tokens_not_found = [t for t in found_tokens if t not in rows_by_token]
    processing_ms = int((time.monotonic() - t0) * 1000)

    # Distinct event_type from reveal-token's human-facing "reveal" action in
    # vault_access_log — a DPO should be able to tell an automated,
    # pipeline-driven bulk reversal apart from a human manually unmasking a
    # value in the dashboard.
    background_tasks.add_task(db.insert_audit_log, {
        "id": str(uuid.uuid4()),
        "org_id": org_id, "pipeline_id": body.pipeline_id,
        "event_type": "bulk_detokenize",
        "entity_type": "multiple", "entity_category": "system",
        "action_taken": "detokenized", "severity": "medium",
        "prompt_hash": hashlib.sha256(body.text.encode()).hexdigest(),
        "pipeline_stage": "proxy", "processing_ms": processing_ms,
        "ibs_status": "pending", "source": "proxy",
        "risk_score": None, "agent_mode": True,
        "metadata": {
            "request_id": request_id,
            "tokens_reversed": reversed_count,
            "tokens_not_found": len(tokens_not_found),
        },
    })

    if reversal_updates:
        background_tasks.add_task(db.bump_reversal_counts, reversal_updates)

    return DetokenizeResponse(
        request_id=request_id,
        detokenized_text=detokenized_text,
        tokens_reversed=reversed_count,
        tokens_not_found=tokens_not_found,
    )


# ── /proxy/protect-structured ─────────────────────────────────────────────────
# Added 2026-07-24 following the Octupus/Robin AI (Odoo copilot) analysis.
#
# /protect works on a single free-text prompt. An ERP copilot's queries
# return typed database rows — many fields, each with its own semantics —
# not prose. A field named "diagnostico" is strong, precise signal that
# its value is health data even if the content itself (a specific
# diagnosis name) isn't recognized by any pattern; a field named
# "importe_facturacion" is confidential regardless of format. This
# endpoint lets a field's NAME force its entity_type via
# policy_rules.field_name_pattern, falling back to normal content-based
# detection (including custom_pattern) for any field with no matching rule.

@router.post("/protect-structured", response_model=ProtectStructuredResponse)
async def protect_structured(
    body: ProtectStructuredRequest,
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_internal),
):
    t0 = time.monotonic()
    request_id = f"req_{uuid.uuid4().hex[:12]}"

    pipeline = await db.get_pipeline(body.pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})
    if not body.fields:
        raise HTTPException(status_code=400, detail={"error": "fields must not be empty"})

    org_id = pipeline["org_id"]
    await quota_svc.check_and_increment(org_id)

    policies = await db.get_policy_rules(org_id, pipeline_id=body.pipeline_id) or []
    custom_pattern_rules = [r for r in policies if r.get("custom_pattern")]
    # Sorted by effective priority so the first match wins when more than
    # one field_name_pattern could match the same field name.
    field_name_rules = sorted(
        (r for r in policies if r.get("field_name_pattern")),
        key=lambda r: r.get("_effective_priority", r.get("priority", 0)),
    )
    compiled_field_rules = []
    for r in field_name_rules:
        try:
            compiled_field_rules.append((re.compile(r["field_name_pattern"], re.IGNORECASE), r))
        except re.error as e:
            print(f"[ProtectStructured] Invalid field_name_pattern for entity_type={r.get('entity_type')}: {e}")

    provider_trust = await db.get_provider_trust(pipeline.get("llm_provider", ""), org_id)
    policy_context = {
        "provider": pipeline.get("llm_provider", ""),
        "user_role": key_record.get("role", "developer"),
        "data_region": (provider_trust or {}).get("data_region", "EU"),
        "agent_mode": True,
        "pipeline_sector": pipeline.get("sector", "general"),
        "default_action": "tokenise",
    }
    provider_risk_level = (provider_trust or {}).get("provider_risk_level", "medium")

    enc_key_id = await get_org_default_key_id(org_id)
    try:
        enc_key = await resolve_encryption_key(enc_key_id, org_id)
    except Exception as e:
        print(f"[ProtectStructured] Key resolution failed, falling back to managed: {e}")
        from app.services.key_manager import _get_managed_key
        enc_key = _get_managed_key()
        enc_key_id = "key-v1"

    protected_fields: Dict[str, str] = {}
    detections_by_field: Dict[str, list] = {}
    all_detections = []
    all_vault_rows = []
    counters: Dict[str, int] = {}

    for field_name, field_value in body.fields.items():
        # 1. Field-name-forced entity type — whole value, no content parsing
        forced_rule = next(
            (rule for pattern, rule in compiled_field_rules if pattern.search(field_name)),
            None,
        )
        if forced_rule:
            field_detections = [Detection(
                type=forced_rule["entity_type"],
                severity=forced_rule.get("severity_override") or "high",
                action="detected",
                token=None,
                start=0,
                end=len(field_value),
                confidence=0.95,
                detector="field_name_rule",
            )]
        else:
            # 2. Normal content-based detection (regex + custom_pattern + NLP)
            field_detections = await _detect_with_timeout(field_value, custom_pattern_rules)

        if policies and field_detections:
            field_detections = pe.apply_policies(field_detections, policies, policy_context)
        else:
            for d in field_detections:
                d.action = "tokenised"

        protected_value = _apply_tokenization(field_value, field_detections, counters)
        protected_fields[field_name] = protected_value
        detections_by_field[field_name] = field_detections
        all_detections.extend(field_detections)

        field_vault_rows = await _build_vault_rows(
            field_value, field_detections, org_id, body.pipeline_id,
            body.conversation_id, enc_key, enc_key_id,
        )
        all_vault_rows.extend(field_vault_rows)

    processing_ms = int((time.monotonic() - t0) * 1000)
    risk_score = pe.compute_risk_score(
        all_detections, provider_risk_level=provider_risk_level,
        agent_mode=True, leaked_count=0,
    )
    stats = detector.build_stats(all_detections, processing_ms)
    stats["risk_score"] = risk_score

    audit_log_id = str(uuid.uuid4())
    background_tasks.add_task(db.insert_audit_log, {
        "id": audit_log_id,
        "org_id": org_id, "pipeline_id": body.pipeline_id,
        "event_type": "structured_protect" if all_detections else "request_clean",
        "entity_type": "multiple" if all_detections else "none",
        "entity_category": "system",
        "action_taken": "tokenised" if all_detections else "passed",
        "severity": "medium" if all_detections else "low",
        "prompt_hash": hashlib.sha256(str(body.fields).encode()).hexdigest(),
        "pipeline_stage": "proxy", "processing_ms": processing_ms,
        "ibs_status": "pending", "source": "proxy",
        "risk_score": risk_score, "agent_mode": True,
        "conversation_id": body.conversation_id if body.conversation_id else None,
        "metadata": {
            "request_id": request_id, "fields_count": len(body.fields),
            "total_detected": len(all_detections),
        },
    })

    if all_vault_rows:
        background_tasks.add_task(db.insert_tokens_batch, all_vault_rows)
        background_tasks.add_task(db.increment_encryption_key_usage, enc_key_id, len(all_vault_rows))

    background_tasks.add_task(ibs.certify_audit_log, audit_log_id, org_id, {"request_id": request_id})

    return ProtectStructuredResponse(
        request_id=request_id,
        protected_fields=protected_fields,
        detections_by_field=detections_by_field,
        stats=stats,
        audit_log_id=audit_log_id,
    )
