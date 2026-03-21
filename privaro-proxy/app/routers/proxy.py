"""
Privacy Proxy Router — Core of the product.

POST /v1/proxy/detect  — Detect PII without masking (analysis mode)
POST /v1/proxy/protect — Detect + mask + audit log + contextual policy (Phase 7b)
GET  /v1/proxy/test    — Health check with sample detection
"""
import time
import uuid
import os
import base64
import hashlib
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import Dict, Any, Optional

from app.models.schemas import (
    ProtectRequest, ProtectResponse,
    DetectRequest, DetectResponse,
    Detection,
)
from app.services import detector
from app.services.auth import verify_api_key_or_dev
from app.services import supabase as db
from app.services import ibs
from app.services import policy_engine as pe
from app.config import settings

router = APIRouter()


# ── /proxy/detect ────────────────────────────────────────────────────────────

@router.post("/detect", response_model=DetectResponse)
async def detect_pii(
    body: DetectRequest,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """Analysis mode: detect PII without masking or storing."""
    t0 = time.monotonic()

    pipeline = await db.get_pipeline(body.pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    detections = detector.detect(body.prompt)
    processing_ms = int((time.monotonic() - t0) * 1000)

    return DetectResponse(
        request_id=f"req_{uuid.uuid4().hex[:8]}",
        detections=detections,
        stats=detector.build_stats(detections, processing_ms),
    )


# ── /proxy/protect ───────────────────────────────────────────────────────────

@router.post("/protect", response_model=ProtectResponse)
async def protect_prompt(
    body: ProtectRequest,
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
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
    9. INSERT tokens_vault (AES-256-GCM)
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
    agent_mode = body.options.agent_mode if hasattr(body.options, "agent_mode") else False

    # ── Step 2: Detect PII ───────────────────────────────────────────────────
    detections = detector.detect(body.prompt)

    # ── Step 3: Load policies + provider trust posture ───────────────────────
    policies = await db.get_policy_rules(org_id) or []
    provider_trust = await db.get_provider_trust(pipeline.get("llm_provider", ""), org_id)
    provider_risk_level = (provider_trust or {}).get("provider_risk_level", "medium")
    
    # Build evaluation context
    policy_context = {
        "provider": pipeline.get("llm_provider", ""),
        "user_role": key_record.get("role", "developer"),
        "data_region": provider_trust.get("data_region", "EU") if provider_trust else "EU",
        "agent_mode": agent_mode,
        "pipeline_sector": pipeline.get("sector", "general"),
        "default_action": body.options.mode.value,
        # Trust posture fields
        "eu_residency": provider_trust.get("eu_residency", True) if provider_trust else True,
        "approved_special_categories": provider_trust.get("approved_special_categories", False) if provider_trust else False,
        "approved_for_agents": provider_trust.get("approved_for_agents", True) if provider_trust else True,
        "provider_risk_level": provider_risk_level,
    }

    provider_risk_level = (provider_trust or {}).get("provider_risk_level", "medium")

    # ── Step 4: Apply contextual policy ──────────────────────────────────────
    if policies and detections:
        detections = pe.apply_policies(detections, policies, policy_context)
    else:
        # Fallback: apply mode from request options
        for d in detections:
            d.action = "tokenised" if body.options.mode.value == "tokenise" else body.options.mode.value

    # ── Step 5: Apply tokenisation to text ───────────────────────────────────
    protected_prompt = body.prompt
    counters: Dict[str, int] = {}

    # Check if any detection is blocked — if all blocked, return blocked response
    if all(d.action == "blocked" for d in detections) and detections:
        processing_ms = int((time.monotonic() - t0) * 1000)
        risk_score = pe.compute_risk_score(detections, provider_risk_level, agent_mode, len(detections))
        audit_log_id = await db.insert_audit_log({
            "org_id": org_id, "pipeline_id": body.pipeline_id,
            "event_type": "request_blocked", "entity_type": detections[0].type,
            "entity_category": pe._get_category(detections[0].type),
            "action_taken": "blocked", "severity": "critical",
            "prompt_hash": hashlib.sha256(body.prompt.encode()).hexdigest(),
            "pipeline_stage": "proxy", "processing_ms": processing_ms,
            "ibs_status": "pending", "source": "proxy",
            "risk_score": risk_score, "agent_mode": agent_mode,
            "metadata": {"request_id": request_id, "mode": body.options.mode.value,
                         "total_detected": len(detections), "total_masked": 0, "by_type": {}},
        })
        if audit_log_id:
            background_tasks.add_task(ibs.certify_audit_log, audit_log_id, org_id,
                                       {"request_id": request_id})
        return ProtectResponse(
            request_id=request_id,
            protected_prompt="[BLOCKED: Policy violation — PII detected that cannot be processed]",
            detections=detections if body.options.include_detections else [],
            stats={"total_detected": len(detections), "total_masked": 0,
                   "leaked": len(detections), "coverage_pct": 0.0,
                   "processing_ms": processing_ms, "by_type": {}, "risk_score": risk_score},
            audit_log_id=audit_log_id,
            gdpr_compliant=False,
        )

    # Apply replacements back-to-front to preserve offsets
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
            replacement = f"[{entity_type.upper()}]"
        else:
            detection.action = "tokenised"
            counters[entity_type] = counters.get(entity_type, 0) + 1
            token = _make_token(entity_type, counters[entity_type])
            detection.token = token
            replacement = token

        protected_prompt = protected_prompt[:detection.start] + replacement + protected_prompt[detection.end:]

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
        "metadata": {
            "request_id": request_id,
            "total_detected": stats["total_detected"],
            "total_masked": stats["total_masked"],
            "by_type": stats["by_type"],
            "mode": body.options.mode.value,
            "risk_score": risk_score,
            "provider": pipeline.get("llm_provider", ""),
            "provider_risk_level": provider_risk_level,
        },
    }

    audit_log_id = await db.insert_audit_log(audit_payload)

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
                "detector_version": "presidio-v1" if d.detector == "presidio" else "regex-v1",
                "risk_score": pe.ENTITY_RISK_WEIGHTS.get(d.type, 0.3),
                "decision_reason": f"Policy: {d.action} for {d.type} in context provider={policy_context['provider']} role={policy_context['user_role']}",
            }
            for d in detections
        ]
        background_tasks.add_task(db.insert_pii_detections, detection_rows)

    # ── Step 8: INSERT tokens_vault ───────────────────────────────────────────
    if detections and audit_log_id and body.options.reversible:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            enc_key_hex = settings.ENCRYPTION_KEY
            enc_key = bytes.fromhex(enc_key_hex) if enc_key_hex else os.urandom(32)
        except Exception:
            enc_key = os.urandom(32)

        token_rows = []
        for d in detections:
            if d.action == "tokenised" and d.token and d.start is not None and d.end is not None:
                original_value = body.prompt[d.start:d.end]
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    aesgcm = AESGCM(enc_key)
                    nonce = os.urandom(12)
                    ciphertext = aesgcm.encrypt(nonce, original_value.encode("utf-8"), None)
                    encrypted = base64.b64encode(nonce + ciphertext).decode("utf-8")
                except Exception as e:
                    print(f"[Vault] Encryption error: {e}")
                    continue

                token_rows.append({
                    "org_id": org_id,
                    "pipeline_id": body.pipeline_id,
                    "entity_type": d.type,
                    "token_value": d.token,
                    "encrypted_original": encrypted,
                    "encryption_key_id": "key-v1",
                    "is_reversible": True,
                    "access_roles": ["admin", "dpo"],
                })

        if token_rows:
            background_tasks.add_task(db.insert_tokens_batch, token_rows)

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

    return ProtectResponse(
        request_id=request_id,
        protected_prompt=protected_prompt,
        detections=detections if body.options.include_detections else [],
        stats=stats,
        audit_log_id=audit_log_id,
        gdpr_compliant=stats["leaked"] == 0,
    )


# ── /proxy/test ──────────────────────────────────────────────────────────────

@router.get("/test")
async def proxy_test(
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    sample = "Paciente: María García, DNI 34521789X, IBAN ES91 2100 0418 4502 0005 1332, email: maria.garcia@clinica.es"
    protected, detections = detector.protect(sample, mode="tokenise")
    return {
        "status": "ok",
        "detector": "regex-v1",
        "policy_engine": "contextual-v1",
        "sample_input": sample,
        "protected_output": protected,
        "entities_detected": len(detections),
        "risk_score": pe.compute_risk_score(detections),
        "detections": [d.model_dump() for d in detections],
    }


# ── Token helpers ─────────────────────────────────────────────────────────────

TOKEN_PREFIX = {
    "full_name": "NM", "dni": "ID", "nie": "ID", "iban": "BK",
    "credit_card": "CC", "email": "EM", "phone": "PH",
    "health_record": "HC", "ip_address": "IP", "date_of_birth": "DT", "ssn": "SS",
}

def _make_token(entity_type: str, counter: int) -> str:
    prefix = TOKEN_PREFIX.get(entity_type, "XX")
    return f"[{prefix}-{counter:04d}]"


def _get_category(entity_type: str) -> str:
    return pe._get_category(entity_type)
