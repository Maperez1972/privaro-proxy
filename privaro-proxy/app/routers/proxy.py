"""
Privacy Proxy Router — Core of the product.

POST /v1/proxy/detect  — Detect PII without masking (analysis mode)
POST /v1/proxy/protect — Detect + mask + audit log (production mode)
GET  /v1/proxy/test    — Health check with sample detection
"""
import time
import uuid
import asyncio
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import Dict, Any

from app.models.schemas import (
    ProtectRequest, ProtectResponse,
    DetectRequest, DetectResponse,
    Detection,
)
from app.services import detector
from app.services.auth import verify_api_key_or_dev
from app.services import supabase as db
from app.services import ibs
from app.config import settings

router = APIRouter()


# ── /proxy/detect ────────────────────────────────────────────────────────────

@router.post("/detect", response_model=DetectResponse)
async def detect_pii(
    body: DetectRequest,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Analysis mode: detect PII entities without masking or storing.
    Use in the PII Sandbox for real-time preview.
    """
    t0 = time.monotonic()

    # Validate pipeline belongs to org
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
    CORE endpoint. Flow:
    1. Validate pipeline + org
    2. Detect PII with regex engine
    3. Apply tokenise / anonymise / block
    4. INSERT audit_log with ibs_status='pending'
    5. INSERT pii_detections (granular)
    6. Return protected_prompt to client (~50ms)
    7. BACKGROUND: trigger iBS certification (Phase 5)
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

    # ── Steps 2-3: Detect and protect ───────────────────────────────────────
    protected_prompt, detections = detector.protect(
        body.prompt,
        mode=body.options.mode.value,
    )

    processing_ms = int((time.monotonic() - t0) * 1000)
    stats = detector.build_stats(detections, processing_ms)

    # ── Step 4: INSERT audit_log ─────────────────────────────────────────────
    # Determine primary event type and severity
    if not detections:
        event_type = "request_clean"
        severity = "low"
        entity_type = "none"
        action_taken = "passed"
    else:
        # Use the most severe detection as the primary event
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        primary = min(detections, key=lambda d: severity_order.get(d.severity, 99))
        event_type = "pii_detected"
        severity = primary.severity
        entity_type = primary.type
        action_taken = primary.action
        if stats["leaked"] > 0:
            event_type = "pii_leaked"

    import hashlib
    prompt_hash = hashlib.sha256(body.prompt.encode()).hexdigest()

    audit_payload = {
        "org_id": org_id,
        "pipeline_id": body.pipeline_id,
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_category": _get_category(entity_type),
        "action_taken": action_taken,
        "severity": severity,
        "prompt_hash": prompt_hash,
        "pipeline_stage": "proxy",
        "processing_ms": processing_ms,
        "ibs_status": "pending",
        "source": "proxy",
        "metadata": {
            "request_id": request_id,
            "total_detected": stats["total_detected"],
            "total_masked": stats["total_masked"],
            "by_type": stats["by_type"],
            "mode": body.options.mode.value,
        },
    }

    audit_log_id = await db.insert_audit_log(audit_payload)

    # ── Step 5: INSERT pii_detections ────────────────────────────────────────
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
            }
            for d in detections
        ]
        background_tasks.add_task(db.insert_pii_detections, detection_rows)

    # ── Step 6 (background): iBS blockchain certification ────────────────────
    if audit_log_id:
        background_tasks.add_task(
            ibs.certify_audit_log,
            audit_log_id,
            org_id,
            audit_payload.get("metadata", {}),
        )

    # ── Step 7 (background): Update pipeline counters ────────────────────────
    background_tasks.add_task(
        db.increment_pipeline_counters,
        body.pipeline_id,
        stats["total_detected"],
        stats["total_masked"],
        stats["leaked"],
        processing_ms,
    )

    # ── Step 7: Return to client ─────────────────────────────────────────────
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
    """
    Smoke test: run the detector on a hardcoded sample.
    Confirms the engine is working without touching the DB.
    """
    sample = "Paciente: María García, DNI 34521789X, IBAN ES91 2100 0418 4502 0005 1332, email: maria.garcia@clinica.es"
    protected, detections = detector.protect(sample, mode="tokenise")
    return {
        "status": "ok",
        "detector": "regex-v1",
        "sample_input": sample,
        "protected_output": protected,
        "entities_detected": len(detections),
        "detections": [d.model_dump() for d in detections],
    }


def _get_category(entity_type: str) -> str:
    categories = {
        "dni": "personal", "nie": "personal", "ssn": "personal",
        "full_name": "personal", "email": "personal",
        "phone": "personal", "ip_address": "personal", "date_of_birth": "personal",
        "iban": "financial", "credit_card": "financial",
        "health_record": "special",
    }
    return categories.get(entity_type, "personal")
