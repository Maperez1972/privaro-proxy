"""
Document Protect Router — Phase 9
POST /v1/proxy/protect-document — multipart/form-data

Accepts a file upload, extracts text, applies PII protection,
and returns the protected text ready to send to an LLM.

Flow:
  1. Receive file (multipart/form-data)
  2. Validate pipeline + org
  3. Extract text from document (PDF/Excel/CSV/DOCX/Email)
  4. Detect + protect PII (same engine as /protect)
  5. INSERT audit_log with document_type + filename_hash
  6. INSERT tokens_vault (conversation-scoped)
  7. Return protected text + detections + stats
  8. BACKGROUND: iBS certification
"""
import time
import uuid
import os
import base64
import hashlib
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form
from typing import Dict, Any, Optional

from app.models.schemas import Detection
from app.services import detector
from app.services.auth import verify_api_key_or_dev
from app.services import supabase as db
from app.services import ibs
from app.services import policy_engine as pe
from app.services.document_processor import extract_text
from app.config import settings

router = APIRouter()

# Max file size: 20MB
MAX_FILE_SIZE = 20 * 1024 * 1024


@router.post("/protect-document")
async def protect_document(
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
    file: UploadFile = File(...),
    pipeline_id: str = Form(...),
    conversation_id: Optional[str] = Form(None),
    mode: str = Form("tokenise"),
    include_detections: bool = Form(True),
    reversible: bool = Form(True),
):
    """
    Protect a document — extract text, detect PII, tokenize, audit.

    multipart/form-data fields:
      - file: the document (PDF, xlsx, csv, docx, eml)
      - pipeline_id: UUID of the pipeline
      - conversation_id: optional UUID for token scoping
      - mode: tokenise | anonymise | block (default: tokenise)
      - include_detections: bool (default: true)
      - reversible: bool (default: true)
    """
    t0 = time.monotonic()
    request_id = f"req_{uuid.uuid4().hex[:12]}"

    # ── Step 1: Validate file size ────────────────────────────────────────────
    file_bytes = await file.read()
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail={"error": "file_too_large", "max_mb": 20}
        )

    # ── Step 2: Validate pipeline ─────────────────────────────────────────────
    pipeline = await db.get_pipeline(pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    org_id = pipeline["org_id"]

    # ── Step 3: Extract text ──────────────────────────────────────────────────
    filename = file.filename or "document"
    content_type = file.content_type or "application/octet-stream"

    try:
        extracted_text, document_format = extract_text(file_bytes, filename, content_type)
    except ValueError as e:
        raise HTTPException(status_code=422, detail={"error": "extraction_failed", "detail": str(e)})
    except ImportError as e:
        raise HTTPException(status_code=501, detail={"error": "format_not_supported", "detail": str(e)})

    if not extracted_text.strip():
        raise HTTPException(
            status_code=422,
            detail={"error": "empty_document", "detail": "No text could be extracted from the document"}
        )

    # ── Step 4: Load policies ─────────────────────────────────────────────────
    policies = await db.get_policy_rules(org_id, pipeline_id=pipeline_id) or []
    provider_trust = await db.get_provider_trust(pipeline.get("llm_provider", ""), org_id)

    policy_context = {
        "provider": pipeline.get("llm_provider", ""),
        "user_role": key_record.get("role", "developer"),
        "data_region": (provider_trust or {}).get("data_region", "EU"),
        "agent_mode": False,
        "pipeline_sector": pipeline.get("sector", "general"),
        "default_action": mode,
    }
    provider_risk_level = (provider_trust or {}).get("provider_risk_level", "medium")

    # ── Step 5: Detect + protect ──────────────────────────────────────────────
    detections = detector.detect(extracted_text)

    if policies and detections:
        detections = pe.apply_policies(detections, policies, policy_context)
    else:
        for d in detections:
            d.action = "tokenised" if mode == "tokenise" else mode

    # Apply tokenisation back-to-front
    protected_text = extracted_text
    counters: Dict[str, int] = {}

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
        elif detection.action in ("anonymised", "anonymise"):
            detection.action = "anonymised"
            replacement = f"[{entity_type.upper()}]"
        elif detection.action == "blocked":
            detection.action = "blocked"
            replacement = f"[BLOCKED:{entity_type.upper()}]"
        else:
            counters[entity_type] = counters.get(entity_type, 0) + 1
            token = _make_token(entity_type, counters[entity_type])
            detection.token = token
            detection.action = "tokenised"
            replacement = token

        protected_text = protected_text[:detection.start] + replacement + protected_text[detection.end:]

    processing_ms = int((time.monotonic() - t0) * 1000)
    stats = detector.build_stats(detections, processing_ms)

    risk_score = pe.compute_risk_score(
        detections,
        provider_risk_level=provider_risk_level,
        agent_mode=False,
        leaked_count=stats["leaked"],
    )
    stats["risk_score"] = risk_score

    # ── Step 6: Audit log ─────────────────────────────────────────────────────
    if not detections:
        event_type, severity, entity_type_val, action_taken = "request_clean", "low", "none", "passed"
    else:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        primary = min(detections, key=lambda d: severity_order.get(d.severity, 99))
        event_type = "pii_detected"
        severity = primary.severity
        entity_type_val = primary.type
        action_taken = primary.action
        if stats["leaked"] > 0:
            event_type = "pii_leaked"

    # Hash filename for privacy (don't store original filename)
    filename_hash = hashlib.sha256(filename.encode()).hexdigest()[:16]

    audit_payload = {
        "org_id": org_id,
        "pipeline_id": pipeline_id,
        "event_type": event_type,
        "entity_type": entity_type_val,
        "entity_category": pe._get_category(entity_type_val),
        "action_taken": action_taken,
        "severity": severity,
        "prompt_hash": hashlib.sha256(extracted_text.encode()).hexdigest(),
        "pipeline_stage": "proxy",
        "processing_ms": processing_ms,
        "ibs_status": "pending",
        "source": "document",
        "risk_score": risk_score,
        "agent_mode": False,
        "conversation_id": conversation_id if conversation_id else None,
        "metadata": {
            "request_id": request_id,
            "document_format": document_format,
            "filename_hash": filename_hash,
            "file_size_bytes": len(file_bytes),
            "extracted_chars": len(extracted_text),
            "total_detected": stats["total_detected"],
            "total_masked": stats["total_masked"],
            "by_type": stats["by_type"],
            "mode": mode,
            "risk_score": risk_score,
            "provider": pipeline.get("llm_provider", ""),
        },
    }

    audit_log_id = await db.insert_audit_log(audit_payload)

    # ── Step 7: Tokens vault ──────────────────────────────────────────────────
    if detections and audit_log_id and reversible:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            enc_key_hex = settings.ENCRYPTION_KEY
            enc_key = bytes.fromhex(enc_key_hex) if enc_key_hex else os.urandom(32)
        except Exception:
            enc_key = os.urandom(32)

        token_rows = []
        for d in detections:
            if d.action == "tokenised" and d.token and d.start is not None and d.end is not None:
                original_value = extracted_text[d.start:d.end]
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    aesgcm = AESGCM(enc_key)
                    nonce = os.urandom(12)
                    ciphertext = aesgcm.encrypt(nonce, original_value.encode("utf-8"), None)
                    encrypted = base64.b64encode(nonce + ciphertext).decode("utf-8")
                except Exception as e:
                    print(f"[Vault] Encryption error: {e}")
                    continue

                # Reuse existing token if conversation-scoped
                if conversation_id:
                    existing = await db.find_existing_token(
                        org_id=org_id,
                        conversation_id=conversation_id,
                        entity_type=d.type,
                        encrypted_value=encrypted,
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
                    "encryption_key_id": "key-v1",
                    "is_reversible": True,
                    "access_roles": ["admin", "dpo"],
                    "conversation_id": conversation_id,
                })

        if token_rows:
            background_tasks.add_task(db.insert_tokens_batch, token_rows)

    # ── Step 8: iBS certification ─────────────────────────────────────────────
    if audit_log_id:
        background_tasks.add_task(
            ibs.certify_audit_log,
            audit_log_id,
            org_id,
            audit_payload.get("metadata", {}),
        )

    # ── Step 9: Pipeline counters ─────────────────────────────────────────────
    background_tasks.add_task(
        db.increment_pipeline_counters,
        pipeline_id,
        stats["total_detected"],
        stats["total_masked"],
        stats["leaked"],
        processing_ms,
    )

    return {
        "request_id": request_id,
        "document_format": document_format,
        "filename": filename,
        "extracted_chars": len(extracted_text),
        "protected_text": protected_text,
        "detections": [d.model_dump() for d in detections] if include_detections else [],
        "stats": stats,
        "audit_log_id": audit_log_id,
        "gdpr_compliant": stats["leaked"] == 0,
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
