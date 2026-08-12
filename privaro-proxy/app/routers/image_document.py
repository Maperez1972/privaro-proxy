"""
Image-Document Protect Router — Tier 1 (Tesseract OCR)
POST /v1/proxy/protect-image-document — multipart/form-data

Accepts a photographed/scanned document image (DNI, contract, screenshot),
OCRs it, applies the exact same PII detection/policy engine used everywhere
else in Privaro, and returns both the protected text AND a redacted copy
of the image with PII regions blacked out.

Deliberately Tier-1-only for now (2026-08-11): only Tesseract, no cloud OCR
fallback yet. Real business decision, not an oversight — with a single
production client (Octupus) and Tesseract's real-world accuracy on photos
(vs. clean scans) still unknown, building a paid cloud-OCR escalation path
before having actual quality data would be guessing at a cost tradeoff
blind. This endpoint returns per-word OCR confidence stats explicitly in
`ocr_quality` so real usage can be measured before deciding whether Tier 2
is worth building at all, and if so, at what confidence threshold to
escalate. Naming note: "Tier 1/Tier 2" here refers to OCR engine choice
(Tesseract vs. cloud), unrelated to detector.py's own Tier 1/Tier 2
terminology for regex vs. Presidio/NLP detection.

Flow:
  1. Receive image (multipart/form-data)
  2. Validate pipeline + org
  3. OCR with Tesseract, keeping per-word bounding boxes + confidence
  4. Reconstruct full text from words (preserving line structure)
  5. Detect + protect PII (same engine as /protect and /protect-document)
  6. Map each detected text span back to the word boxes it covers
  7. Redact those regions on the image (solid black boxes)
  8. INSERT audit_log + tokens_vault (conversation-scoped), same as /protect-document
  9. Return protected text + redacted image (base64) + detections + OCR quality stats
"""
import time
import uuid
import os
import io
import base64
import hashlib
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form
from typing import Dict, Any, List, Optional, Tuple

import re
from app.services import detector
from app.services.detector import _verify_spanish_id_checksum
from app.services.auth import verify_api_key_or_internal
from app.services import supabase as db
from app.services import ibs
from app.services import policy_engine as pe
from app.config import settings

router = APIRouter()

MAX_FILE_SIZE = 15 * 1024 * 1024  # 15MB — photos from phones can be large
SUPPORTED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp", "image/tiff"}

# Below this per-word confidence (Tesseract's 0-100 scale), a word is
# counted as "low confidence" in ocr_quality — chosen as a starting point
# for gathering real data, not a validated threshold. Revisit once there's
# a real distribution to look at.
LOW_CONFIDENCE_THRESHOLD = 60

TOKEN_PREFIX = {
    "full_name": "NM", "dni": "ID", "nie": "ID", "iban": "BK",
    "credit_card": "CC", "email": "EM", "phone": "PH",
    "health_record": "HC", "ip_address": "IP", "date_of_birth": "DT", "ssn": "SS",
    "passport": "PP", "money": "MN", "license_plate": "LP", "address": "AD",
}


def _make_token(entity_type: str, counter: int) -> str:
    prefix = TOKEN_PREFIX.get(entity_type, "XX")
    return f"[{prefix}-{counter:04d}]"


def _ocr_with_boxes(image_bytes: bytes) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Runs Tesseract on the image, returns:
      - full_text: reconstructed text (line breaks preserved)
      - word_spans: list of {start, end, left, top, width, height, conf} —
        start/end are character offsets into full_text
      - quality: aggregate OCR confidence stats

    Reconstruction logic: Tesseract's image_to_data returns one row per
    word with its (block, paragraph, line) position. Words on the same
    line are joined with a single space; lines are joined with "\n". Each
    word's [start, end) offset into the resulting string is recorded so a
    later PII detection's character span can be mapped back to exactly
    which word boxes it covers.
    """
    import pytesseract
    from PIL import Image

    image = Image.open(io.BytesIO(image_bytes))
    if image.mode != "RGB":
        image = image.convert("RGB")

    data = pytesseract.image_to_data(
        image, lang="spa+eng", output_type=pytesseract.Output.DICT
    )

    n = len(data["text"])
    words = []
    for i in range(n):
        text = data["text"][i].strip()
        conf = int(data["conf"][i]) if str(data["conf"][i]).lstrip("-").isdigit() else -1
        if not text or conf < 0:
            continue
        words.append({
            "text": text,
            "conf": conf,
            "left": data["left"][i], "top": data["top"][i],
            "width": data["width"][i], "height": data["height"][i],
            "line_key": (data["block_num"][i], data["par_num"][i], data["line_num"][i]),
        })

    full_text_parts: List[str] = []
    word_spans: List[Dict[str, Any]] = []
    offset = 0
    prev_line_key = None

    for w in words:
        if prev_line_key is not None and w["line_key"] != prev_line_key:
            full_text_parts.append("\n")
            offset += 1
        elif prev_line_key is not None:
            full_text_parts.append(" ")
            offset += 1

        start = offset
        full_text_parts.append(w["text"])
        offset += len(w["text"])
        end = offset

        word_spans.append({
            "start": start, "end": end,
            "left": w["left"], "top": w["top"], "width": w["width"], "height": w["height"],
            "conf": w["conf"],
        })
        prev_line_key = w["line_key"]

    full_text = "".join(full_text_parts)

    confidences = [w["conf"] for w in words]
    total = len(confidences)
    low_conf_count = sum(1 for c in confidences if c < LOW_CONFIDENCE_THRESHOLD)
    quality = {
        "engine": "tesseract",
        "words_detected": total,
        "avg_confidence": round(sum(confidences) / total, 1) if total else None,
        "min_confidence": min(confidences) if total else None,
        "low_confidence_word_pct": round(100 * low_conf_count / total, 1) if total else None,
        "low_confidence_threshold": LOW_CONFIDENCE_THRESHOLD,
    }

    return full_text, word_spans, quality


def _ocr_with_google_vision(image_bytes: bytes) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Tier 2 OCR (2026-08-11) — Google Cloud Vision's DOCUMENT_TEXT_DETECTION.
    Same output contract as _ocr_with_boxes (Tesseract, Tier 1): full_text,
    word_spans (character offsets into full_text + pixel box), quality dict.
    This makes it a drop-in alternative, not a parallel code path.

    Verified against a real API call before writing this (not assumed from
    docs alone): confidence is available per-word AND per-symbol via
    fullTextAnnotation.pages[].blocks[].paragraphs[].words[].symbols[] —
    finer-grained than Tesseract's word-only confidence. boundingBox comes
    as 4 vertices (not left/top/width/height like Tesseract), converted
    here via min/max of the vertices.

    Real API key required via GOOGLE_VISION_API_KEY env var. Auth is a
    simple `?key=` query param (confirmed working directly against
    the real endpoint) — not OAuth2/service-account, so no extra
    google-cloud-vision SDK dependency needed, just httpx.
    """
    import httpx as _httpx

    api_key = settings.GOOGLE_VISION_API_KEY
    if not api_key:
        raise RuntimeError("GOOGLE_VISION_API_KEY not configured")

    payload = {
        "requests": [{
            "image": {"content": base64.b64encode(image_bytes).decode("utf-8")},
            "features": [{"type": "DOCUMENT_TEXT_DETECTION"}],
            "imageContext": {"languageHints": ["es"]},
        }]
    }

    with _httpx.Client(timeout=30.0) as client:
        resp = client.post(
            f"https://vision.googleapis.com/v1/images:annotate?key={api_key}",
            json=payload,
        )
    resp.raise_for_status()
    data = resp.json()
    result = data.get("responses", [{}])[0]

    if "error" in result:
        raise RuntimeError(f"Google Vision error: {result['error'].get('message', 'unknown')}")

    full_annotation = result.get("fullTextAnnotation")
    if not full_annotation:
        return "", [], {"engine": "google_vision", "words_detected": 0, "avg_confidence": None,
                         "min_confidence": None, "low_confidence_word_pct": None,
                         "low_confidence_threshold": LOW_CONFIDENCE_THRESHOLD}

    full_text_parts: List[str] = []
    word_spans: List[Dict[str, Any]] = []
    confidences: List[float] = []
    offset = 0

    # Fixed 2026-08-11 during verification: assuming "new paragraph = new
    # line" produced wrong reconstructions (e.g. two visually separate
    # lines merged into one, because Google Vision groups multiple visual
    # lines into the same "paragraph" when they're related). The real,
    # precise signal is symbol.property.detectedBreak.type on each word's
    # LAST symbol — verified directly against a real API response before
    # relying on it: SPACE/SURE_SPACE -> a space; EOL_SURE_SPACE/LINE_BREAK
    # -> an actual newline. This mirrors how the text visually breaks,
    # rather than inferring it from paragraph structure.
    for page in full_annotation.get("pages", []):
        for block in page.get("blocks", []):
            for paragraph in block.get("paragraphs", []):
                for word in paragraph.get("words", []):
                    symbols = word.get("symbols", [])
                    word_text = "".join(s.get("text", "") for s in symbols)
                    if not word_text:
                        continue
                    conf_pct = round(word.get("confidence", 0.0) * 100, 1)
                    confidences.append(conf_pct)

                    start = offset
                    full_text_parts.append(word_text)
                    offset += len(word_text)
                    end = offset

                    vertices = word.get("boundingBox", {}).get("vertices", [])
                    xs = [v.get("x", 0) for v in vertices] or [0]
                    ys = [v.get("y", 0) for v in vertices] or [0]
                    left, top = min(xs), min(ys)

                    word_spans.append({
                        "start": start, "end": end,
                        "left": left, "top": top,
                        "width": max(xs) - left, "height": max(ys) - top,
                        "conf": conf_pct,
                    })

                    break_type = (symbols[-1].get("property", {}).get("detectedBreak", {}) or {}).get("type")
                    if break_type in ("LINE_BREAK", "EOL_SURE_SPACE"):
                        full_text_parts.append("\n")
                        offset += 1
                    elif break_type in ("SPACE", "SURE_SPACE"):
                        full_text_parts.append(" ")
                        offset += 1
                    # HYPHEN or no break: no separator inserted (word continues)

    full_text = "".join(full_text_parts).rstrip("\n").rstrip(" ")
    total = len(confidences)
    low_conf_count = sum(1 for c in confidences if c < LOW_CONFIDENCE_THRESHOLD)
    quality = {
        "engine": "google_vision",
        "words_detected": total,
        "avg_confidence": round(sum(confidences) / total, 1) if total else None,
        "min_confidence": min(confidences) if total else None,
        "low_confidence_word_pct": round(100 * low_conf_count / total, 1) if total else None,
        "low_confidence_threshold": LOW_CONFIDENCE_THRESHOLD,
    }
    return full_text, word_spans, quality


def _should_escalate_to_tier2(full_text: str) -> bool:
    """
    Decides whether Tier 1 (Tesseract) output is trustworthy enough, or
    whether to re-run with Tier 2 (Google Vision).

    v1 (earlier today) required first matching ID-document keywords
    ("DNI", "IDENTIDAD", etc.) before checking the DNI shape/checksum.
    Fixed after testing against a real photographed DNI: OCR quality was
    so poor (hologram, glare, photo overlaid on text) that NONE of those
    keywords were read either — not just the DNI number. The trigger
    designed to catch bad OCR never fired precisely because the OCR was
    bad, the opposite of what it needed to do.

    v2 (this fix): escalate directly whenever no checksum-valid DNI/NIE
    shape is found in the text — full stop, no keyword precondition. This
    endpoint's real-world use case is already "photographed identity
    documents", so a slightly higher false-escalation rate (paying for a
    Tier 2 call on an image that turns out not to be an ID) is an
    acceptable and cheap tradeoff (Google Vision: ~$1.50/1000 images)
    against the alternative of silently failing to protect the one field
    that matters most.
    """
    dni_pattern = re.compile(
        r'\b(?:DNI|NIF|NIE)[\s:]+([XYZxyz]?\d{7,8}[A-Za-z])\b'
        r'|\b([XYZxyz]\d{7}[A-Za-z])\b'
        r'|\b(\d{8}[A-Za-z])\b'
    )
    match = dni_pattern.search(full_text)
    if not match:
        return True

    matched_value = next(g for g in match.groups() if g)
    return not _verify_spanish_id_checksum(matched_value)


def _redact_image(image_bytes: bytes, boxes: List[Dict[str, int]]) -> bytes:
    """Draws solid black rectangles over the given pixel boxes and returns
    the result as PNG bytes."""
    from PIL import Image, ImageDraw

    image = Image.open(io.BytesIO(image_bytes))
    if image.mode != "RGB":
        image = image.convert("RGB")
    draw = ImageDraw.Draw(image)

    for b in boxes:
        x0, y0 = b["left"], b["top"]
        x1, y1 = b["left"] + b["width"], b["top"] + b["height"]
        draw.rectangle([x0, y0, x1, y1], fill="black")

    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def _boxes_for_span(word_spans: List[Dict[str, Any]], start: int, end: int) -> List[Dict[str, int]]:
    """Every word box whose character range overlaps [start, end)."""
    return [
        {"left": w["left"], "top": w["top"], "width": w["width"], "height": w["height"]}
        for w in word_spans
        if w["start"] < end and w["end"] > start
    ]


@router.post("/protect-image-document")
async def protect_image_document(
    background_tasks: BackgroundTasks,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_internal),
    file: UploadFile = File(...),
    pipeline_id: str = Form(...),
    conversation_id: Optional[str] = Form(None),
    mode: str = Form("tokenise"),
    include_detections: bool = Form(True),
    reversible: bool = Form(True),
    return_redacted_image: bool = Form(True),
    extract_only: bool = Form(False),
):
    """
    Protect a photographed/scanned document — OCR, detect PII, tokenize
    the text, and (optionally) return the image with those regions redacted.

    multipart/form-data fields:
      - file: the image (jpeg, png, webp, tiff)
      - pipeline_id: UUID of the pipeline
      - conversation_id: optional UUID for token scoping
      - mode: tokenise | anonymise | block (default: tokenise)
      - include_detections: bool (default: true)
      - reversible: bool (default: true)
      - return_redacted_image: bool (default: true) — set false to skip
        image redaction entirely if only the protected text is needed
        (saves the redaction step, not the OCR step)
      - extract_only: bool (default: false) — OCR only, no detection, no
        tokenisation, no audit log, no vault write. Added 2026-08-11 for
        the chat attachment flow: extracting a preview of an attached
        image happens BEFORE the user hits send, same as the existing
        PDF/DOCX text-extraction step — real protection happens once,
        later, when the full message (text + extracted file content) is
        sent through protect-chat-message. Calling this endpoint in full
        mode at attach-time would write an audit log / vault tokens for
        every attach, even if the user never sends the message.
    """
    t0 = time.monotonic()
    request_id = f"req_{uuid.uuid4().hex[:12]}"

    # ── Step 1: Validate file ─────────────────────────────────────────────────
    file_bytes = await file.read()
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail={"error": "file_too_large", "max_mb": 15})

    content_type = file.content_type or "application/octet-stream"
    if content_type not in SUPPORTED_CONTENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail={"error": "unsupported_image_type", "supported": sorted(SUPPORTED_CONTENT_TYPES)},
        )

    # ── Step 2: Validate pipeline ─────────────────────────────────────────────
    pipeline = await db.get_pipeline(pipeline_id)
    if not pipeline:
        raise HTTPException(status_code=404, detail={"error": "pipeline_not_found"})
    if pipeline["org_id"] != key_record["org_id"]:
        raise HTTPException(status_code=403, detail={"error": "pipeline_org_mismatch"})

    org_id = pipeline["org_id"]

    # ── Step 3-4: OCR ──────────────────────────────────────────────────────────
    # Changed 2026-08-12 (explicit decision, not a default): Google Vision is
    # now the PRIMARY engine, not a conditional escalation from Tesseract.
    # Reasoning: repeated real-world Tesseract failures today (control-letter
    # misread as a digit with no confidence drop, OCR segmentation gluing
    # unrelated text together) made confidence in Tesseract-first low enough
    # that the marginal cost of Google Vision (~$1.50/1000 images, trivial at
    # current volume) is worth paying on every call rather than only when a
    # (fallible) trigger decides it's needed. Real tradeoff worth restating
    # here even though the decision is made: every image now leaves to a
    # third party (Google) unprotected before Privaro can tokenize anything,
    # not just the ones that would have failed Tier 1 — previously this only
    # happened on escalation. Revisit if this endpoint's use case broadens
    # beyond ID documents, where that tradeoff may weigh differently.
    #
    # Tesseract is kept as a resilience fallback ONLY — if Google Vision
    # itself errors (key not configured, quota, network), not as a quality
    # comparison. _should_escalate_to_tier2 is no longer used for this reason
    # but left in the module in case a future cost-sensitive mode wants it back.
    if settings.GOOGLE_VISION_API_KEY:
        try:
            extracted_text, word_spans, ocr_quality = _ocr_with_google_vision(file_bytes)
        except Exception as e:
            print(f"[ImageDocument] Google Vision failed, falling back to Tesseract: {e}")
            try:
                extracted_text, word_spans, ocr_quality = _ocr_with_boxes(file_bytes)
                ocr_quality["fell_back_to_tier1"] = True
            except Exception as e2:
                raise HTTPException(status_code=422, detail={"error": "ocr_failed", "detail": str(e2)})
    else:
        try:
            extracted_text, word_spans, ocr_quality = _ocr_with_boxes(file_bytes)
        except Exception as e:
            raise HTTPException(status_code=422, detail={"error": "ocr_failed", "detail": str(e)})

    if extract_only:
        # No pipeline-scoped side effects at all here — no audit log, no
        # vault write, no quota increment. Real protection happens later
        # when the caller sends the extracted text through the normal
        # text-protection path (e.g. protect-chat-message -> /v1/proxy/protect).
        return {
            "request_id": request_id,
            "filename": file.filename or "image",
            "extracted_text": extracted_text,
            "extracted_chars": len(extracted_text),
            "ocr_quality": ocr_quality,
        }

    if not extracted_text.strip():
        raise HTTPException(
            status_code=422,
            detail={"error": "no_text_detected", "detail": "OCR found no readable text in the image", "ocr_quality": ocr_quality},
        )

    # ── Step 5: Load policies ─────────────────────────────────────────────────
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

    # ── Step 6: Detect + protect (identical engine to /protect-document) ─────
    detections = detector.detect(extracted_text)

    if policies and detections:
        detections = pe.apply_policies(detections, policies, policy_context)
    else:
        for d in detections:
            d.action = "tokenised" if mode == "tokenise" else mode

    protected_text = extracted_text
    counters: Dict[str, int] = {}
    redaction_boxes: List[Dict[str, int]] = []

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

        # Map this detection's text span back to the image regions it
        # covers, BEFORE editing protected_text (start/end indices are
        # only valid against the original extracted_text).
        redaction_boxes.extend(_boxes_for_span(word_spans, detection.start, detection.end))

        protected_text = protected_text[:detection.start] + replacement + protected_text[detection.end:]

    processing_ms = int((time.monotonic() - t0) * 1000)
    stats = detector.build_stats(detections, processing_ms)

    risk_score = pe.compute_risk_score(
        detections, provider_risk_level=provider_risk_level,
        agent_mode=False, leaked_count=stats["leaked"],
    )
    stats["risk_score"] = risk_score

    # ── Step 7: Redact image ──────────────────────────────────────────────────
    redacted_image_b64 = None
    if return_redacted_image and redaction_boxes:
        try:
            redacted_bytes = _redact_image(file_bytes, redaction_boxes)
            redacted_image_b64 = base64.b64encode(redacted_bytes).decode("utf-8")
        except Exception as e:
            print(f"[ImageDocument] Redaction error: {e}")

    # ── Step 8: Audit log ──────────────────────────────────────────────────────
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

    filename = file.filename or "image"
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
        "source": "image_document",
        "risk_score": risk_score,
        "agent_mode": False,
        "conversation_id": conversation_id if conversation_id else None,
        "metadata": {
            "request_id": request_id,
            "filename_hash": filename_hash,
            "file_size_bytes": len(file_bytes),
            "extracted_chars": len(extracted_text),
            "total_detected": stats["total_detected"],
            "total_masked": stats["total_masked"],
            "by_type": stats["by_type"],
            "mode": mode,
            "risk_score": risk_score,
            "provider": pipeline.get("llm_provider", ""),
            "ocr_quality": ocr_quality,
        },
    }

    audit_log_id = await db.insert_audit_log(audit_payload)

    # ── Step 9: Tokens vault (identical pattern to /protect-document) ────────
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
                original_value_hash = hashlib.sha256(original_value.encode("utf-8")).hexdigest()
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    aesgcm = AESGCM(enc_key)
                    nonce = os.urandom(12)
                    ciphertext = aesgcm.encrypt(nonce, original_value.encode("utf-8"), None)
                    encrypted = base64.b64encode(nonce + ciphertext).decode("utf-8")
                except Exception as e:
                    print(f"[Vault] Encryption error: {e}")
                    continue

                if conversation_id:
                    existing = await db.find_existing_token(
                        org_id=org_id, conversation_id=conversation_id,
                        entity_type=d.type, original_value_hash=original_value_hash,
                    )
                    if existing:
                        d.token = existing["token_value"]
                        continue

                token_rows.append({
                    "org_id": org_id, "pipeline_id": pipeline_id,
                    "entity_type": d.type, "token_value": d.token,
                    "encrypted_original": encrypted, "encryption_key_id": "key-v1",
                    "original_value_hash": original_value_hash,
                    "is_reversible": True, "access_roles": ["admin", "dpo"],
                    "conversation_id": conversation_id,
                })

        if token_rows:
            background_tasks.add_task(db.insert_tokens_batch, token_rows)

    # ── Step 10: iBS certification + pipeline counters ────────────────────────
    if audit_log_id:
        background_tasks.add_task(
            ibs.certify_audit_log, audit_log_id, org_id, audit_payload.get("metadata", {}),
        )

    background_tasks.add_task(
        db.increment_pipeline_counters,
        pipeline_id, stats["total_detected"], stats["total_masked"], stats["leaked"], processing_ms,
    )

    return {
        "request_id": request_id,
        "filename": filename,
        "extracted_chars": len(extracted_text),
        "protected_text": protected_text,
        "redacted_image_base64": redacted_image_b64,
        "detections": [d.model_dump() for d in detections] if include_detections else [],
        "stats": stats,
        "ocr_quality": ocr_quality,
        "audit_log_id": audit_log_id,
        "gdpr_compliant": stats["leaked"] == 0,
    }
