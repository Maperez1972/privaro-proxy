"""
PII Detection Engine — MVP v0.1
Detects PII using regex patterns for Spanish/EU entities.

Phase 2 will add: Microsoft Presidio + spaCy es_core_news_lg
Current coverage:
  - DNI / NIE / NIF (Spain)
  - IBAN ES
  - Email
  - Phone (Spain + international)
  - Full name (heuristic)
  - Credit card numbers
  - IP addresses
  - Dates of birth patterns
"""
import re
import uuid
from typing import List, Tuple
from app.models.schemas import Detection


# ── Pattern registry ────────────────────────────────────────────────────────
# Each entry: (entity_type, severity, pattern, confidence)
PATTERNS: List[Tuple[str, str, re.Pattern, float]] = [

    # DNI: 8 digits + letter. NIE: X/Y/Z + 7 digits + letter
    ("dni", "critical",
     re.compile(r'\b(?:DNI|NIF|NIE)?[\s:]*([XYZxyz]?\d{7,8}[A-Za-z])\b'),
     0.95),

    # IBAN ES: ES + 2 check digits + 20 digits (spaces optional)
    ("iban", "critical",
     re.compile(r'\bES\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
     0.99),

    # Credit card: 13-19 digits with spacing patterns (Luhn not checked in MVP)
    ("credit_card", "critical",
     re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4}\b'),
     0.90),

    # Email
    ("email", "high",
     re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
     0.99),

    # Spanish phone: +34 or 6xx/7xx/9xx, 9 digits
    ("phone", "high",
     re.compile(r'(?:\+34[\s-]?)?(?:6\d{2}|7[1-9]\d|9\d{2})[\s-]?\d{3}[\s-]?\d{3}\b'),
     0.90),

    # International phone (loose): +XX format
    ("phone", "medium",
     re.compile(r'\+(?!34)\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b'),
     0.75),

    # SIP (Sistema de Información de Población) / Health card ES
    # Format: XXXX-XXXXXXXX-XX (varies by region)
    ("health_record", "critical",
     re.compile(r'\b(?:SIP|TSI|CIP)[\s:]*([A-Z0-9]{8,16})\b', re.IGNORECASE),
     0.85),

    # IPv4
    ("ip_address", "medium",
     re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
     0.99),

    # Date of birth patterns (common formats)
    ("date_of_birth", "medium",
     re.compile(r'\b(?:nacido?|born|dob|f\.?nac\.?)[\s:]+(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b', re.IGNORECASE),
     0.85),

    # Full name heuristic: 2-3 capitalized words, typical Spanish surnames
    # Triggered by keywords: paciente, nombre, cliente, empleado, sr/sra, don/doña
    ("full_name", "low",
     re.compile(
         r'(?:paciente|nombre|cliente|empleado|trabajador|sr\.?|sra\.?|don|doña|mr\.?|ms\.?|mrs\.?)[\s:]+([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){1,3})',
         re.IGNORECASE
     ),
     0.80),
]

# ── Severity → category mapping ─────────────────────────────────────────────
ENTITY_CATEGORY = {
    "dni": "personal",
    "iban": "financial",
    "credit_card": "financial",
    "email": "personal",
    "phone": "personal",
    "health_record": "special",       # GDPR Art.9 special category
    "full_name": "personal",
    "ip_address": "personal",
    "date_of_birth": "personal",
    "ssn": "personal",
}

# ── Token counters per type (per-request, reset each call) ──────────────────
TOKEN_PREFIX = {
    "full_name": "NM",
    "dni": "ID",
    "nie": "ID",
    "iban": "BK",
    "credit_card": "CC",
    "email": "EM",
    "phone": "PH",
    "health_record": "HC",
    "ip_address": "IP",
    "date_of_birth": "DT",
    "ssn": "SS",
}


def _make_token(entity_type: str, counter: int) -> str:
    prefix = TOKEN_PREFIX.get(entity_type, "XX")
    return f"[{prefix}-{counter:04d}]"


def detect(text: str) -> List[Detection]:
    """
    Detect PII entities in text using regex patterns.
    Returns list of Detection objects sorted by position (start offset).
    """
    detections: List[Detection] = []
    seen_spans: List[Tuple[int, int]] = []  # avoid overlapping matches

    for entity_type, severity, pattern, confidence in PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()

            # Skip if overlaps with an already-detected span
            if any(s <= start < e or s < end <= e for s, e in seen_spans):
                continue

            seen_spans.append((start, end))
            detections.append(Detection(
                type=entity_type,
                severity=severity,
                action="detected",          # will be updated by protect()
                token=None,
                start=start,
                end=end,
                confidence=confidence,
                detector="regex",
            ))

    # Sort by position in text
    detections.sort(key=lambda d: d.start or 0)
    return detections


def protect(text: str, mode: str = "tokenise") -> Tuple[str, List[Detection]]:
    """
    Detect and apply protection (tokenise / anonymise / block) to text.
    Returns (protected_text, detections_with_actions).
    """
    detections = detect(text)
    if not detections:
        return text, []

    if mode == "block":
        # If ANY PII found, block the entire request
        for d in detections:
            d.action = "blocked"
        return "[BLOCKED: PII detected]", detections

    # Build protected text by replacing matches back-to-front
    # (back-to-front preserves offsets for earlier matches)
    counters: dict = {}
    result = text

    for detection in reversed(detections):
        start, end = detection.start, detection.end
        entity_type = detection.type

        if mode == "tokenise":
            counters[entity_type] = counters.get(entity_type, 0) + 1
            token = _make_token(entity_type, counters[entity_type])
            detection.token = token
            detection.action = "tokenised"
            replacement = token

        elif mode == "anonymise":
            detection.action = "anonymised"
            replacement = f"[{entity_type.upper()}]"

        result = result[:start] + replacement + result[end:]

    return result, detections


def build_stats(detections: List[Detection], processing_ms: int) -> dict:
    total = len(detections)
    masked = sum(1 for d in detections if d.action in ("tokenised", "anonymised", "blocked"))
    leaked = sum(1 for d in detections if d.action == "leaked")
    coverage = round((masked / total * 100) if total > 0 else 100.0, 1)

    return {
        "total_detected": total,
        "total_masked": masked,
        "leaked": leaked,
        "coverage_pct": coverage,
        "processing_ms": processing_ms,
        "by_type": {
            t: sum(1 for d in detections if d.type == t)
            for t in set(d.type for d in detections)
        },
    }
