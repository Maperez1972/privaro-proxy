"""
NLP Detection Engine — Phase 8 — Tier 2
Microsoft Presidio + spaCy es_core_news_md

Detects entities that regex cannot:
  - full_name without keywords (contextual)
  - address fragments
  - implicit PII in free text

Loaded lazily on first use to avoid startup penalty.
Falls back gracefully if model not available.
"""
import logging
from typing import List, Optional
from app.models.schemas import Detection

logger = logging.getLogger(__name__)

# ── Lazy-loaded singletons ────────────────────────────────────────────────────
_analyzer = None
_nlp_available = None


def _get_analyzer():
    global _analyzer, _nlp_available

    if _nlp_available is False:
        return None
    if _analyzer is not None:
        return _analyzer

    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        # Configure Presidio with spaCy ES model
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "es", "model_name": "es_core_news_md"}],
        })
        nlp_engine = provider.create_engine()

        _analyzer = AnalyzerEngine(
            nlp_engine=nlp_engine,
            supported_languages=["es", "en"],
        )
        _nlp_available = True
        logger.info("[NLP] Presidio + spaCy es_core_news_md loaded ✅")
        return _analyzer

    except Exception as e:
        _nlp_available = False
        logger.warning(f"[NLP] Presidio unavailable — falling back to regex only: {e}")
        return None


# ── Presidio entity → Privaro entity_type mapping ────────────────────────────
PRESIDIO_TO_PRIVARO = {
    "PERSON":           ("full_name",    "low",      0.75),
    "EMAIL_ADDRESS":    ("email",        "high",     0.99),
    "PHONE_NUMBER":     ("phone",        "high",     0.88),
    "ES_NIF":           ("dni",          "critical", 0.95),
    "ES_NIE":           ("dni",          "critical", 0.95),
    "IBAN_CODE":        ("iban",         "critical", 0.99),
    "CREDIT_CARD":      ("credit_card",  "critical", 0.92),
    "IP_ADDRESS":       ("ip_address",   "medium",   0.99),
    "DATE_TIME":        ("date_of_birth","medium",   0.70),
    "LOCATION":         ("full_name",    "low",      0.60),  # addresses
    "NRP":              ("dni",          "critical", 0.85),  # national registration
}

# Minimum confidence threshold for NLP results
# Raised from 0.65 → 0.75 to reduce false positives on capitalized text
# (e.g. legal document headers, contract titles, clause references)
NLP_CONFIDENCE_THRESHOLD = 0.75


def detect_nlp(
    text: str,
    existing_spans: List[tuple],
    language: str = "es",
) -> List[Detection]:
    """
    Run Presidio NLP detection on text.
    Skips spans already detected by Tier 1 regex.
    Returns new detections only.
    """
    analyzer = _get_analyzer()
    if not analyzer:
        return []

    try:
        results = analyzer.analyze(
            text=text,
            language=language,
            entities=list(PRESIDIO_TO_PRIVARO.keys()),
            score_threshold=NLP_CONFIDENCE_THRESHOLD,
        )
    except Exception as e:
        logger.warning(f"[NLP] Analysis failed: {e}")
        return []

    new_detections = []
    for result in results:
        start, end = result.start, result.end

        # Skip if overlaps with already-detected regex span
        if any(s <= start < e2 or s < end <= e2
               for s, e2 in existing_spans):
            continue

        mapping = PRESIDIO_TO_PRIVARO.get(result.entity_type)
        if not mapping:
            continue

        entity_type, severity, base_confidence = mapping
        confidence = min(result.score, base_confidence)

        # ── Post-NLP filter: full_name requires ≥2 consecutive capitalized words ──
        # Avoids false positives on single capitalized words in legal documents,
        # contract clause titles, article headers, etc.
        # e.g. "CONTRATO", "CLÁUSULA", "Parte" → rejected
        # e.g. "Juan García", "MIGUEL ÁNGEL PÉREZ" → accepted
        if entity_type == "full_name":
            span_text = text[start:end]
            # Count consecutive capitalized tokens (words starting with uppercase
            # or fully uppercase, excluding pure punctuation/numbers)
            import re as _re
            tokens = span_text.split()
            cap_tokens = [t for t in tokens if _re.match(r'^[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñA-ZÁÉÍÓÚÜÑ]*$', t)]
            if len(cap_tokens) < 2:
                logger.debug(
                    f"[NLP] Skipping full_name false positive: '{span_text}' "
                    f"(only {len(cap_tokens)} capitalized word(s))"
                )
                continue

        new_detections.append(Detection(
            type=entity_type,
            severity=severity,
            action="detected",
            token=None,
            start=start,
            end=end,
            confidence=round(confidence, 3),
            detector="presidio",
        ))

    return new_detections


def is_available() -> bool:
    """Check if NLP engine is loaded and ready."""
    return _get_analyzer() is not None
