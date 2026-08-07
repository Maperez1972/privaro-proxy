"""
PII Detection Engine — Phase 8 — Hybrid Architecture
Tier 1: Regex (deterministic, high confidence, structured data)
Tier 2: Presidio + spaCy ES (contextual NLP, free text, names)

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
import logging
from typing import List, Tuple, Optional, Dict
from app.models.schemas import Detection


# ── Pattern registry ────────────────────────────────────────────────────────
# Each entry: (entity_type, severity, pattern, confidence)
PATTERNS: List[Tuple[str, str, re.Pattern, float]] = [

    # DNI / NIF / NIE: optional "DNI:"/"NIF:"/"NIE:" prefix + digits + letter
    # Group captures ONLY the number — excludes the keyword prefix from span.
    #
    # Fixed 2026-07-30 — real gap found: a bare NIE (letter + 7 digits +
    # letter, e.g. "X1234567L") with NO "NIE:" label in front never matched
    # the old standalone branch, which required exactly 8 digits regardless
    # of the leading letter — that's the DNI shape, not the NIE shape. A
    # real Spanish DNI has no leading letter and exactly 8 digits; a real
    # NIE has a leading X/Y/Z and exactly 7 digits. The standalone branch
    # now requires the correct digit count for each shape instead of always
    # demanding 8.
    ("dni", "critical",
     re.compile(
         r'\b(?:DNI|NIF|NIE)[\s:]+([XYZxyz]?\d{7,8}[A-Za-z])\b'
         r'|\b([XYZxyz]\d{7}[A-Za-z])\b'   # bare NIE: letter + 7 digits + letter
         r'|\b(\d{8}[A-Za-z])\b'           # bare DNI: 8 digits + letter, no leading letter
     ),
     0.95),

    # IBAN ES: ES + 2 check digits + 20 digits (spaces optional)
    ("iban", "critical",
     re.compile(r'\bES\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
     0.99),

    # IBAN — any other country (generic format: 2 letters + 2 check digits +
    # up to 30 alphanumeric chars, per ISO 13616). Added 2026-07-30 — real
    # gap: the ES-only pattern above left every non-Spanish IBAN (DE, FR,
    # IT, PT, NL...) completely unprotected, which matters for any org with
    # EU clients/suppliers outside Spain. Slightly lower confidence than the
    # ES-specific pattern since the generic shape is looser (a coincidental
    # 2-letter+2-digit+alphanumeric string is more plausible than the exact
    # ES structure), and explicitly excludes ES here to avoid double-firing
    # with the stricter pattern above (seen_spans dedup would handle it
    # anyway, but keeping the intent explicit).
    ("iban", "critical",
     re.compile(r'\b(?!ES)[A-Z]{2}\d{2}[\s-]?(?:[A-Z0-9]{4}[\s-]?){2,7}[A-Z0-9]{1,4}\b'),
     0.85),

    # Credit card: 13-19 digits with spacing patterns (Luhn not checked in MVP)
    ("credit_card", "critical",
     re.compile(r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4}\b'),
     0.90),

    # Email
    ("email", "high",
     re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
     0.99),

    # Spanish phone — covers all common ES formats:
    #   677 23 45 67  (3+2+2+2)
    #   677 234 567   (3+3+3)
    # Spanish mobile/landline: 9\d{2}|6\d{2}|7[1-9]\d prefix + exactly 6 more
    # digits (grouped as 3+3 or 2+2+2 — the two conventional Spanish
    # formattings), for exactly 9 digits total.
    #   677 23 45 67  677234567  677-23-45-67  +34 677 234 567
    # Anchored: must NOT be preceded or followed by a digit (avoids IBAN/CC fragments)
    #
    # Fixed 2026-07-30 — real bug found via domain battery testing: the
    # previous `(?:[\s-]?\d{2,3}){2,3}` allowed a variable 7-12 digit total,
    # so an 8-digit fragment (the numeric part of a SIP health-card code,
    # "SIP: CD98765432" -> "98765432") satisfied the shape and got
    # misclassified as a phone number. Because overlapping spans are
    # resolved by pattern-list order (first match wins), that false "phone"
    # detection then BLOCKED the correct health_record detection at the
    # same position — a real card number leaked untokenised. Now the total
    # digit count after the prefix is fixed at exactly 6 (via explicit
    # 3+3 / 2+2+2 alternation) instead of a loose range.
    ("phone", "high",
     re.compile(
         r'(?<!\d)(?:\+34[\s-]?)?(?:6\d{2}|7[1-9]\d|9\d{2})'
         r'(?:(?:[\s-]?\d{3}){2}|(?:[\s-]?\d{2}){3})'
         r'(?!\d)'
     ),
     0.90),

    # International phone (loose): +XX format, not Spain
    ("phone", "medium",
     re.compile(r'\+(?!34)\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b'),
     0.75),

    # SIP / Health card ES (group 1 = number only)
    ("health_record", "critical",
     re.compile(r'\b(?:SIP|TSI|CIP)[\s:]*([A-Z0-9]{8,16})\b', re.IGNORECASE),
     0.85),

    # Medical record / case number (generic) — added 2026-07-30 following
    # the real leak found in a genetic test report: "Nº de historia:
    # 00183370" was previously undetected entirely (only SIP/TSI/CIP
    # regional health-card codes were covered), and its digits were even
    # being misclassified as a phone number by the loose international
    # phone pattern below. Covers "historia clínica", "nº historia",
    # "medical record", "record number", "expediente médico" followed by
    # a numeric/alphanumeric identifier. Keyword-anchored (not standalone)
    # since a bare number with no context is indistinguishable from any
    # other business ID.
    ("health_record", "critical",
     re.compile(
         r'(?i:n[úu]mero\s+de\s+historia|historia\s+cl[íi]nica|n[º°o]\.?\s*de\s+historia'
         r'|expediente\s+m[ée]dico|medical\s+record(?:\s+number)?|record\s+number|mrn)'
         r'(?:\s+n[úu]mero|\s+n[º°o]\.?)?'
         r'[\s:#]*([A-Z0-9][A-Z0-9\-]{4,15})\b'
     ),
     0.85),

    # Spanish passport — 3 letters + 6 digits, always keyword-anchored to
    # avoid false positives against other 9-char alphanumeric business
    # codes (SKUs, batch numbers, etc. share this shape). Added 2026-07-30.
    ("passport", "critical",
     re.compile(r'(?i:pasaporte|passport)[\s:#]*([A-Za-z]{3}\d{6})\b'),
     0.90),

    # Spanish Social Security affiliation number (NUSS) — 12 digits,
    # keyword-anchored. Added 2026-07-30: previously undetected entirely.
    ("ssn", "critical",
     re.compile(
         r'(?i:n[úu]mero\s+de\s+afiliaci[óo]n|n[úu]mero\s+de\s+la\s+seguridad\s+social'
         r'|seguridad\s+social|n\.?a\.?f\.?|nuss)'
         r'[\s:#]*(\d{2}[\s-]?\d{7,8}[\s-]?\d{2})\b'
     ),
     0.90),

    # IPv4
    ("ip_address", "medium",
     re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
     0.99),

    # Date of birth patterns — group 1 = date only, excludes keyword
    ("date_of_birth", "medium",
     re.compile(r'\b(?:nacido?|born|dob|f\.?nac\.?)[\s:]+(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b', re.IGNORECASE),
     0.85),

    # Full name heuristic — keyword-triggered, group 1 = name only
    #
    # v2 (2026-07-30) — rewritten after a real production leak: a genetic
    # test report with "Paciente: PURIFICACION GARCIA DIAZ" (ALL-CAPS,
    # tabular label:value layout typical of lab/clinical reports) passed
    # through completely untokenised. Root causes found and fixed here:
    #
    #   1. Word shape only accepted Title Case ([A-Z][a-z]+) — ALL-CAPS
    #      names never matched at all. Now each word may be Title Case
    #      OR fully uppercase.
    #   2. Keyword list was missing "médico", "doctor", "dr./dra.",
    #      "titular", "firmado por", "derivad[oa] por", "remitente",
    #      "destinatario" — common in clinical/legal documents.
    #   3. Every word in the name had to start with a capital letter, so
    #      lowercase particles ("de", "la", "del", "van", "von", "di")
    #      silently truncated names like "María de la Cruz Gómez" at
    #      "María". Now an optional lowercase-particle segment is allowed
    #      between capitalised words.
    #   4. Minimum 2 words were required — single-word names/aliases
    #      ("Cliente: Madonna") never matched. Now 1 word is enough
    #      (still capped at 4 total to limit over-capture).
    #
    # Known remaining limitation (documented, not fixed here — needs NLP):
    # if the word immediately after a real name is ALSO capitalised and
    # looks name-shaped (a company name, "Empresa", "SL", another proper
    # noun), it can still be swallowed into the match — a short blocklist
    # of common non-name trailing words is included to cut the most
    # frequent cases, but this is a heuristic, not a full fix.
    ("full_name", "low",
     re.compile(
         r'(?i:paciente|solicitante|nombre|cliente|empleado|trabajador|cotitular'
         r'|sr\.?|sra\.?|don|doña|dña\.?|dr\.?|dra\.?|d\.?/d.?a\.?|médico|medico|doctor|doctora'
         r'|mr\.?|ms\.?|mrs\.?'
         r'|titular|remitente|destinatario|derivad[oa]\s+por|firmad[oa]\s+por'
         r'|asegurad[oa]|tomador|beneficiari[oa]|responsable'
         r'|compareciente|a\s+favor\s+de'
         r'|atendid[oa]\s+por|gestionad[oa]\s+por|tramitad[oa]\s+por|recibid[oa]\s+por)[\s:]+'
         r'('
         r'(?:[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+|[A-ZÁÉÍÓÚÑ]{2,})'
         # Continuation words stay on the SAME line ([ \t-]+, never \n) —
         # fixed 2026-07-30: the previous [\s-]+ included newlines, so a
         # tabular field like "Paciente: JUAN PEREZ\nMédico: Ana..." greedily
         # swallowed the next line's label ("...PEREZ\nMédico") whenever that
         # label also happened to be capitalised. Multi-word names are
         # space-separated on one line in practice; a name never legitimately
         # continues onto the next line in this label:value document style.
         r'(?:[ \t-]+(?:de\s+la\s+|de\s+los\s+|de\s+las\s+|de\s+|del\s+|la\s+|van\s+|von\s+|di\s+|do\s+|dos\s+)?'
         r'(?:[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+|[A-ZÁÉÍÓÚÑ]{2,})){0,3}'
         r')'
         r'(?!\s+(?:Empresa|Sociedad|Compañ[íi]a|Corp|Inc|Ltd|LLC|S\.?A\.?U?\.?|S\.?L\.?U?\.?|SL|SA)\b)'
     ),
     0.80),

    # ── Bare ALL-CAPS name safety net — added 2026-08-07 ──────────────────
    # Real finding from a genetic report PDF: the extracted text had the
    # patient's name (PURIFICACION GARCIA DIAZ) with NO keyword adjacent
    # to it at all — the PDF's tabular layout got scrambled during text
    # extraction, so "Paciente:" and the actual name ended up separated
    # by unrelated reordered content in the raw character stream. Every
    # full_name pattern above requires an adjacent keyword, so none of
    # them can ever catch this — it's a structural gap, not a regex bug.
    # Presidio (Tier 2 NLP) is supposed to be the safety net for
    # keyword-less names, but standard NER models rely heavily on
    # capitalisation patterns (Title Case) to recognise names; ALL-CAPS
    # text loses that signal and measurably hurts NER recall — so Tier 2
    # can miss exactly this case too.
    #
    # This pattern catches ANY standalone run of 2-4 consecutive
    # ALL-CAPS words (3+ letters each, pure alphabetic — gene names like
    # PMS2 or acronyms with digits don't qualify), regardless of context.
    #
    # KNOWN TRADE-OFF, accepted deliberately: this also flags non-name
    # ALL-CAPS phrases as false positives — clinic names ("CLINICA
    # VISTAHERMOSA"), sample types ("SANGRE PERIFERICA"), document
    # titles ("INFORME GENETICO"). This is intentional: over-tokenising
    # a clinic name is a far more acceptable failure than leaking a real
    # patient's name.
    #
    # Confidence set to 0.75, not lower: /v1/agent/protect has its own
    # confidence gate (_is_valid_name(), agent.py) that silently drops
    # any full_name detection below 0.75 — found while implementing this,
    # a real example of the endpoint-drift this codebase already has
    # (see the duplicated PREFIX_MAP history). Keeping this pattern above
    # that threshold means it actually takes effect on all three
    # endpoints (/v1/proxy/protect, /v1/relay/complete, /v1/agent/protect)
    # instead of silently working on two of them and not the third.
    ("full_name", "low",
     re.compile(
         r'\b(?:[A-ZÁÉÍÓÚÑ]{3,}(?:-[A-ZÁÉÍÓÚÑ]{3,})?[ \t]+){1,3}[A-ZÁÉÍÓÚÑ]{3,}(?:-[A-ZÁÉÍÓÚÑ]{3,})?\b'
     ),
     0.75),

    # Money / business amounts — added 2026-07-24 following the Octupus/Robin
    # AI (Odoo copilot) analysis: ERP data is full of commercially sensitive
    # figures (revenue, margins, contract values) that customers want kept
    # from LLM providers for confidentiality reasons, independent of GDPR
    # personal-data status. Covers symbol-before (€45.200,50) and
    # symbol/code-after (45.200 € / 45,200.50 EUR) formats, ES and
    # international thousand/decimal separator conventions.
    ("money", "medium",
     re.compile(
         r'(?:[€$£]\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{1,2})?'
         r'|\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{1,2})?\s?[€$£]'
         r'|\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{1,2})?\s?(?:EUR|USD|GBP)\b)',
         re.IGNORECASE
     ),
     0.85),
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
    "passport": "personal",
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
    "passport": "PP",
    "money": "MN",
}


def _make_token(entity_type: str, counter: int) -> str:
    prefix = TOKEN_PREFIX.get(entity_type, "XX")
    return f"[{prefix}-{counter:04d}]"


def detect(text: str, use_nlp: bool = True, custom_rules: Optional[List[Dict]] = None) -> List[Detection]:
    """
    Hybrid detection: Tier 1 (regex) + Tier 1.5 (custom org/pipeline patterns)
    + Tier 2 (Presidio NLP).

    Tier 1 runs first — high confidence, deterministic.
    Tier 1.5 fills gaps specific to a customer's own domain vocabulary
    (e.g. a clinic's own list of diagnosis terms, a law firm's case-number
    format) via policy_rules.custom_pattern — added 2026-07-24 following
    the Octupus/Robin AI (Odoo copilot) analysis. This column existed in
    the schema but was never wired into detection until now.
    Tier 2 fills further gaps — catches names, implicit PII, free text.
    Later tiers never override earlier ones (no duplicate spans).
    """
    detections: List[Detection] = []
    seen_spans: List[Tuple[int, int]] = []

    # A full_name capture that consists ONLY of a title abbreviation itself
    # (no actual name attached) is a harmless-but-noisy false positive: e.g.
    # "Médico: Dr./Dra. Ana..." — the "médico" keyword's [\s:]+ lands right
    # on "Dr", which superficially satisfies the name-word shape, before the
    # separate "Dra." trigger correctly catches the real name right after.
    # The real name is never left unprotected either way; this just skips
    # tokenising the meaningless "Dr" fragment on its own. Found 2026-07-30
    # while validating the full_name rewrite.
    _TITLE_ONLY_RE = re.compile(r'^(?:dr|dra|sr|sra|don|doña|dña|mr|ms|mrs|d)\.?$', re.IGNORECASE)

    # ── Tier 1: Regex ────────────────────────────────────────────────────────
    for entity_type, severity, pattern, confidence in PATTERNS:
        for match in pattern.finditer(text):
            # If pattern has capturing group(s), use the first non-None group
            # span — this excludes keyword prefixes like "DNI:", "nacido:", etc.
            # from the detection span so only the PII value itself is tokenised.
            grp = next(
                (i for i in range(1, pattern.groups + 1) if match.group(i) is not None),
                None
            )
            start = match.start(grp) if grp else match.start()
            end   = match.end(grp)   if grp else match.end()

            # Fixed 2026-08-07 — real bug found via a garbled tokenization
            # report: the old check (s <= start < e or s < end <= e) only
            # catches PARTIAL overlaps where one span's boundary falls
            # inside the other. It misses full containment — a span that
            # starts before AND ends after an existing one satisfies
            # neither clause, since neither of ITS boundaries falls inside
            # the existing span. Real example that slipped through: an
            # existing regex span (13720,13734) and a new candidate
            # (13716,13738) that fully contains it — old check: false on
            # both clauses, so the containing span was kept too. Two
            # overlapping detections both got tokenised, and
            # _apply_tokenization's back-to-front replacement corrupted
            # the text between them (stale offsets after the inner
            # replacement shifted the string length). The correct general
            # interval-overlap test is start1 < end2 AND start2 < end1 —
            # used here and in the two other places this exact same
            # pattern was duplicated (see nlp_engine.py's detect_nlp()).
            if any(start < e and s < end for s, e in seen_spans):
                continue

            if entity_type == "full_name" and _TITLE_ONLY_RE.match(text[start:end]):
                continue

            seen_spans.append((start, end))
            detections.append(Detection(
                type=entity_type,
                severity=severity,
                action="detected",
                token=None,
                start=start,
                end=end,
                confidence=confidence,
                detector="regex",
            ))

    # ── Tier 1.5: Custom org/pipeline patterns (policy_rules.custom_pattern) ──
    if custom_rules:
        for rule in custom_rules:
            raw_pattern = rule.get("custom_pattern")
            if not raw_pattern:
                continue
            entity_type = rule.get("entity_type")
            if not entity_type:
                continue
            try:
                compiled = re.compile(raw_pattern, re.IGNORECASE)
            except re.error as e:
                logging.getLogger(__name__).warning(
                    f"[CustomPattern] Invalid regex for entity_type={entity_type}: {e}"
                )
                continue
            severity = rule.get("severity_override") or "medium"
            for match in compiled.finditer(text):
                grp = next(
                    (i for i in range(1, compiled.groups + 1) if match.group(i) is not None),
                    None
                ) if compiled.groups else None
                start = match.start(grp) if grp else match.start()
                end   = match.end(grp)   if grp else match.end()
                if start == end:
                    continue  # skip zero-width matches
                # Same interval-overlap fix as the Tier 1 loop above —
                # see the detailed comment there.
                if any(start < e and s < end for s, e in seen_spans):
                    continue
                seen_spans.append((start, end))
                detections.append(Detection(
                    type=entity_type,
                    severity=severity,
                    action="detected",
                    token=None,
                    start=start,
                    end=end,
                    confidence=0.9,
                    detector="custom_pattern",
                ))

    # ── Tier 2: Presidio NLP ─────────────────────────────────────────────────
    if use_nlp:
        try:
            from app.services.nlp_engine import detect_nlp
            nlp_detections = detect_nlp(text, existing_spans=seen_spans)
            for d in nlp_detections:
                if d.start is not None and d.end is not None:
                    seen_spans.append((d.start, d.end))
            detections.extend(nlp_detections)
        except Exception as e:
            # NLP failure never breaks the request — Tier 1 results stand
            logging.getLogger(__name__).warning(f"[NLP] Tier 2 skipped: {e}")

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
