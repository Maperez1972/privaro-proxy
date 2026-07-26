"""
Pydantic models — request/response validation for all proxy endpoints.
"""
import uuid as _uuid
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
from enum import Enum


def _validate_conversation_id(v: Optional[str]) -> Optional[str]:
    """
    Fixed 2026-07-24 — found via live testing: conversation_id is stored
    in a Postgres `uuid` column, but the request models accepted any
    plain string with no validation. Passing something like
    "test-conversation-001" made the tokens_vault INSERT fail silently
    (it runs as a background task -- the caller gets a normal-looking
    200 response, then /detokenize later reports 0 tokens reversed with
    no indication why). Now rejected immediately with a clear 422 at
    request time instead of a confusing silent failure minutes later.
    """
    if v is None:
        return v
    try:
        _uuid.UUID(v)
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f"conversation_id must be a valid UUID, got: {v!r}")
    return v


class DetectionMode(str, Enum):
    tokenise = "tokenise"
    anonymise = "anonymise"
    block = "block"


class ProxyOptions(BaseModel):
    mode: DetectionMode = DetectionMode.tokenise
    include_detections: bool = True
    reversible: bool = True
    agent_mode: bool = False          # Phase 7b: triggers stricter policies


class ProtectRequest(BaseModel):
    pipeline_id: str
    prompt: str = Field(..., min_length=1, max_length=50000)
    options: ProxyOptions = ProxyOptions()
    conversation_id: Optional[str] = None  # Token scoping: reuse tokens within same conversation

    _validate_conv_id = field_validator("conversation_id")(_validate_conversation_id)


class DetectRequest(BaseModel):
    pipeline_id: str
    prompt: str = Field(..., min_length=1, max_length=50000)


class Detection(BaseModel):
    type: str
    severity: str
    action: str
    token: Optional[str] = None
    start: Optional[int] = None
    end: Optional[int] = None
    confidence: float = 1.0
    detector: str = "regex"
    regulation_ref: Optional[str] = None   # set by policy engine when a rule matches


class ProtectResponse(BaseModel):
    request_id: str
    protected_prompt: str
    detections: List[Detection]
    stats: Dict[str, Any]
    audit_log_id: Optional[str] = None
    gdpr_compliant: bool = True
    # Added 2026-07 — graceful degradation. When true, the detector/policy
    # engine failed or timed out and protected_prompt is the ORIGINAL,
    # UNMODIFIED prompt (fail-open, never blocks the caller's traffic).
    # The event is still logged to audit_logs (event_type=degraded_bypass)
    # so the DPO has visibility that unprotected data may have gone out.
    degraded_mode: bool = False
    degraded_reason: Optional[str] = None


class DetectResponse(BaseModel):
    request_id: str
    detections: List[Detection]
    stats: Dict[str, Any]


class DetokenizeRequest(BaseModel):
    """
    Bulk, automated token reversal — for agentic write-back flows (e.g. an
    Odoo copilot that needs real values to actually write a delivery note),
    as opposed to reveal-token's human-facing, password-gated, one-token-
    at-a-time flow. Added 2026-07-24 following the Octupus/Robin AI analysis.
    """
    pipeline_id: str
    text: str = Field(..., min_length=1, max_length=100000)
    # Fixed 2026-07-24 (found via live testing): token_value is NOT unique
    # within an org over time -- it's just a per-request counter that
    # restarts at 0001 every /protect call. Without conversation_id there
    # is no way to disambiguate which of possibly dozens of historical
    # rows sharing the literal token string is the right one. Strongly
    # recommended: pass the same conversation_id used in the /protect (or
    # /protect-structured) call that generated these tokens.
    conversation_id: Optional[str] = None

    _validate_conv_id = field_validator("conversation_id")(_validate_conversation_id)


class DetokenizeResponse(BaseModel):
    request_id: str
    detokenized_text: str
    tokens_reversed: int
    tokens_not_found: List[str] = []


class ProtectStructuredRequest(BaseModel):
    """
    Field-aware protection for structured payloads (e.g. an Odoo record's
    fields), as opposed to /protect's single free-text prompt. Added
    2026-07-24 following the Octupus/Robin AI analysis: ERP query results
    are typed rows with many fields, not prose — a field literally named
    "diagnostico" is strong, precise signal on its own, independent of
    whether its content matches any free-text medical-term pattern.
    """
    pipeline_id: str
    fields: Dict[str, str]
    conversation_id: Optional[str] = None

    _validate_conv_id = field_validator("conversation_id")(_validate_conversation_id)


class ProtectStructuredResponse(BaseModel):
    request_id: str
    protected_fields: Dict[str, str]
    detections_by_field: Dict[str, List[Detection]]
    stats: Dict[str, Any]
    audit_log_id: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    detector: str
    supabase: str
