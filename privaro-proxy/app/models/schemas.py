"""
Pydantic models — request/response validation for all proxy endpoints.
"""
import uuid as _uuid
from pydantic import BaseModel, Field, field_validator, model_validator
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
    optimize_context: bool = False    # opt-in: compress tokenised prompt before returning


class ProtectRequest(BaseModel):
    pipeline_id: str
    prompt: str = Field(..., min_length=1, max_length=50000)
    options: ProxyOptions = ProxyOptions()
    conversation_id: Optional[str] = None  # Token scoping: reuse tokens within same conversation

    _validate_conv_id = field_validator("conversation_id")(_validate_conversation_id)

    # Fixed 2026-07-24 — closing the gap at the root instead of just
    # recommending conversation_id: token_value (e.g. "[NM-0001]") is NOT
    # unique within an org over time -- confirmed with real data (47
    # historical rows sharing one literal token string for one org).
    # When reversible=true (the default), a token WILL be persisted and
    # WILL eventually need disambiguating on reversal -- so
    # conversation_id becomes mandatory in that case. When reversible is
    # explicitly false, nothing is persisted, so there's nothing to
    # disambiguate later and conversation_id stays optional.
    @model_validator(mode="after")
    def _require_conversation_id_if_reversible(self):
        if self.options.reversible and not self.conversation_id:
            raise ValueError(
                "conversation_id is required when options.reversible is true "
                "(the default) -- otherwise a token like [NM-0001] cannot be "
                "reliably reversed later, since it is not unique across "
                "unrelated requests over time. Pass a UUID identifying this "
                "conversation/session, or set options.reversible=false if you "
                "don't need to reverse tokens for this call."
            )
        return self


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
    # Added 2026-07-30 — Context Optimization for /v1/proxy/protect (the
    # endpoint the dashboard Sandbox actually calls, via proxy-bridge).
    # Was previously only wired into /v1/relay/complete (PR #1), leaving
    # the Sandbox's "Context Optimization" toggle a silent no-op: the
    # frontend already sent options.optimize_context and read
    # compressionStats.tokens_saved, but this endpoint never set the field,
    # so CompressionStatsCard just never rendered — no error, no feedback,
    # just nothing. Found during a full integration audit, not a live bug
    # report.
    compression_stats: Dict[str, Any] = {}


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
    # Fixed 2026-07-24 (found via live testing, made mandatory the same
    # day after confirming the "recommended but optional" version still
    # let a real request return the WRONG value): token_value is NOT
    # unique within an org over time -- it's just a per-request counter
    # that restarts at 0001 every /protect call. Confirmed with real
    # data: 47 historical rows shared one literal token string for one
    # org. There is no safe "best effort" here for an endpoint whose
    # entire purpose is precise reversal -- must be the same
    # conversation_id used in the /protect (or /protect-structured) call
    # that generated these tokens.
    conversation_id: str

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
    # Fixed 2026-07-24 (same root-cause fix as DetokenizeRequest): this
    # endpoint has no options.reversible toggle at all -- any "tokenised"
    # detection always gets persisted to tokens_vault. Since token_value
    # is not unique across unrelated requests over time, conversation_id
    # is mandatory here for the same reason it's mandatory for /protect
    # when reversible=true.
    conversation_id: str

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
    nlp_active: bool = True
