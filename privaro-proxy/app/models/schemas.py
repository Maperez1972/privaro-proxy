"""
Pydantic models — request/response validation for all proxy endpoints.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


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
