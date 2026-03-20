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


class ProtectResponse(BaseModel):
    request_id: str
    protected_prompt: str
    detections: List[Detection]
    stats: Dict[str, Any]
    audit_log_id: Optional[str] = None
    gdpr_compliant: bool = True


class DetectResponse(BaseModel):
    request_id: str
    detections: List[Detection]
    stats: Dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    detector: str
    supabase: str
