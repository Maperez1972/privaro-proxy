"""
Internal Encryption Router — added 2026-07-23.

Fixes a real security bug found while testing streaming: AdminProviders.tsx
(frontend) was saving customer LLM provider API keys as PLAINTEXT into
llm_providers.api_key_encrypted -- a column whose name promises encryption,
and which llm_router.py has always assumed was encrypted (it tries to
AES-256-GCM decrypt + base64-decode it, which is exactly why streaming
failed with "Incorrect padding": you can't base64-decode a raw
"sk-proj-..." string).

The encryption logic (key_manager.encrypt_byok_key_for_storage) already
existed and is correct -- it was simply never exposed anywhere the
frontend could call it before saving. This endpoint exposes it.

Auth: NOT a customer-facing endpoint. Only callable server-to-server, by
a Supabase Edge Function (encrypt-provider-key) using a shared secret --
same pattern as send-usage-notification / INTERNAL_NOTIFY_SECRET. The
browser must never see this endpoint or the raw key must never be sent
anywhere except straight from the admin's browser session to that Edge
Function, which then calls this and stores the result -- it never touches
localStorage or gets echoed back.
"""
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from typing import Optional
import os

from app.config import settings
from app.services.key_manager import encrypt_byok_key_for_storage

router = APIRouter(prefix="/internal", tags=["Internal"])


class EncryptKeyRequest(BaseModel):
    raw_key: str


class EncryptKeyResponse(BaseModel):
    encrypted: str


@router.get("/diag-secret")
async def diag_secret():
    """
    TEMPORARY diagnostic (2026-07-23) — chasing a server_misconfigured
    error where the user confirms INTERNAL_NOTIFY_SECRET is set in Railway
    with the right name/value, but settings.INTERNAL_NOTIFY_SECRET still
    reads as falsy. Compares os.environ directly against what pydantic-
    settings loaded, without ever revealing the actual value. Remove once
    resolved.
    """
    raw_env = os.environ.get("INTERNAL_NOTIFY_SECRET")
    return {
        "os_environ_present": raw_env is not None,
        "os_environ_length": len(raw_env) if raw_env else 0,
        "os_environ_has_leading_or_trailing_whitespace": (raw_env != raw_env.strip()) if raw_env else None,
        "pydantic_settings_present": settings.INTERNAL_NOTIFY_SECRET is not None,
        "pydantic_settings_length": len(settings.INTERNAL_NOTIFY_SECRET) if settings.INTERNAL_NOTIFY_SECRET else 0,
        "pydantic_settings_truthy": bool(settings.INTERNAL_NOTIFY_SECRET),
        "values_match": raw_env == settings.INTERNAL_NOTIFY_SECRET,
        "environment": settings.ENVIRONMENT,
    }


@router.post("/encrypt-provider-key", response_model=EncryptKeyResponse)
async def encrypt_provider_key(
    body: EncryptKeyRequest,
    x_internal_secret: Optional[str] = Header(None),
):
    if not settings.INTERNAL_NOTIFY_SECRET:
        raise HTTPException(status_code=500, detail={"error": "server_misconfigured"})
    if x_internal_secret != settings.INTERNAL_NOTIFY_SECRET:
        raise HTTPException(status_code=401, detail={"error": "unauthorized"})
    if not body.raw_key or len(body.raw_key) < 8:
        raise HTTPException(status_code=400, detail={"error": "invalid_key"})

    encrypted = encrypt_byok_key_for_storage(body.raw_key)
    return EncryptKeyResponse(encrypted=encrypted)
