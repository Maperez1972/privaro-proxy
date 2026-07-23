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

from app.config import settings
from app.services.key_manager import encrypt_byok_key_for_storage

router = APIRouter(prefix="/internal", tags=["Internal"])


class EncryptKeyRequest(BaseModel):
    raw_key: str


class EncryptKeyResponse(BaseModel):
    encrypted: str


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
