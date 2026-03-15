"""
Authentication — API Key validation for proxy endpoints.
Enterprise apps authenticate with X-Privaro-Key header.
Format: prvr_xxxxxxxxxxxx (key_prefix visible, full key hashed in DB).
"""
import hashlib
import httpx
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader
from typing import Optional, Dict, Any
from app.config import settings

api_key_header = APIKeyHeader(name="X-Privaro-Key", auto_error=False)

SUPABASE_REST = f"{settings.SUPABASE_URL}/rest/v1"
SUPABASE_HEADERS = {
    "apikey": settings.SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
}


def _hash_key(key: str) -> str:
    """SHA-256 hash of the API key — matches what's stored in api_keys.key_hash."""
    return hashlib.sha256(key.encode()).hexdigest()


async def verify_api_key(
    api_key: Optional[str] = Security(api_key_header),
) -> Dict[str, Any]:
    """
    Validate X-Privaro-Key against the api_keys table.
    Returns the key record (with org_id, pipeline_ids, permissions) on success.
    Raises 401 on missing or invalid key.
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail={"error": "missing_api_key", "message": "X-Privaro-Key header required"},
        )

    if not api_key.startswith("prvr_"):
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_api_key_format", "message": "Key must start with prvr_"},
        )

    key_hash = _hash_key(api_key)
    key_prefix = api_key[:12]  # prvr_ + first 7 chars

    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(
            f"{SUPABASE_REST}/api_keys",
            headers=SUPABASE_HEADERS,
            params={
                "key_hash": f"eq.{key_hash}",
                "is_active": "eq.true",
                "select": "id,org_id,name,pipeline_ids,permissions,expires_at",
                "limit": "1",
            },
        )

    if response.status_code != 200 or not response.json():
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_api_key", "message": "API key not found or revoked"},
        )

    key_record = response.json()[0]

    # Check expiry
    if key_record.get("expires_at"):
        from datetime import datetime, timezone
        expires = datetime.fromisoformat(key_record["expires_at"].replace("Z", "+00:00"))
        if expires < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=401,
                detail={"error": "api_key_expired", "message": "API key has expired"},
            )

    # Update last_used_at (fire-and-forget, don't await)
    import asyncio
    asyncio.create_task(_update_last_used(key_record["id"]))

    return key_record


async def _update_last_used(key_id: str) -> None:
    """Update last_used_at timestamp for the API key (background task)."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.patch(
                f"{SUPABASE_REST}/api_keys",
                headers={**SUPABASE_HEADERS, "Content-Type": "application/json"},
                params={"id": f"eq.{key_id}"},
                json={"last_used_at": "now()"},
            )
    except Exception:
        pass  # Non-critical, don't fail the request


# ── Dev mode bypass ──────────────────────────────────────────────────────────
# In development, if no api_keys exist yet, allow a master dev key from env
async def verify_api_key_or_dev(
    api_key: Optional[str] = Security(api_key_header),
) -> Dict[str, Any]:
    """
    Development-friendly auth: falls back to PRIVARO_DEV_KEY env var.
    NEVER use in production.
    """
    if settings.ENVIRONMENT == "production":
        return await verify_api_key(api_key)

    dev_key = getattr(settings, "PRIVARO_DEV_KEY", None)
    if dev_key and api_key == dev_key:
        return {
            "id": "dev",
            "org_id": getattr(settings, "DEV_ORG_ID", "dev-org"),
            "name": "Development Key",
            "pipeline_ids": None,
            "permissions": ["proxy:write", "proxy:read", "admin"],
        }

    return await verify_api_key(api_key)
