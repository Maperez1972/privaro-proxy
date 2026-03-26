"""
BYOK Admin Router — Phase 13
POST /v1/admin/keys          — Register a new encryption key (BYOK or KMS)
GET  /v1/admin/keys          — List org encryption keys
DELETE /v1/admin/keys/{id}   — Deactivate a key (never deleted — tokens still need it)
POST /v1/admin/keys/{id}/rotate — Rotate to a new key

Authentication: admin role required (X-Privaro-Key with admin permissions)
"""
import uuid
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.services.auth import verify_api_key_or_dev
from app.services.key_manager import (
    encrypt_byok_key_for_storage,
    generate_key_id,
    resolve_encryption_key,
)
from app.config import settings
import app.services.supabase as db
import httpx

router = APIRouter(prefix="/v1/admin", tags=["byok"])

SUPABASE_REST = f"{settings.SUPABASE_URL}/rest/v1"
SUPABASE_HEADERS = {
    "apikey": settings.SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}


# ── Request models ─────────────────────────────────────────────────────────────

class RegisterKeyRequest(BaseModel):
    key_type: str = Field(..., description="managed | byok | kms_aws | kms_azure | kms_gcp")
    display_name: str = Field(..., min_length=1, max_length=100)
    # For byok: the customer's 32-byte key in hex (64 chars)
    key_material: Optional[str] = Field(None, description="64-char hex string for byok type")
    # For kms_*: ARN or Vault URL
    key_reference: Optional[str] = Field(None, description="ARN/URL for KMS types")
    set_as_default: bool = Field(False, description="Set as default key for new tokens")


class KeyResponse(BaseModel):
    id: str
    key_type: str
    display_name: str
    is_active: bool
    is_default: bool
    tokens_encrypted: int
    created_at: str
    last_used_at: Optional[str] = None


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/keys", response_model=List[KeyResponse])
async def list_keys(
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """List all encryption keys for the org. Admin/DPO only."""
    org_id = key_record["org_id"]
    _require_admin_or_dpo(key_record)

    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(
            f"{SUPABASE_REST}/encryption_keys",
            headers=SUPABASE_HEADERS,
            params={
                "org_id": f"eq.{org_id}",
                "order": "created_at.desc",
                "select": "id,key_type,display_name,is_active,is_default,tokens_encrypted,created_at,last_used_at",
            },
        )
        if r.status_code != 200:
            raise HTTPException(status_code=500, detail={"error": "failed_to_fetch_keys"})
        return r.json()


@router.post("/keys", response_model=KeyResponse)
async def register_key(
    body: RegisterKeyRequest,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Register a new encryption key for the org.
    Admin role required.

    For byok: provide key_material (64-char hex). It will be encrypted with
    iCommunity KEK before storage — never stored in plaintext.

    For kms_aws: provide key_reference (AWS KMS ARN). The actual key never
    leaves your AWS account.
    """
    org_id = key_record["org_id"]
    _require_admin(key_record)

    if body.key_type not in ("managed", "byok", "kms_aws", "kms_azure", "kms_gcp"):
        raise HTTPException(status_code=400, detail={"error": "invalid_key_type"})

    # Validate byok key material
    if body.key_type == "byok":
        if not body.key_material or len(body.key_material) != 64:
            raise HTTPException(
                status_code=400,
                detail={"error": "byok_requires_64_char_hex_key",
                        "hint": "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""}
            )
        try:
            bytes.fromhex(body.key_material)
        except ValueError:
            raise HTTPException(status_code=400, detail={"error": "key_material_must_be_hex"})

    # Validate KMS reference
    if body.key_type.startswith("kms_") and not body.key_reference:
        raise HTTPException(status_code=400, detail={"error": "kms_requires_key_reference"})

    # Build key record
    key_id = generate_key_id(org_id, body.key_type)
    key_reference = None

    if body.key_type == "byok":
        # Encrypt customer key with iCommunity KEK before storage
        key_reference = encrypt_byok_key_for_storage(body.key_material)
    elif body.key_type.startswith("kms_"):
        key_reference = body.key_reference  # ARN or URL only

    # If set_as_default, unset current default first
    if body.set_as_default:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.patch(
                f"{SUPABASE_REST}/encryption_keys",
                headers=SUPABASE_HEADERS,
                params={"org_id": f"eq.{org_id}", "is_default": "eq.true"},
                json={"is_default": False},
            )

    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(
            f"{SUPABASE_REST}/encryption_keys",
            headers=SUPABASE_HEADERS,
            json={
                "id": key_id,
                "org_id": org_id,
                "key_type": body.key_type,
                "display_name": body.display_name,
                "key_reference": key_reference,
                "is_active": True,
                "is_default": body.set_as_default,
            },
        )
        if r.status_code not in (200, 201):
            raise HTTPException(status_code=500, detail={"error": "failed_to_register_key"})

        created = r.json()[0] if r.json() else {}

    # Test key resolution to validate it works before returning
    try:
        await resolve_encryption_key(key_id, org_id)
    except Exception as e:
        # Roll back — delete the key we just created
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.delete(
                f"{SUPABASE_REST}/encryption_keys",
                headers=SUPABASE_HEADERS,
                params={"id": f"eq.{key_id}"},
            )
        raise HTTPException(
            status_code=422,
            detail={"error": "key_validation_failed", "detail": str(e)}
        )

    return created


@router.delete("/keys/{key_id}")
async def deactivate_key(
    key_id: str,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Deactivate a key. Does NOT delete it — tokens encrypted with this key
    can still be decrypted. Cannot deactivate the default key.
    """
    org_id = key_record["org_id"]
    _require_admin(key_record)

    if key_id == "key-v1":
        raise HTTPException(
            status_code=400,
            detail={"error": "cannot_deactivate_system_key",
                    "hint": "key-v1 is the system default and cannot be deactivated"}
        )

    async with httpx.AsyncClient(timeout=5.0) as client:
        # Verify key belongs to org and is not default
        r = await client.get(
            f"{SUPABASE_REST}/encryption_keys",
            headers=SUPABASE_HEADERS,
            params={"id": f"eq.{key_id}", "org_id": f"eq.{org_id}", "limit": "1"},
        )
        if not r.json():
            raise HTTPException(status_code=404, detail={"error": "key_not_found"})

        key = r.json()[0]
        if key.get("is_default"):
            raise HTTPException(
                status_code=400,
                detail={"error": "cannot_deactivate_default_key",
                        "hint": "Set another key as default first"}
            )

        await client.patch(
            f"{SUPABASE_REST}/encryption_keys",
            headers=SUPABASE_HEADERS,
            params={"id": f"eq.{key_id}", "org_id": f"eq.{org_id}"},
            json={"is_active": False},
        )

    return {"status": "deactivated", "key_id": key_id,
            "note": "Existing tokens encrypted with this key remain decryptable"}


@router.post("/keys/{key_id}/set-default")
async def set_default_key(
    key_id: str,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """Set a key as the default for new token encryptions."""
    org_id = key_record["org_id"]
    _require_admin(key_record)

    async with httpx.AsyncClient(timeout=5.0) as client:
        # Verify key exists, belongs to org, and is active
        r = await client.get(
            f"{SUPABASE_REST}/encryption_keys",
            headers=SUPABASE_HEADERS,
            params={"id": f"eq.{key_id}", "org_id": f"eq.{org_id}", "is_active": "eq.true", "limit": "1"},
        )
        if not r.json():
            raise HTTPException(status_code=404, detail={"error": "key_not_found_or_inactive"})

        # Unset current default
        await client.patch(
            f"{SUPABASE_REST}/encryption_keys",
            headers=SUPABASE_HEADERS,
            params={"org_id": f"eq.{org_id}", "is_default": "eq.true"},
            json={"is_default": False},
        )

        # Set new default
        await client.patch(
            f"{SUPABASE_REST}/encryption_keys",
            headers=SUPABASE_HEADERS,
            params={"id": f"eq.{key_id}", "org_id": f"eq.{org_id}"},
            json={"is_default": True},
        )

    return {"status": "updated", "default_key_id": key_id}


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _require_admin(key_record: Dict[str, Any]) -> None:
    perms = key_record.get("permissions", [])
    if "admin" not in perms and settings.ENVIRONMENT == "production":
        raise HTTPException(status_code=403, detail={"error": "admin_role_required"})


def _require_admin_or_dpo(key_record: Dict[str, Any]) -> None:
    perms = key_record.get("permissions", [])
    if "admin" not in perms and "dpo" not in perms and settings.ENVIRONMENT == "production":
        raise HTTPException(status_code=403, detail={"error": "admin_or_dpo_role_required"})
