"""
Key Manager — BYOK Architecture Phase 13
Resolves encryption keys for token vault operations.

Key types:
  managed  → Railway ENCRYPTION_KEY env var (current default, unchanged)
  byok     → Customer-provided key, stored encrypted with iCommunity KEK
  kms_aws  → AWS KMS ARN — key never leaves customer AWS account (Phase 13b)
  kms_azure→ Azure Key Vault URL (Phase 13c)
  kms_gcp  → Google Cloud KMS resource ID (Phase 13d)

Design principles:
  - Backward compatible: all existing tokens use 'key-v1' → managed type
  - Zero key storage for KMS types: only ARN/URL stored, never key material
  - Per-org isolation: each org can have its own key
  - Key rotation: old key retained for decryption, new key for new tokens
"""
import os
import base64
import logging
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)

# ── Managed key cache ─────────────────────────────────────────────────────────
# Avoids re-reading env var on every request
_managed_key_cache: Optional[bytes] = None


def _get_managed_key() -> bytes:
    """Returns the iCommunity managed key from Railway env var."""
    global _managed_key_cache
    if _managed_key_cache is None:
        key_hex = settings.ENCRYPTION_KEY
        if not key_hex or len(key_hex) != 64:
            raise ValueError(
                "ENCRYPTION_KEY must be a 64-char hex string (32 bytes). "
                "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        _managed_key_cache = bytes.fromhex(key_hex)
    return _managed_key_cache


# ── Key resolution ─────────────────────────────────────────────────────────────

async def resolve_encryption_key(key_id: str, org_id: str) -> bytes:
    """
    Resolve a key_id to actual key bytes.

    For 'managed' type: returns Railway ENCRYPTION_KEY.
    For 'byok' type: decrypts customer key from Supabase using KEK.
    For 'kms_*' types: calls customer KMS API (not yet implemented).

    This is the ONLY function that should produce raw key bytes.
    All other code works with key_id strings.
    """
    # ── managed (key-v1 and future managed keys) ──────────────────────────────
    if key_id.startswith("key-") or key_id == "key-v1":
        return _get_managed_key()

    # ── BYOK soft ─────────────────────────────────────────────────────────────
    if key_id.startswith("byok-"):
        return await _resolve_byok_key(key_id, org_id)

    # ── AWS KMS ───────────────────────────────────────────────────────────────
    if key_id.startswith("kms-aws-"):
        return await _resolve_kms_aws(key_id, org_id)

    # ── Azure Key Vault ───────────────────────────────────────────────────────
    if key_id.startswith("kms-azure-"):
        raise NotImplementedError(
            "Azure Key Vault integration not yet implemented. "
            "Contact support@icommunity.io for enterprise HSM onboarding."
        )

    # ── GCP Cloud KMS ─────────────────────────────────────────────────────────
    if key_id.startswith("kms-gcp-"):
        raise NotImplementedError(
            "Google Cloud KMS integration not yet implemented. "
            "Contact support@icommunity.io for enterprise HSM onboarding."
        )

    # ── Unknown key type — fallback to managed ────────────────────────────────
    logger.warning(f"[KeyManager] Unknown key_id '{key_id}' — falling back to managed key")
    return _get_managed_key()


async def get_org_default_key_id(org_id: str) -> str:
    """
    Returns the default encryption key_id for an org.
    Calls Supabase RPC get_org_encryption_key().
    Falls back to 'key-v1' if org has no key registered.
    """
    try:
        import httpx
        from app.config import settings

        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.post(
                f"{settings.SUPABASE_URL}/rest/v1/rpc/get_org_encryption_key",
                headers={
                    "apikey": settings.SUPABASE_SERVICE_KEY,
                    "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                    "Content-Type": "application/json",
                },
                json={"p_org_id": org_id},
            )
            if r.status_code == 200:
                return r.json() or "key-v1"
    except Exception as e:
        logger.warning(f"[KeyManager] Could not fetch org key — using default: {e}")
    return "key-v1"


# ── BYOK soft implementation ──────────────────────────────────────────────────

async def _resolve_byok_key(key_id: str, org_id: str) -> bytes:
    """
    Resolve a BYOK soft key.
    The customer's key is stored in encryption_keys.key_reference,
    encrypted with the iCommunity KEK (same managed key).
    """
    try:
        import httpx
        from app.config import settings

        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                f"{settings.SUPABASE_URL}/rest/v1/encryption_keys",
                headers={
                    "apikey": settings.SUPABASE_SERVICE_KEY,
                    "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                },
                params={
                    "id": f"eq.{key_id}",
                    "org_id": f"eq.{org_id}",
                    "is_active": "eq.true",
                    "select": "key_reference",
                    "limit": "1",
                },
            )
            if r.status_code == 200 and r.json():
                encrypted_key_ref = r.json()[0].get("key_reference")
                if encrypted_key_ref:
                    # Decrypt customer key using managed KEK
                    kek = _get_managed_key()
                    customer_key = _decrypt_aes_gcm(encrypted_key_ref, kek)
                    return bytes.fromhex(customer_key)
    except Exception as e:
        logger.error(f"[KeyManager] BYOK key resolution failed for {key_id}: {e}")

    raise ValueError(f"Could not resolve BYOK key '{key_id}' for org '{org_id}'")


async def _resolve_kms_aws(key_id: str, org_id: str) -> bytes:
    """
    AWS KMS integration — Phase 13b.
    Uses boto3 to call GenerateDataKey on the customer's KMS key ARN.
    The data key is used for this operation only — never persisted.
    """
    try:
        import boto3  # type: ignore
        from app.config import settings

        # Fetch KMS key ARN from encryption_keys table
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                f"{settings.SUPABASE_URL}/rest/v1/encryption_keys",
                headers={
                    "apikey": settings.SUPABASE_SERVICE_KEY,
                    "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                },
                params={
                    "id": f"eq.{key_id}",
                    "org_id": f"eq.{org_id}",
                    "is_active": "eq.true",
                    "select": "key_reference",
                    "limit": "1",
                },
            )
            if not r.json():
                raise ValueError(f"KMS key '{key_id}' not found")

            key_arn = r.json()[0]["key_reference"]

        # Call AWS KMS GenerateDataKey
        kms_client = boto3.client("kms")
        response = kms_client.generate_data_key(
            KeyId=key_arn,
            KeySpec="AES_256",
        )
        # PlaintextKey is the 32-byte AES key — use for this operation only
        plaintext_key = response["Plaintext"]
        logger.info(f"[KeyManager] AWS KMS data key generated for {key_id[:20]}...")
        return plaintext_key

    except ImportError:
        raise NotImplementedError(
            "boto3 not installed. Add to requirements.txt: boto3==1.35.0"
        )
    except Exception as e:
        logger.error(f"[KeyManager] AWS KMS resolution failed for {key_id}: {e}")
        raise ValueError(f"AWS KMS key resolution failed: {e}")


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def _decrypt_aes_gcm(encrypted_b64: str, key: bytes) -> str:
    """Decrypt AES-256-GCM. Format: base64(nonce[12] + ciphertext + tag[16])."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(encrypted_b64)
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def encrypt_byok_key_for_storage(customer_key_hex: str) -> str:
    """
    Encrypt a customer-provided key with the iCommunity KEK for safe storage.
    Called when an admin configures a BYOK key in the UI.
    Returns base64-encoded encrypted key reference for storage in encryption_keys.key_reference.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    kek = _get_managed_key()
    nonce = os.urandom(12)
    aesgcm = AESGCM(kek)
    ciphertext = aesgcm.encrypt(nonce, customer_key_hex.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def generate_key_id(org_id: str, key_type: str) -> str:
    """Generate a unique key_id for a new encryption key."""
    import uuid
    prefix = {"byok": "byok", "kms_aws": "kms-aws", "kms_azure": "kms-azure", "kms_gcp": "kms-gcp"}.get(key_type, "key")
    suffix = uuid.uuid4().hex[:12]
    return f"{prefix}-{suffix}"
