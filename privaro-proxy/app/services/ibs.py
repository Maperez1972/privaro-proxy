"""
iBS (iCommunity Blockchain Solutions) — Blockchain Evidence Layer
Certifica cada audit_log y vault_access en Polygon via POST /v2/evidences.
"""
import hashlib
import base64
import json
import httpx
from typing import Dict, Any
from app.config import settings
from app.services import supabase as db

IBS_BASE = settings.IBS_API_BASE


def _get_ibs_headers() -> dict:
    """Lee la key en runtime — no al importar el módulo."""
    return {
        "Authorization": f"Bearer {settings.IBS_API_KEY}",
        "Content-Type": "application/json",
    }


def _build_hash(payload: Dict) -> str:
    """SHA-512 del JSON serializado, codificado en base64.standard."""
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sha512_bytes = hashlib.sha512(payload_json.encode("utf-8")).digest()
    return base64.b64encode(sha512_bytes).decode("utf-8")


async def _post_evidence(title: str, payload_hash: str) -> str | None:
    """POST /v2/evidences. Devuelve evidence_id o None si falla."""
    ibs_payload = {
        "payload": {
            "title": title,
            "files": [{"name": "event.json", "file": payload_hash}],
        },
        "signatures": []
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{IBS_BASE}/evidences",
                headers=_get_ibs_headers(),
                json=ibs_payload,
            )
            print(f"[iBS] POST /evidences status: {response.status_code}")
            print(f"[iBS] response: {response.text[:300]}")
            if response.status_code in (200, 201):
                data = response.json()
                evidence_id = data.get("id") or data.get("evidence_id") or data.get("_id")
                print(f"[iBS] Evidence created: {evidence_id}")
                return evidence_id
            else:
                print(f"[iBS] Error: {response.status_code} {response.text}")
                return None
    except Exception as e:
        print(f"[iBS] Exception in _post_evidence: {e}")
        return None


async def certify_audit_log(
    audit_log_id: str,
    org_id: str,
    metadata: Dict[str, Any],
) -> bool:
    """Certifica un audit_log PII en blockchain Polygon."""
    if not settings.IBS_API_KEY:
        print("[iBS] IBS_API_KEY no configurada — skipping")
        return False

    payload = {
        "audit_log_id": audit_log_id,
        "org_id": org_id,
        "source": "privaro-proxy",
        **metadata,
    }
    payload_hash = _build_hash(payload)
    title = f"privaro_{audit_log_id[:16]}"

    evidence_id = await _post_evidence(title, payload_hash)
    if evidence_id:
        await db.insert_ibs_sync_queue({
            "audit_log_id": audit_log_id,
            "org_id": org_id,
            "ibs_payload_hash": payload_hash,
            "ibs_evidence_id": evidence_id,
        })
        return True
    return False


async def certify_vault_reveal(
    token_id: str,
    org_id: str,
    user_id: str,
    entity_type: str,
    token_value: str,
) -> bool:
    """
    Certifica un evento de reveal del Tokens Vault en blockchain.
    Garantiza trazabilidad inmutable de accesos a datos PII.
    """
    if not settings.IBS_API_KEY:
        print("[iBS] IBS_API_KEY no configurada — skipping vault reveal certification")
        return False

    payload = {
        "event": "vault_reveal",
        "token_id": token_id,
        "org_id": org_id,
        "user_id": user_id,
        "entity_type": entity_type,
        "token_value": token_value,
        "source": "privaro-vault",
    }
    payload_hash = _build_hash(payload)
    title = f"vault_{token_id[:16]}"

    evidence_id = await _post_evidence(title, payload_hash)
    if evidence_id:
        print(f"[iBS] Vault reveal certified: token={token_value} evidence={evidence_id}")
        # Actualizar vault_access_log con el evidence_id
        await db.update_vault_access_ibs(token_id, user_id, evidence_id)
        return True
    return False


async def register_webhook() -> bool:
    """Verifica que los webhooks están registrados en iBS."""
    if not settings.IBS_API_KEY:
        return False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{IBS_BASE}/webhooks", headers=_get_ibs_headers())
            if r.status_code == 200:
                data = r.json()
                webhooks = data.get("list", data) if isinstance(data, dict) else data
                count = len(webhooks) if isinstance(webhooks, list) else 0
                print(f"[iBS] {count} webhook(s) registrados en iBS")
                return count > 0
            return False
    except Exception as e:
        print(f"[iBS] Error verificando webhooks: {e}")
        return False
