"""
iBS (iCommunity Blockchain Solutions) — Blockchain Evidence Layer
Certifica cada audit_log en Polygon via POST /v2/evidences.
"""
import hashlib
import base64
import json
import asyncio
import httpx
from typing import Optional, Dict, Any
from app.config import settings
from app.services import supabase as db

IBS_BASE = settings.IBS_API_BASE


def _get_ibs_headers() -> dict:
    """Lee la key en runtime — no al importar el módulo."""
    return {
        "Authorization": f"Bearer {settings.IBS_API_KEY}",
        "Content-Type": "application/json",
    }


def _build_audit_payload_hash(audit_log_id: str, org_id: str, metadata: Dict) -> str:
    payload = {
        "audit_log_id": audit_log_id,
        "org_id": org_id,
        "source": "privaro-proxy",
        **metadata,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sha512_bytes = hashlib.sha512(payload_json.encode("utf-8")).digest()
    return base64.b64encode(sha512_bytes).decode("utf-8")


async def certify_audit_log(
    audit_log_id: str,
    org_id: str,
    metadata: Dict[str, Any],
) -> bool:
    if not settings.IBS_API_KEY:
        print("[iBS] IBS_API_KEY no configurada — skipping certification")
        return False

    payload_hash = _build_audit_payload_hash(audit_log_id, org_id, metadata)
    title = f"privaro_{audit_log_id[:16]}"

    ibs_payload = {
        "payload": {
            "title": title,
            "files": [{"name": "audit_log.json", "file": payload_hash}],
        }
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{IBS_BASE}/evidences",
                headers=_get_ibs_headers(),  # ← lazy, lee key en runtime
                json=ibs_payload,
            )
            print(f"[iBS] POST /evidences status: {response.status_code}")
            print(f"[iBS] POST /evidences response: {response.text[:300]}")

            if response.status_code in (200, 201):
                data = response.json()
                evidence_id = data.get("id") or data.get("evidence_id") or data.get("_id")
                print(f"[iBS] Evidence created: {evidence_id}")
                await db.insert_ibs_sync_queue({
                    "audit_log_id": audit_log_id,
                    "org_id": org_id,
                    "ibs_payload_hash": payload_hash,
                    "ibs_evidence_id": evidence_id,
                })
                return True
            else:
                print(f"[iBS] Error: {response.status_code} {response.text}")
                return False

    except Exception as e:
        print(f"[iBS] Exception in certify_audit_log: {e}")
        return False


async def register_webhook() -> bool:
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
