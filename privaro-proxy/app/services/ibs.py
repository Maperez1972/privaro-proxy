"""
iBS (iCommunity Blockchain Solutions) — Blockchain Evidence Layer
Certifica cada audit_log en Polygon via POST /v2/evidences.
Flujo ASYNC: el proxy responde al cliente en ~50ms,
la certificación llega después vía webhook event evidence.certified.
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
IBS_HEADERS = {
    "Authorization": f"Bearer {settings.IBS_API_KEY}",
    "Content-Type": "application/json",
}


def _build_audit_payload_hash(audit_log_id: str, org_id: str, metadata: Dict) -> str:
    """
    SHA-512 del JSON del audit_log serializado, codificado en base64.standard.
    Este es el payload que enviamos a iBS como evidencia.
    """
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
    """
    POST /v2/evidences — certifica el audit_log en blockchain Polygon.
    Devuelve True si el request fue aceptado por iBS (201).
    La certificación real llega después via webhook.
    """
    if not settings.IBS_API_KEY:
        print("[iBS] IBS_API_KEY no configurada — skipping certification")
        return False

    payload_hash = _build_audit_payload_hash(audit_log_id, org_id, metadata)
    title = f"privaro_{audit_log_id[:16]}"

    ibs_payload = {
        "payload": {
            "title": title,
            "files": [
                {
                    "name": "audit_log.json",
                    "file": payload_hash,
                }
            ],
        }
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{IBS_BASE}/evidences",
                headers=IBS_HEADERS,
                json=ibs_payload,
            )
            print(f"[iBS] POST /evidences status: {response.status_code}")
            print(f"[iBS] POST /evidences response: {response.text[:300]}")

            if response.status_code in (200, 201):
                data = response.json()
                evidence_id = data.get("id") or data.get("evidence_id") or data.get("_id")
                print(f"[iBS] Evidence created: {evidence_id}")

                # Guardar en ibs_sync_queue para resiliencia
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
    """
    Registra el endpoint /v1/webhooks/ibs en iBS al arrancar el proxy.
    Solo registra si no existe ya.
    """
    if not settings.IBS_API_KEY:
        return False

    webhook_url = "https://privaro-proxy-production.up.railway.app/v1/webhooks/ibs"
    webhook_secret = settings.IBS_WEBHOOK_SECRET or "privaro_webhook_secret_2026"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # 1. Listar webhooks existentes
            r = await client.get(f"{IBS_BASE}/webhooks", headers=IBS_HEADERS)
            if r.status_code == 200:
                existing = r.json()
                webhooks_list = existing.get("list", existing) if isinstance(existing, dict) else existing
                if isinstance(webhooks_list, list):
                    already = any(
                        w.get("url") == webhook_url
                        for w in webhooks_list
                        if isinstance(w, dict)
                    )
                    if already:
                        print(f"[iBS] Webhook ya registrado: {webhook_url}")
                        return True

            # 2. Registrar webhook
            payload = {
                "url": webhook_url,
                "bearer": webhook_secret,
                "name": "privaro-evidence-certified",
                "events": ["evidence.certified"],
            }
            r2 = await client.post(f"{IBS_BASE}/webhooks", headers=IBS_HEADERS, json=payload)
            print(f"[iBS] Register webhook status: {r2.status_code} {r2.text[:200]}")
            return r2.status_code in (200, 201)

    except Exception as e:
        print(f"[iBS] Exception in register_webhook: {e}")
        return False
