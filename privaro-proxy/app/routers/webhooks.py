"""
Webhook receptor para iBS — recibe event evidence.certified
iBS envía el secret como Authorization: Bearer <IBS_WEBHOOK_SECRET>
"""
from fastapi import APIRouter, Request, HTTPException
from typing import Optional
from app.services import supabase as db

router = APIRouter()


def _validate_ibs_request(request: Request):
    """
    Valida que el webhook viene de iBS.
    iBS envía Authorization: Bearer <bearer configurado al registrar el webhook>
    Si no hay IBS_WEBHOOK_SECRET configurado, acepta sin validar (modo dev).
    """
    from app.config import settings
    expected_secret = settings.IBS_WEBHOOK_SECRET or ""

    if not expected_secret:
        # Sin secret configurado — aceptar todo (modo dev / webhook sin bearer)
        return

    auth_header = request.headers.get("Authorization", "")
    bearer_token = auth_header.replace("Bearer ", "").strip()

    if bearer_token != expected_secret:
        print(f"[Webhook] Unauthorized — bearer no coincide")
        raise HTTPException(status_code=401, detail="Invalid webhook secret")


async def _process_evidence_certified(payload: dict) -> dict:
    print(f"[Webhook] iBS payload: {str(payload)[:400]}")

    data = payload.get("data", payload)
    evidence_id = (
        data.get("evidence_id") or data.get("id") or data.get("_id")
        or payload.get("evidence_id") or payload.get("id")
    )
    title = data.get("title") or payload.get("title", "")
    certification_hash = (
        data.get("certification_hash") or data.get("certificationHash")
        or data.get("tx_hash") or data.get("txHash")
    )
    network = data.get("network", "polygon")
    certification_timestamp = (
        data.get("certification_timestamp") or data.get("certificationTimestamp")
        or data.get("certified_at")
    )

    print(f"[Webhook] evidence_id={evidence_id}, title={title}, hash={certification_hash}")

    if not evidence_id:
        print(f"[Webhook] Missing evidence_id — payload: {payload}")
        return {"status": "ignored", "reason": "no evidence_id"}

    audit_log_id = await db.get_audit_log_id_by_evidence(evidence_id, title)

    if not audit_log_id:
        print(f"[Webhook] audit_log not found for evidence_id={evidence_id}")
        return {"status": "not_found", "evidence_id": evidence_id}

    updated = await db.update_audit_log_ibs(
        audit_log_id=audit_log_id,
        ibs_evidence_id=evidence_id,
        ibs_certification_hash=certification_hash or "",
        ibs_network=network,
        ibs_certified_at=certification_timestamp,
    )

    if updated:
        await db.delete_ibs_sync_queue(audit_log_id)
        print(f"[Webhook] ✅ Certified: {audit_log_id} → {certification_hash}")
        return {"status": "certified", "audit_log_id": audit_log_id}
    else:
        print(f"[Webhook] ❌ Update failed for audit_log_id={audit_log_id}")
        raise HTTPException(status_code=500, detail="Failed to update audit log")


@router.post("/ibs")
async def receive_ibs_webhook(request: Request):
    _validate_ibs_request(request)
    return await _process_evidence_certified(await request.json())


@router.post("/ibs/ibs-webhook")
async def receive_ibs_webhook_evidence(request: Request):
    _validate_ibs_request(request)
    return await _process_evidence_certified(await request.json())


@router.post("/ibs/ibs-webhook-signature-ok")
async def receive_ibs_signature_ok(request: Request):
    _validate_ibs_request(request)
    payload = await request.json()
    print(f"[Webhook] Signature OK: {str(payload)[:300]}")
    return await _process_evidence_certified(payload)


@router.post("/ibs/ibs-webhook-signature-ko")
async def receive_ibs_signature_ko(request: Request):
    _validate_ibs_request(request)
    payload = await request.json()
    print(f"[Webhook] ⚠️ Signature KO: {str(payload)[:300]}")
    evidence_id = payload.get("evidence_id") or payload.get("id")
    if evidence_id:
        title = payload.get("title", "")
        audit_log_id = await db.get_audit_log_id_by_evidence(evidence_id, title)
        if audit_log_id:
            await db.update_audit_log_ibs_failed(audit_log_id, evidence_id)
    return {"status": "ko_received"}
