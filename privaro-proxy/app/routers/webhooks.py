"""
Webhook receptor para iBS — recibe event evidence.certified
y actualiza el audit_log con el tx hash de Polygon.
"""
from fastapi import APIRouter, Request, HTTPException, Header
from typing import Optional
from app.config import settings
from app.services import supabase as db

router = APIRouter()


@router.post("/ibs")
async def receive_ibs_webhook(
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """
    Recibe el webhook evidence.certified de iBS.
    iBS envía: Authorization: Bearer <IBS_WEBHOOK_SECRET>
    """
    # Validar secret
    webhook_secret = settings.IBS_WEBHOOK_SECRET or "privaro_webhook_secret_2026"
    expected = f"Bearer {webhook_secret}"

    if authorization != expected:
        print(f"[Webhook] Unauthorized — got: {authorization}")
        raise HTTPException(status_code=401, detail="Invalid webhook secret")

    payload = await request.json()
    print(f"[Webhook] iBS payload received: {str(payload)[:300]}")

    event = payload.get("event")
    if event != "evidence.certified":
        # Ignorar otros eventos silenciosamente
        return {"status": "ignored", "event": event}

    data = payload.get("data", {})
    evidence_id = data.get("evidence_id") or data.get("id")
    title = data.get("title", "")
    certification_hash = data.get("certification_hash")
    network = data.get("network", "polygon")
    certification_timestamp = data.get("certification_timestamp")

    if not evidence_id or not certification_hash:
        print(f"[Webhook] Missing fields: evidence_id={evidence_id}, hash={certification_hash}")
        raise HTTPException(status_code=400, detail="Missing required fields")

    # Extraer audit_log_id del title (formato: "privaro_<audit_log_id_first16>")
    # Buscar en ibs_sync_queue por evidence_id
    audit_log_id = await db.get_audit_log_id_by_evidence(evidence_id, title)

    if not audit_log_id:
        print(f"[Webhook] audit_log not found for evidence_id={evidence_id}, title={title}")
        # No devolver error — iBS no debe reintentar por esto
        return {"status": "not_found", "evidence_id": evidence_id}

    # UPDATE audit_log con datos de certificación
    updated = await db.update_audit_log_ibs(
        audit_log_id=audit_log_id,
        ibs_evidence_id=evidence_id,
        ibs_certification_hash=certification_hash,
        ibs_network=network,
        ibs_certified_at=certification_timestamp,
    )

    if updated:
        # Limpiar de la sync_queue
        await db.delete_ibs_sync_queue(audit_log_id)
        print(f"[Webhook] ✅ Certified: {audit_log_id} → tx {certification_hash[:20]}...")
        return {"status": "certified", "audit_log_id": audit_log_id}
    else:
        print(f"[Webhook] ❌ Failed to update audit_log: {audit_log_id}")
        raise HTTPException(status_code=500, detail="Failed to update audit log")
