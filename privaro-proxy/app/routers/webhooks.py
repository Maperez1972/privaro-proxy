"""
Webhook router — iBS inbound + Outbound dispatcher
Handles:
  - POST /ibs              — iBS blockchain certification callbacks
  - POST /ibs/*            — iBS variant callbacks
  - Outbound dispatch      — fires org webhooks on high-risk events
"""
import hashlib
import hmac
import json
import time
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from typing import Optional
from app.services import supabase as db

router = APIRouter()


# ══════════════════════════════════════════════════════════════════════
# OUTBOUND WEBHOOK DISPATCHER
# ══════════════════════════════════════════════════════════════════════

WEBHOOK_EVENTS = {
    "high_risk_step":  "Triggered when an agent step has risk_score ≥ 0.8",
    "run_completed":   "Triggered when an agent run ends (completed/failed/cancelled)",
    "pii_blocked":     "Triggered when a step has detections with action=blocked",
    "pii_detected":    "Triggered when any PII is detected in a step",
}


def _sign_payload(secret: str, payload_bytes: bytes) -> str:
    """Generate HMAC-SHA256 signature for webhook payload."""
    return "sha256=" + hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


async def dispatch_webhook(
    org_id: str,
    event_type: str,
    payload: dict,
) -> None:
    """
    Fire outbound webhooks for an org on a given event.
    Called as a BackgroundTask — non-blocking for the main request.
    Retries up to 3 times with exponential backoff.
    """
    import httpx

    # Fetch active webhooks for this org that subscribe to this event
    rows = await db.get_org_webhooks(org_id=org_id, event_type=event_type)
    if not rows:
        return

    payload_bytes = json.dumps(payload, default=str).encode("utf-8")
    timestamp = str(int(time.time()))

    for webhook in rows:
        webhook_id = webhook["id"]
        url = webhook["url"]
        secret = webhook.get("secret") or ""

        headers = {
            "Content-Type": "application/json",
            "X-Privaro-Event": event_type,
            "X-Privaro-Timestamp": timestamp,
            "X-Privaro-Delivery": webhook_id,
        }
        if secret:
            headers["X-Privaro-Signature"] = _sign_payload(secret, payload_bytes)

        # Attempt delivery with retries
        delivered = False
        http_status = None
        response_body = ""
        attempts = 0

        for attempt in range(3):
            attempts += 1
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(url, content=payload_bytes, headers=headers)
                    http_status = resp.status_code
                    response_body = resp.text[:500]
                    if resp.status_code < 300:
                        delivered = True
                        break
                    # Non-2xx: wait before retry
                    await asyncio.sleep(2 ** attempt)
            except Exception as e:
                response_body = str(e)[:500]
                import asyncio
                await asyncio.sleep(2 ** attempt)

        # Log the delivery attempt
        await db.log_webhook_delivery(
            webhook_id=webhook_id,
            org_id=org_id,
            event_type=event_type,
            payload=payload,
            status="delivered" if delivered else "failed",
            http_status=http_status,
            response_body=response_body,
            attempts=attempts,
        )

        print(
            f"[Webhook] {'✅' if delivered else '❌'} {event_type} → {url} "
            f"| status={http_status} | attempts={attempts}"
        )


async def maybe_dispatch_agent_step(
    org_id: str,
    agent_run_id: str,
    step_index: int,
    pipeline_id: str,
    risk_score: float,
    pii_detected: int,
    pii_masked: int,
    gdpr_compliant: bool,
    detections: list,
    background_tasks: BackgroundTasks,
) -> None:
    """
    Evaluate agent step and fire relevant webhooks.
    Called from agent.py after /v1/agent/protect.
    """
    payload_base = {
        "org_id": org_id,
        "agent_run_id": agent_run_id,
        "step_index": step_index,
        "pipeline_id": pipeline_id,
        "risk_score": round(risk_score, 4),
        "pii_detected": pii_detected,
        "pii_masked": pii_masked,
        "gdpr_compliant": gdpr_compliant,
        "timestamp": time.time(),
    }

    # high_risk_step: risk_score >= 0.8
    if risk_score >= 0.8:
        background_tasks.add_task(
            dispatch_webhook,
            org_id=org_id,
            event_type="high_risk_step",
            payload={**payload_base, "event": "high_risk_step"},
        )

    # pii_blocked: any detection with action=blocked
    blocked = [d for d in detections if getattr(d, "action", "") == "blocked"]
    if blocked:
        background_tasks.add_task(
            dispatch_webhook,
            org_id=org_id,
            event_type="pii_blocked",
            payload={
                **payload_base,
                "event": "pii_blocked",
                "blocked_types": list({d.type for d in blocked}),
            },
        )

    # pii_detected: any detection
    if pii_detected > 0:
        background_tasks.add_task(
            dispatch_webhook,
            org_id=org_id,
            event_type="pii_detected",
            payload={
                **payload_base,
                "event": "pii_detected",
                "entity_types": list({
                    getattr(d, "type", "unknown") for d in detections
                }),
            },
        )


async def dispatch_run_completed(
    org_id: str,
    agent_run_id: str,
    pipeline_id: str,
    status: str,
    step_count: int,
    total_pii_detected: int,
    max_risk_score: float,
    gdpr_compliant: bool,
    background_tasks: BackgroundTasks,
) -> None:
    """Fire run_completed webhook when an agent run ends."""
    background_tasks.add_task(
        dispatch_webhook,
        org_id=org_id,
        event_type="run_completed",
        payload={
            "event": "run_completed",
            "org_id": org_id,
            "agent_run_id": agent_run_id,
            "pipeline_id": pipeline_id,
            "status": status,
            "step_count": step_count,
            "total_pii_detected": total_pii_detected,
            "max_risk_score": round(max_risk_score, 4),
            "gdpr_compliant": gdpr_compliant,
            "timestamp": time.time(),
        },
    )


# ══════════════════════════════════════════════════════════════════════
# INBOUND — iBS CERTIFICATION CALLBACKS
# ══════════════════════════════════════════════════════════════════════

def _validate_ibs_request(request: Request):
    from app.config import settings
    expected_secret = settings.IBS_WEBHOOK_SECRET or ""
    if not expected_secret:
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
    network = data.get("network", "fantom_opera_mainnet")
    certification_timestamp = (
        data.get("certification_timestamp") or data.get("certificationTimestamp")
        or data.get("certified_at")
    )

    print(f"[Webhook] evidence_id={evidence_id}, title={title}, hash={certification_hash}")

    if not evidence_id:
        print(f"[Webhook] Missing evidence_id — payload: {payload}")
        return {"status": "ignored", "reason": "no evidence_id"}

    results = []

    audit_log_id = await db.get_audit_log_id_by_evidence(evidence_id, title)
    if audit_log_id:
        updated = await db.update_audit_log_ibs(
            audit_log_id=audit_log_id,
            ibs_evidence_id=evidence_id,
            ibs_certification_hash=certification_hash or "",
            ibs_network=network,
            ibs_certified_at=certification_timestamp,
        )
        if updated:
            await db.delete_ibs_sync_queue(audit_log_id)
            print(f"[Webhook] ✅ Audit log certified: {audit_log_id} → {certification_hash}")
            results.append({"type": "audit_log", "id": audit_log_id})

    if certification_hash:
        await db.update_audit_logs_batch_hash(
            evidence_id=evidence_id,
            certification_hash=certification_hash,
            network=network,
            certified_at=certification_timestamp,
        )
        agent_runs_updated = await db.update_agent_runs_ibs_hash(
            evidence_id=evidence_id,
            certification_hash=certification_hash,
            network=network,
            certified_at=certification_timestamp,
        )
        if agent_runs_updated > 0:
            print(f"[Webhook] ✅ {agent_runs_updated} agent_run(s) hash updated → {certification_hash}")
            results.append({"type": "agent_runs", "count": agent_runs_updated})
        await db.update_ibs_batch_certified(
            evidence_id=evidence_id,
            certification_hash=certification_hash,
            network=network,
        )

    vault_updated = await db.update_vault_access_log_ibs(
        evidence_id=evidence_id,
        certification_hash=certification_hash or "",
        network=network,
    )
    if vault_updated:
        print(f"[Webhook] ✅ Vault access certified: evidence={evidence_id}")
        results.append({"type": "vault_access", "evidence_id": evidence_id})

    if results:
        return {"status": "certified", "evidence_id": evidence_id, "updated": results}

    print(f"[Webhook] ⚠️ No matching record for evidence_id={evidence_id}")
    return {"status": "not_found", "evidence_id": evidence_id}


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
