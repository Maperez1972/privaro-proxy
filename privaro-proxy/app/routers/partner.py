"""
Partner API Router — added 2026-07 for the partner/sub_account model.

Lets a partner (e.g. Octopus/Robin, org_type='partner') read — never write —
compliance artefacts belonging to its own sub_account orgs, so the partner
can embed a "compliance status" panel in ITS OWN product instead of sending
each end client to a separate Privaro login.

Auth: same X-Privaro-Key mechanism as everything else, but the key must:
  1. Belong to an org with org_type = 'partner'
  2. Carry the 'partner:read_children' permission

Data isolation is enforced per-request by verifying the target org's
parent_org_id matches the caller's org_id — NOT by widening what the
partner's key can see. A partner key can never read another partner's data,
and can never write to a sub_account (no POST/PATCH/DELETE in this router).
"""
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any

from app.services.auth import verify_api_key_or_dev
from app.services import supabase as db
from app.config import settings

router = APIRouter()


def _require_partner(key_record: Dict[str, Any]) -> None:
    perms = key_record.get("permissions", [])
    if "partner:read_children" not in perms and settings.ENVIRONMENT == "production":
        raise HTTPException(
            status_code=403,
            detail={"error": "partner_permission_required",
                    "message": "This key is not authorized for partner sub-account access."},
        )


async def _resolve_sub_account_or_403(partner_org_id: str, sub_org_id: str) -> None:
    ok = await db.verify_sub_account(partner_org_id, sub_org_id)
    if not ok:
        # Same error whether the org doesn't exist or belongs to someone else —
        # don't leak which orgs exist to a caller who shouldn't see them.
        raise HTTPException(
            status_code=404,
            detail={"error": "sub_account_not_found",
                    "message": "No sub-account with this id under your partner organization."},
        )


# ── GET /v1/partner/sub-accounts ────────────────────────────────────────────

@router.get("/sub-accounts")
async def list_sub_accounts(
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """List all sub-accounts (end clients) under the calling partner org."""
    _require_partner(key_record)
    accounts = await db.list_sub_accounts(key_record["org_id"])
    return {"sub_accounts": accounts, "count": len(accounts)}


# ── GET /v1/partner/sub-accounts/{org_id}/dpo-report/latest ─────────────────

@router.get("/sub-accounts/{org_id}/dpo-report/latest")
async def latest_dpo_report(
    org_id: str,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Latest DPO report for a sub-account, with a short-lived signed download
    URL (1h). Embed this link/button directly in the partner's own product —
    no Privaro login required for the end client.
    """
    _require_partner(key_record)
    await _resolve_sub_account_or_403(key_record["org_id"], org_id)

    report = await db.get_latest_dpo_report(org_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail={"error": "no_dpo_report_yet",
                    "message": "No DPO report has been generated for this sub-account yet."},
        )

    signed_url = None
    if report.get("storage_path"):
        signed_url = await db.get_signed_dpo_report_url(report["storage_path"])

    return {
        "org_id": org_id,
        "period_label": report.get("period_label"),
        "period_start": report.get("period_start"),
        "period_end": report.get("period_end"),
        "generated_at": report.get("generated_at"),
        "event_count": report.get("event_count"),
        "certified_count": report.get("certified_count"),
        "high_risk_count": report.get("high_risk_count"),
        "download_url": signed_url,
        "download_url_expires_in": 3600 if signed_url else None,
    }


# ── GET /v1/partner/sub-accounts/{org_id}/audit-summary ─────────────────────

@router.get("/sub-accounts/{org_id}/audit-summary")
async def audit_summary(
    org_id: str,
    days: int = 30,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Lightweight compliance widget data — event counts, leaks, high-risk
    events over the trailing N days. Meant for a small status card in the
    partner's own dashboard, not a full audit log dump.
    """
    _require_partner(key_record)
    await _resolve_sub_account_or_403(key_record["org_id"], org_id)

    summary = await db.get_audit_summary(org_id, days=min(days, 90))
    return {"org_id": org_id, **summary}
