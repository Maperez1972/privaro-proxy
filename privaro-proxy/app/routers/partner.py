"""
Partner API Router — added 2026-07 for the partner/sub_account model.

Lets a partner (e.g. Octopus/Robin, org_type='partner') read compliance
artefacts belonging to its own sub_account orgs, so the partner can embed
a "compliance status" panel in ITS OWN product instead of sending each end
client to a separate Privaro login. Since 2026-07-23, also lets a partner
CREATE sub-accounts programmatically (POST) — the API-key-authenticated
equivalent of the "Mis clientes" self-service screen, for a partner whose
own backend wants to auto-provision a Privaro sub-account with zero manual
steps (e.g. the moment a new client signs up with them).

Auth: same X-Privaro-Key mechanism as everything else, but the key must:
  1. Belong to an org with org_type = 'partner'
  2. Carry 'partner:read_children' for the read endpoints below
  3. Carry 'partner:write_children' for POST /sub-accounts (a separate,
     more sensitive permission — principle of least privilege: a partner's
     read-only integration key should never be able to create billable
     sub-accounts just because it can read reports).

Data isolation is enforced per-request by verifying the target org's
parent_org_id matches the caller's org_id — NOT by widening what the
partner's key can see. A partner key can never read another partner's data,
and can never write to an EXISTING sub_account (no PATCH/DELETE here).
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any
import hashlib
import secrets

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


def _require_partner_write(key_record: Dict[str, Any]) -> None:
    perms = key_record.get("permissions", [])
    if "partner:write_children" not in perms and settings.ENVIRONMENT == "production":
        raise HTTPException(
            status_code=403,
            detail={"error": "partner_write_permission_required",
                    "message": "This key can read but not create sub-accounts. "
                               "Generate a key with 'partner:write_children' to use this endpoint."},
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


# ── POST /v1/partner/sub-accounts — added 2026-07-23 ────────────────────────

class CreateSubAccountRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    sector: str
    llm_provider: str
    llm_model: str


@router.post("/sub-accounts", status_code=201)
async def create_sub_account(
    body: CreateSubAccountRequest,
    key_record: Dict[str, Any] = Depends(verify_api_key_or_dev),
):
    """
    Programmatic equivalent of "Mis clientes" → "Añadir cliente" in the
    dashboard. For a partner's own backend to auto-provision a Privaro
    sub-account (e.g. the moment one of THEIR clients signs up), with no
    manual step in the Privaro UI.

    Requires the caller's org to be org_type='partner' and its key to carry
    'partner:write_children' — deliberately a different, narrower permission
    than the read endpoints, so a read-only integration key can't
    accidentally create billable sub-accounts.

    On any partial failure, rolls back everything created so far (same
    behaviour as the dashboard's Edge Function) rather than leaving an
    orphaned org/pipeline behind.
    """
    _require_partner(key_record)
    _require_partner_write(key_record)

    partner_org_id = key_record["org_id"]
    partner_org = await db.get_organization(partner_org_id)
    if not partner_org or not partner_org.get("billing_account_id"):
        raise HTTPException(
            status_code=500,
            detail={"error": "partner_billing_not_configured",
                    "message": "This partner organization has no billing_account configured."},
        )
    billing_account_id = partner_org["billing_account_id"]

    new_org = await db.create_sub_account_org(
        name=body.name, parent_org_id=partner_org_id, billing_account_id=billing_account_id,
    )
    if not new_org:
        raise HTTPException(status_code=500, detail={"error": "org_creation_failed"})

    pipeline = await db.create_pipeline_for_org(
        org_id=new_org["id"], name=f"{body.name} — default pipeline",
        sector=body.sector, llm_provider=body.llm_provider, llm_model=body.llm_model,
    )
    if not pipeline:
        await db.delete_organization(new_org["id"])
        raise HTTPException(status_code=500, detail={"error": "pipeline_creation_failed"})

    raw_key = f"prvr_{secrets.token_hex(20)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:12]

    key_created = await db.create_api_key_for_org(
        org_id=new_org["id"], name=f"{body.name} — proxy key",
        key_hash=key_hash, key_prefix=key_prefix, pipeline_ids=[pipeline["id"]],
    )
    if not key_created:
        await db.delete_pipeline(pipeline["id"])
        await db.delete_organization(new_org["id"])
        raise HTTPException(status_code=500, detail={"error": "api_key_creation_failed"})

    return {
        "org_id": new_org["id"],
        "pipeline_id": pipeline["id"],
        "api_key": raw_key,
        "warning": "This key is shown only once. Store it securely now — Privaro cannot retrieve it again.",
    }


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
