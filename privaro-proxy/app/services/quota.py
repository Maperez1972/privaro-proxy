"""
quota.py — Request quota enforcement.

v3 (2026-07): fires a usage_threshold (80%) / usage_overage (100%)
notification the FIRST time each is crossed per billing cycle. The RPC
(increment_billing_requests) does the crossing detection and dedup
server-side (threshold_notified_at / overage_notified_at columns), so this
file just reacts to the flags it gets back — no polling, no extra queries
on the hot path.

Notifications are dispatched as a fire-and-forget background task so a
slow email/webhook never adds latency to the actual proxy request.

v2 recap: reads/writes billing_accounts instead of organizations directly.
Sub-account requests roll up to the parent partner's billing_account
automatically (resolved server-side by organizations.billing_account_id).
Soft-cap: never blocks. Monthly reset and the 20%->15% discount step-down
are handled by pg_cron jobs in Supabase — nothing to do here.
"""

import asyncio
import logging
from app.services import supabase as db

logger = logging.getLogger(__name__)


async def check_and_increment(org_id: str) -> dict:
    """
    Atomically increment the org's billing account request counter.

    Returns dict with allowed, requests_used, requests_limit, plan,
    over_quota, owner_org_id. Never raises — soft-cap means requests always
    proceed.
    """
    try:
        result = await db.rpc(
            "increment_billing_requests",
            {"p_org_id": org_id},
        )
    except Exception as e:
        logger.error(f"[Quota] RPC error for org {org_id}: {e}")
        return {
            "allowed": True, "requests_used": -1, "requests_limit": -1,
            "plan": "unknown", "over_quota": False,
        }

    if not result:
        logger.error(f"[Quota] Empty RPC result for org {org_id}")
        return {
            "allowed": True, "requests_used": -1, "requests_limit": -1,
            "plan": "unknown", "over_quota": False,
        }

    row = result[0] if isinstance(result, list) else result

    if row.get("over_quota"):
        logger.warning(
            f"[Quota] OVERAGE org={org_id} plan={row.get('plan')} "
            f"used={row.get('requests_used')}/{row.get('requests_limit')}"
        )
    else:
        logger.debug(
            f"[Quota] OK org={org_id} plan={row.get('plan')} "
            f"used={row.get('requests_used')}/{row.get('requests_limit')}"
        )

    # Fire-and-forget — never let a notification delay or fail the request.
    if row.get("notify_threshold") or row.get("notify_overage"):
        asyncio.create_task(_dispatch_notifications(row))

    return row


async def _dispatch_notifications(row: dict) -> None:
    owner_org_id = row.get("owner_org_id")
    if not owner_org_id:
        return

    try:
        org = await db.get_organization(owner_org_id)
        org_name = org.get("name") if org else owner_org_id

        if row.get("notify_threshold"):
            await db.send_usage_notification(
                owner_org_id, "usage_threshold", org_name, row.get("plan"),
                row.get("requests_used"), row.get("requests_limit"),
            )
        if row.get("notify_overage"):
            await db.send_usage_notification(
                owner_org_id, "usage_overage", org_name, row.get("plan"),
                row.get("requests_used"), row.get("requests_limit"),
            )
    except Exception as e:
        logger.error(f"[Quota] Notification dispatch failed for org {owner_org_id}: {e}")
