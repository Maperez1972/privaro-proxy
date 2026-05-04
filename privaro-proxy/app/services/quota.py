"""
quota.py — Request quota enforcement for free/trial plans.

Called from proxy.py before any billable operation.
Uses the increment_org_requests() Supabase RPC to atomically
count requests and check limits.

Plans:
  free:       500 requests lifetime (no expiry)
  starter:    50_000 / month (reset monthly — TODO: cron)
  pro:        500_000 / month
  enterprise: unlimited
"""

import logging
from fastapi import HTTPException
from app.services import supabase as db

logger = logging.getLogger(__name__)

PLAN_LIMITS = {
    "free":       500,
    "pilot":      500,        # legacy — treat same as free
    "starter":    50_000,
    "pro":        500_000,
    "enterprise": None,       # unlimited
}


async def check_and_increment(org_id: str) -> dict:
    """
    Atomically increment org request counter and check quota.

    Returns dict with allowed, requests_used, requests_limit, plan.
    Raises HTTP 429 if quota exceeded.
    """
    try:
        result = await db.rpc(
            "increment_org_requests",
            {"p_org_id": org_id},
        )
    except Exception as e:
        # Non-fatal — log and allow on RPC error to avoid blocking prod traffic
        logger.error(f"[Quota] RPC error for org {org_id}: {e}")
        return {"allowed": True, "requests_used": -1, "requests_limit": -1, "plan": "unknown"}

    if not result:
        logger.error(f"[Quota] Empty RPC result for org {org_id}")
        return {"allowed": True, "requests_used": -1, "requests_limit": -1, "plan": "unknown"}

    row = result[0] if isinstance(result, list) else result

    if not row.get("allowed", True):
        plan = row.get("plan", "free")
        used = row.get("requests_used", 0)
        limit = row.get("requests_limit", 500)
        logger.warning(f"[Quota] BLOCKED org={org_id} plan={plan} used={used}/{limit}")
        raise HTTPException(
            status_code=429,
            detail={
                "error": "quota_exceeded",
                "message": (
                    f"You have used all {limit} requests included in your {plan} plan. "
                    "Upgrade to continue using Privaro."
                ),
                "requests_used": used,
                "requests_limit": limit,
                "plan": plan,
                "upgrade_url": "https://privaro.ai/pricing",
            },
        )

    logger.debug(
        f"[Quota] OK org={org_id} plan={row.get('plan')} "
        f"used={row.get('requests_used')}/{row.get('requests_limit')}"
    )
    return row
