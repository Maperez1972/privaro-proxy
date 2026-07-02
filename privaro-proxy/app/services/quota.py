"""
quota.py — Request quota enforcement.

v2 (2026-07): reads/writes billing_accounts instead of organizations directly.
This is what makes partner aggregation work: a sub_account org's requests
increment its PARENT partner's billing_account, not its own — the RPC
resolves this via organizations.billing_account_id, so no branching logic
is needed here.

Soft-cap behaviour: once the plan's requests_limit is exceeded, requests are
still allowed (never blocked) and counted separately as overage. This matches
the public pricing FAQ ("we don't block your calls, you can upgrade or add
overage capacity"). Enterprise plans are unlimited (bypassed inside the RPC).

Monthly reset and the 20%->15% partner discount step-down are handled by
pg_cron jobs in Supabase (reset_billing_cycles, apply_discount_reviews) —
nothing to do here.
"""

import logging
from app.services import supabase as db

logger = logging.getLogger(__name__)


async def check_and_increment(org_id: str) -> dict:
    """
    Atomically increment the org's billing account request counter.

    Returns dict with allowed, requests_used, requests_limit, plan, over_quota.
    Never raises — soft-cap means requests always proceed. Callers that want
    to notify the customer (80%/100% thresholds) should inspect the returned
    dict and fire a notification themselves; this function only counts.
    """
    try:
        result = await db.rpc(
            "increment_billing_requests",
            {"p_org_id": org_id},
        )
    except Exception as e:
        # Non-fatal — log and allow on RPC error to avoid blocking prod traffic.
        # NOTE: this fails open by design (never block billable traffic on an
        # infra hiccup), but it also means quota under-counts during an outage.
        # Alert on repeated [Quota] RPC error log lines — that's a signal the
        # RPC or billing_accounts table has a problem, not just noise.
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

    return row
