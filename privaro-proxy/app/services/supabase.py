"""
Supabase service — server-side database operations using service_role key.
This bypasses RLS intentionally: the proxy is a trusted server component.
All writes are validated and scoped by org_id before reaching this layer.
"""
import httpx
import json
from typing import Optional, Dict, Any
from app.config import settings


SUPABASE_REST = f"{settings.SUPABASE_URL}/rest/v1"
SUPABASE_HEADERS = {
    "apikey": settings.SUPABASE_SERVICE_KEY,
    "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}


async def insert_audit_log(payload: Dict[str, Any]) -> Optional[str]:
    """
    Insert a new audit_log row and return its UUID.
    Uses service_role — bypasses RLS (correct for server writes).
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{SUPABASE_REST}/audit_logs",
            headers=SUPABASE_HEADERS,
            json=payload,
        )
        if response.status_code in (200, 201):
            data = response.json()
            return data[0]["id"] if data else None
        else:
            print(f"[Supabase] audit_log INSERT failed: {response.status_code} {response.text}")
            return None


async def insert_pii_detections(rows: list) -> bool:
    """Insert multiple pii_detection rows for a single request."""
    if not rows:
        return True
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{SUPABASE_REST}/pii_detections",
            headers=SUPABASE_HEADERS,
            json=rows,
        )
        return response.status_code in (200, 201)


async def get_pipeline(pipeline_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch pipeline config by ID.
    Returns None if pipeline not found or inactive.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(
            f"{SUPABASE_REST}/pipelines",
            headers=SUPABASE_HEADERS,
            params={
                "id": f"eq.{pipeline_id}",
                "status": "eq.active",
                "select": "id,org_id,name,sector,llm_provider,llm_model,status",
                "limit": "1",
            },
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else None
        return None


async def get_org_settings(org_id: str) -> Optional[Dict[str, Any]]:
    """Fetch org settings for policy enforcement."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(
            f"{SUPABASE_REST}/org_settings",
            headers=SUPABASE_HEADERS,
            params={"org_id": f"eq.{org_id}", "limit": "1"},
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else None
        return None


async def insert_ibs_sync_queue(payload: Dict[str, Any]) -> bool:
    """Insert into ibs_sync_queue for resilience tracking."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            f"{SUPABASE_REST}/ibs_sync_queue",
            headers=SUPABASE_HEADERS,
            json=payload,
        )
        return response.status_code in (200, 201)


async def update_audit_log_ibs(
    audit_log_id: str,
    ibs_evidence_id: str,
    ibs_certification_hash: str,
    ibs_network: str,
    ibs_certified_at: Optional[str],
) -> bool:
    """UPDATE audit_log ibs_* columns when webhook arrives."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.patch(
            f"{SUPABASE_REST}/audit_logs",
            headers=SUPABASE_HEADERS,
            params={"id": f"eq.{audit_log_id}"},
            json={
                "ibs_status": "certified",
                "ibs_evidence_id": ibs_evidence_id,
                "ibs_certification_hash": ibs_certification_hash,
                "ibs_network": ibs_network,
                "ibs_certified_at": ibs_certified_at,
            },
        )
        return response.status_code in (200, 201, 204)


async def update_audit_log_ibs_failed(audit_log_id: str, ibs_evidence_id: str) -> bool:
    """Mark audit_log as ibs_status=failed when signature KO."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.patch(
            f"{SUPABASE_REST}/audit_logs",
            headers=SUPABASE_HEADERS,
            params={"id": f"eq.{audit_log_id}"},
            json={"ibs_status": "failed", "ibs_evidence_id": ibs_evidence_id},
        )
        return response.status_code in (200, 201, 204)


async def get_audit_log_id_by_evidence(evidence_id: str, title: str) -> Optional[str]:
    """
    Find audit_log_id from ibs_sync_queue by evidence_id.
    Fallback: search by title prefix in audit_logs metadata.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        # Try ibs_sync_queue first
        r = await client.get(
            f"{SUPABASE_REST}/ibs_sync_queue",
            headers=SUPABASE_HEADERS,
            params={
                "ibs_evidence_id": f"eq.{evidence_id}",
                "select": "audit_log_id",
                "limit": "1",
            },
        )
        if r.status_code == 200:
            data = r.json()
            if data:
                return data[0]["audit_log_id"]

        # Fallback: extract from title "privaro_<first16_of_uuid>"
        # title format: "privaro_67a5583e4ca14f3c"
        if title.startswith("privaro_"):
            partial_id = title.replace("privaro_", "")
            r2 = await client.get(
                f"{SUPABASE_REST}/audit_logs",
                headers=SUPABASE_HEADERS,
                params={
                    "id": f"like.{partial_id}%",
                    "select": "id",
                    "limit": "1",
                },
            )
            if r2.status_code == 200:
                data2 = r2.json()
                if data2:
                    return data2[0]["id"]
        return None


async def delete_ibs_sync_queue(audit_log_id: str) -> bool:
    """Remove from ibs_sync_queue after successful certification."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.delete(
            f"{SUPABASE_REST}/ibs_sync_queue",
            headers=SUPABASE_HEADERS,
            params={"audit_log_id": f"eq.{audit_log_id}"},
        )
        return response.status_code in (200, 204)


async def increment_pipeline_counters(
    pipeline_id: str,
    detected: int,
    masked: int,
    leaked: int,
    latency_ms: int,
) -> None:
    """Increment pipeline aggregate counters (fire-and-forget)."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        # Use Supabase RPC for atomic increments
        await client.post(
            f"{settings.SUPABASE_URL}/rest/v1/rpc/increment_pipeline_stats",
            headers=SUPABASE_HEADERS,
            json={
                "p_pipeline_id": pipeline_id,
                "p_requests": 1,
                "p_detected": detected,
                "p_masked": masked,
                "p_leaked": leaked,
                "p_latency_ms": latency_ms,
            },
        )


async def update_vault_access_ibs(token_id: str, user_id: str, evidence_id: str) -> bool:
    """Update vault_access_log with iBS evidence_id after certification."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.patch(
            f"{SUPABASE_REST}/vault_access_log",
            headers=SUPABASE_HEADERS,
            params={
                "token_id": f"eq.{token_id}",
                "user_id": f"eq.{user_id}",
                "action": "eq.reveal",
            },
            json={"ibs_evidence_id": evidence_id},
        )
        return response.status_code in (200, 201, 204)


async def get_org_ibs_signature(org_id: str) -> Optional[str]:
    """Get the iBS signature_id for an organization."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(
            f"{SUPABASE_REST}/organizations",
            headers=SUPABASE_HEADERS,
            params={
                "id": f"eq.{org_id}",
                "select": "ibs_signature_id",
                "limit": "1",
            },
        )
        if response.status_code == 200:
            data = response.json()
            if data and data[0].get("ibs_signature_id"):
                return data[0]["ibs_signature_id"]
    return None


async def get_policy_rules(org_id: str) -> list:
    """Fetch all enabled policy rules for an org, ordered by priority."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(
            f"{SUPABASE_REST}/policy_rules",
            headers=SUPABASE_HEADERS,
            params={
                "org_id": f"eq.{org_id}",
                "is_enabled": "eq.true",
                "order": "priority.asc",
            },
        )
        if response.status_code == 200:
            return response.json()
        return []


async def get_provider_trust(provider: str, org_id: str) -> dict | None:
    """Fetch provider trust posture for a given provider name."""
    if not provider:
        return None
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(
            f"{SUPABASE_REST}/llm_providers",
            headers=SUPABASE_HEADERS,
            params={
                "org_id": f"eq.{org_id}",
                "provider": f"eq.{provider}",
                "limit": "1",
            },
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else None
        return None
