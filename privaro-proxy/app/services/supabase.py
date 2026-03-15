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
