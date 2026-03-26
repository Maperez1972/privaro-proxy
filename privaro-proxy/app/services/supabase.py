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


async def get_policy_rules(org_id: str, pipeline_id: str | None = None) -> list:
    """
    Fetch effective policy rules with 3-level scope resolution.

    Level 1 — Pipeline rules (scope='pipeline'):
        Specific to this pipeline. Evaluated first (priority as-is).
        If overrides_org=True, suppresses the org rule for the same entity_type.

    Level 2 — Org rules (scope='org', pipeline_id IS NULL):
        Apply to all pipelines as fallback.
        Suppressed per-entity when pipeline has overrides_org=True for that entity.
        Otherwise additive: both pipeline + org rules run (pipeline wins on conflict).

    Level 3 — Effective priority:
        Pipeline rules: priority as defined.
        Org fallback rules: priority + 1000 (always evaluated after pipeline rules).

    Returns merged list sorted by effective_priority ascending.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        pipeline_rules = []
        overridden_entities: set = set()

        if pipeline_id:
            r_pipe = await client.get(
                f"{SUPABASE_REST}/policy_rules",
                headers=SUPABASE_HEADERS,
                params={
                    "org_id": f"eq.{org_id}",
                    "pipeline_id": f"eq.{pipeline_id}",
                    "is_enabled": "eq.true",
                    "order": "priority.asc",
                },
            )
            if r_pipe.status_code == 200:
                pipeline_rules = r_pipe.json()

            # Entity types where pipeline rule explicitly overrides org rule
            overridden_entities = {
                r["entity_type"]
                for r in pipeline_rules
                if r.get("overrides_org", False)
            }

        # Always fetch org-level rules as fallback
        r_org = await client.get(
            f"{SUPABASE_REST}/policy_rules",
            headers=SUPABASE_HEADERS,
            params={
                "org_id": f"eq.{org_id}",
                "pipeline_id": "is.null",
                "is_enabled": "eq.true",
                "order": "priority.asc",
            },
        )
        org_rules = r_org.json() if r_org.status_code == 200 else []

        # Suppress org rules where pipeline has explicit override
        filtered_org = [
            r for r in org_rules
            if r["entity_type"] not in overridden_entities
        ]

        # Tag effective priority before merging
        for r in pipeline_rules:
            r["_effective_priority"] = r["priority"]
            r["_source"] = "pipeline"
        for r in filtered_org:
            r["_effective_priority"] = r["priority"] + 1000
            r["_source"] = "org"

        merged = sorted(
            pipeline_rules + filtered_org,
            key=lambda r: (r["_effective_priority"], r["entity_type"])
        )

        print(
            f"[PolicyEngine] org={org_id[:8]} pipeline={str(pipeline_id)[:8] if pipeline_id else 'None'} "
            f"→ {len(pipeline_rules)} pipeline + {len(filtered_org)} org rules "
            f"({len(overridden_entities)} entities suppressed)"
        )
        return merged


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


async def insert_tokens_batch(rows: list) -> bool:
    """Insert multiple tokens in tokens_vault in one call."""
    if not rows:
        return True
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            f"{SUPABASE_REST}/tokens_vault",
            headers=SUPABASE_HEADERS,
            json=rows,
        )
        if response.status_code not in (200, 201):
            print(f"[Vault] INSERT tokens failed: {response.status_code} {response.text[:200]}")
        return response.status_code in (200, 201)


async def update_vault_access_log_ibs(
    evidence_id: str,
    certification_hash: str,
    network: str,
) -> bool:
    """Update vault_access_log with certification_hash when iBS webhook arrives."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.patch(
            f"{SUPABASE_REST}/vault_access_log",
            headers=SUPABASE_HEADERS,
            params={"ibs_evidence_id": f"eq.{evidence_id}"},
            json={
                "ibs_certification_hash": certification_hash,
                "ibs_network": network,
            },
        )
        return response.status_code in (200, 201, 204)


async def find_existing_token(
    org_id: str,
    conversation_id: str,
    entity_type: str,
    encrypted_value: str,
) -> dict | None:
    """
    Look up an existing token for the same encrypted value within a conversation.
    Enables token consistency: same PII = same token within a conversation.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(
            f"{SUPABASE_REST}/tokens_vault",
            headers=SUPABASE_HEADERS,
            params={
                "org_id": f"eq.{org_id}",
                "conversation_id": f"eq.{conversation_id}",
                "entity_type": f"eq.{entity_type}",
                "encrypted_original": f"eq.{encrypted_value}",
                "is_reversible": "eq.true",
                "limit": "1",
                "select": "id,token_value",
            },
        )
        if response.status_code == 200:
            data = response.json()
            return data[0] if data else None
        return None


async def create_pipeline_policy_rule(payload: Dict[str, Any]) -> Optional[str]:
    """
    Insert a pipeline-scoped policy rule.
    payload must include: org_id, pipeline_id, entity_type, action, category, scope='pipeline'
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(
            f"{SUPABASE_REST}/policy_rules",
            headers=SUPABASE_HEADERS,
            json={**payload, "scope": "pipeline"},
        )
        if response.status_code in (200, 201):
            data = response.json()
            return data[0]["id"] if data else None
        print(f"[Supabase] policy_rule INSERT failed: {response.status_code} {response.text[:200]}")
        return None


async def apply_preset_to_pipeline(
    org_id: str,
    pipeline_id: str,
    preset_sector: str,
    updated_by: str,
) -> int:
    """
    Copy all policy_rules from a policy_preset sector template
    and create pipeline-scoped versions for the given pipeline.
    Deletes any existing pipeline-scoped rules for this pipeline first.
    Returns count of rules created.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        # 1. Delete existing pipeline-scoped rules for this pipeline
        await client.delete(
            f"{SUPABASE_REST}/policy_rules",
            headers=SUPABASE_HEADERS,
            params={
                "pipeline_id": f"eq.{pipeline_id}",
                "org_id": f"eq.{org_id}",
            },
        )

        # 2. Fetch preset template rules from policy_presets
        r = await client.get(
            f"{SUPABASE_REST}/policy_presets",
            headers=SUPABASE_HEADERS,
            params={
                "sector": f"eq.{preset_sector}",
                "select": "rules",
                "limit": "1",
            },
        )
        if r.status_code != 200 or not r.json():
            return 0

        preset = r.json()[0]
        rules_template = preset.get("rules") or []

        if not rules_template:
            return 0

        # 3. Build pipeline-scoped rule rows from template
        new_rules = [
            {
                "org_id": org_id,
                "pipeline_id": pipeline_id,
                "scope": "pipeline",
                "entity_type": rule.get("entity_type"),
                "category": rule.get("category", "personal"),
                "action": rule.get("action", "tokenise"),
                "is_enabled": True,
                "priority": rule.get("priority", 100),
                "regulation_ref": rule.get("regulation_ref"),
                "applies_to_providers": rule.get("applies_to_providers", ["all"]),
                "applies_to_roles": rule.get("applies_to_roles", ["all"]),
                "overrides_org": rule.get("overrides_org", False),
                "updated_by": updated_by,
            }
            for rule in rules_template
            if rule.get("entity_type")
        ]

        if not new_rules:
            return 0

        # 4. Bulk insert
        r2 = await client.post(
            f"{SUPABASE_REST}/policy_rules",
            headers=SUPABASE_HEADERS,
            json=new_rules,
        )
        if r2.status_code in (200, 201):
            created = r2.json()
            return len(created)
        return 0


# ── Agent API DB functions ─────────────────────────────────────────────────────

async def create_agent_run(
    org_id: str,
    pipeline_id: str,
    api_key_id: Optional[str],
    agent_name: Optional[str],
    agent_framework: Optional[str],
    external_run_id: Optional[str],
    metadata: dict,
) -> Optional[str]:
    """Create a new agent_run row. Returns the run UUID."""
    payload = {
        "org_id": org_id,
        "pipeline_id": pipeline_id,
        "status": "running",
        "metadata": metadata,
    }
    if api_key_id:  payload["api_key_id"]     = api_key_id
    if agent_name:  payload["agent_name"]      = agent_name
    if agent_framework: payload["agent_framework"] = agent_framework
    if external_run_id: payload["external_run_id"] = external_run_id

    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(
            f"{SUPABASE_REST}/agent_runs",
            headers=SUPABASE_HEADERS,
            json=payload,
        )
        if r.status_code in (200, 201):
            data = r.json()
            return data[0]["id"] if data else None
        print(f"[Supabase] create_agent_run failed: {r.status_code} {r.text[:200]}")
        return None


async def get_agent_run(run_id: str, org_id: str) -> Optional[Dict[str, Any]]:
    """Fetch an agent_run by ID, verified against org_id."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(
            f"{SUPABASE_REST}/agent_runs",
            headers=SUPABASE_HEADERS,
            params={
                "id": f"eq.{run_id}",
                "org_id": f"eq.{org_id}",
                "limit": "1",
            },
        )
        if r.status_code == 200:
            data = r.json()
            return data[0] if data else None
        return None


async def create_agent_step(
    agent_run_id: str,
    org_id: str,
    step_index: int,
    role: str,
    step_type: str,
    prompt_hash: Optional[str],
    pii_detected: int,
    pii_masked: int,
    risk_score: float,
    gdpr_compliant: bool,
    processing_ms: int,
) -> Optional[str]:
    """Insert an agent_step. Returns step UUID."""
    payload = {
        "agent_run_id": agent_run_id,
        "org_id": org_id,
        "step_index": step_index,
        "role": role,
        "step_type": step_type,
        "pii_detected": pii_detected,
        "pii_masked": pii_masked,
        "risk_score": risk_score,
        "gdpr_compliant": gdpr_compliant,
        "processing_ms": processing_ms,
    }
    if prompt_hash: payload["prompt_hash"] = prompt_hash

    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(
            f"{SUPABASE_REST}/agent_steps",
            headers=SUPABASE_HEADERS,
            json=payload,
        )
        if r.status_code in (200, 201):
            data = r.json()
            return data[0]["id"] if data else None
        print(f"[Supabase] create_agent_step failed: {r.status_code} {r.text[:200]}")
        return None


async def get_agent_run_token_map(agent_run_id: str, org_id: str) -> dict:
    """
    Returns {token_value: original_value} for all reversible tokens in the run.
    Used by /agent/reveal to detokenise final output.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(
            f"{settings.SUPABASE_URL}/rest/v1/rpc/get_agent_run_tokens",
            headers=SUPABASE_HEADERS,
            json={"p_agent_run_id": agent_run_id, "p_org_id": org_id},
        )
        if r.status_code == 200:
            rows = r.json()
            # token_value → encrypted_original (proxy decrypts on reveal)
            # For now return token_value → token_value as placeholder
            # Full decrypt requires ENCRYPTION_KEY — handled in reveal endpoint
            return {row["token_value"]: row["token_value"] for row in rows if row.get("token_value")}
        return {}


async def close_agent_run(run_id: str, status: str = "completed") -> bool:
    """Call close_agent_run RPC to finalise counters and set status."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(
            f"{settings.SUPABASE_URL}/rest/v1/rpc/close_agent_run",
            headers=SUPABASE_HEADERS,
            json={"p_run_id": run_id, "p_status": status},
        )
        return r.status_code in (200, 201, 204)


async def find_existing_agent_token(
    agent_run_id: str,
    entity_type: str,
    encrypted_value: str,
) -> Optional[dict]:
    """
    Look up existing token in agent run scope.
    Same PII → same token within a run (consistency guarantee).
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(
            f"{settings.SUPABASE_URL}/rest/v1/rpc/find_agent_token",
            headers=SUPABASE_HEADERS,
            json={
                "p_agent_run_id": agent_run_id,
                "p_entity_type": entity_type,
                "p_encrypted_val": encrypted_value,
            },
        )
        if r.status_code == 200:
            data = r.json()
            return data[0] if data else None
        return None

async def get_agent_run_vault_rows(agent_run_id: str, org_id: str) -> list:
    """
    Fetch all reversible vault rows for an agent run.
    Returns raw rows with token_value + encrypted_original for decryption.
    Used by /agent/reveal to detokenise final output.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(
            f"{SUPABASE_REST}/tokens_vault",
            headers=SUPABASE_HEADERS,
            params={
                "agent_run_id": f"eq.{agent_run_id}",
                "org_id": f"eq.{org_id}",
                "is_reversible": "eq.true",
                "select": "token_value,encrypted_original,entity_type",
            },
        )
        if r.status_code == 200:
            return r.json()
        print(f"[Supabase] get_agent_run_vault_rows failed: {r.status_code} {r.text[:200]}")
        return []

async def update_audit_logs_batch_hash(
    evidence_id: str,
    certification_hash: str,
    network: str,
    certified_at: Optional[str],
) -> bool:
    """
    Update ALL audit_logs that share this batch evidence_id with the TX hash.
    Called when iBS webhook arrives for a batch certification.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.patch(
            f"{SUPABASE_REST}/audit_logs",
            headers=SUPABASE_HEADERS,
            params={"ibs_evidence_id": f"eq.{evidence_id}"},
            json={
                "ibs_certification_hash": certification_hash,
                "ibs_network": network,
                "ibs_certified_at": certified_at,
            },
        )
        return response.status_code in (200, 201, 204)


async def update_agent_runs_ibs_hash(
    evidence_id: str,
    certification_hash: str,
    network: str,
    certified_at: Optional[str],
) -> int:
    """
    Update agent_runs that were certified in this batch with the TX hash.
    Returns number of rows updated.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.patch(
            f"{SUPABASE_REST}/agent_runs",
            headers={**SUPABASE_HEADERS, "Prefer": "return=representation"},
            params={"ibs_evidence_id": f"eq.{evidence_id}"},
            json={
                "ibs_certification_hash": certification_hash,
                "ibs_network": network,
                "ibs_certified_at": certified_at,
            },
        )
        if response.status_code in (200, 201, 204):
            data = response.json()
            return len(data) if isinstance(data, list) else 0
        return 0


async def update_ibs_batch_certified(
    evidence_id: str,
    certification_hash: str,
    network: str,
) -> bool:
    """Mark an ibs_batch as certified when webhook arrives."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.patch(
            f"{SUPABASE_REST}/ibs_batches",
            headers=SUPABASE_HEADERS,
            params={"evidence_id": f"eq.{evidence_id}"},
            json={
                "status": "certified",
                "certified_at": "now()",
            },
        )
        return response.status_code in (200, 201, 204)

async def increment_encryption_key_usage(key_id: str, count: int = 1) -> None:
    """
    Increment tokens_encrypted counter on encryption_keys table.
    Fire-and-forget — non-critical, never breaks a request.
    """
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{settings.SUPABASE_URL}/rest/v1/rpc/increment_key_usage",
                headers={
                    "apikey": settings.SUPABASE_SERVICE_KEY,
                    "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                    "Content-Type": "application/json",
                },
                json={"p_key_id": key_id, "p_count": count},
            )
    except Exception:
        pass  # Non-critical — never fail a request over usage tracking
