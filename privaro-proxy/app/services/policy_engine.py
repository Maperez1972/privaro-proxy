"""
Contextual Policy Engine — Phase 7b
Evaluates policy rules against a multi-dimensional context:
  entity_type × provider × user_role × pipeline_sector × region × agent_mode

Returns the resolved action for each detection.
"""
from typing import List, Dict, Any, Optional
from app.models.schemas import Detection


# ── Entity weights for risk scoring ──────────────────────────────────────────
ENTITY_RISK_WEIGHTS = {
    "health_record":  1.0,
    "dni":            0.9,
    "nie":            0.9,
    "ssn":            0.9,
    "iban":           0.9,
    "credit_card":    0.9,
    "full_name":      0.6,
    "date_of_birth":  0.6,
    "email":          0.5,
    "phone":          0.4,
    "ip_address":     0.3,
}

PROVIDER_RISK_FACTORS = {
    "low":    0.0,
    "medium": 0.1,
    "high":   0.2,
}

# ── Action priority (higher = more restrictive) ───────────────────────────────
ACTION_PRIORITY = {
    "block":                 100,
    "anonymise_irreversible": 80,
    "anonymise":              60,
    "pseudonymise":           40,
    "tokenise":               20,
    "passed":                  0,
}


def _matches_context(rule: Dict, context: Dict) -> bool:
    """
    Returns True if the rule applies to the given context.
    Supports wildcard 'all' in array fields.
    """
    # Provider match
    providers = rule.get("applies_to_providers") or ["all"]
    provider = context.get("provider", "")
    if "all" not in providers and provider not in providers:
        return False

    # Role match
    roles = rule.get("applies_to_roles") or ["all"]
    role = context.get("user_role", "viewer")
    if "all" not in roles and role not in roles:
        return False

    # Region match
    regions = rule.get("applies_to_regions") or ["all"]
    region = context.get("data_region", "EU")
    if "all" not in regions and region not in regions:
        return False

    # Agent mode match
    if rule.get("agent_mode_only") and not context.get("agent_mode", False):
        return False

    # Category match (if rule has category, entity must match)
    rule_category = rule.get("category")
    entity_category = context.get("entity_category", "personal")
    if rule_category and rule_category != "all" and rule_category != entity_category:
        return False

    return True


def evaluate_policies(
    detection: Detection,
    policies: List[Dict],
    context: Dict,
) -> tuple[str, str | None, bool]:
    """
    Evaluate all matching policies for a detection.
    Returns (resolved_action, regulation_ref, requires_approval).

    Priority: higher priority rules win. Among same priority, more
    restrictive action wins.
    """
    entity_type = detection.type
    entity_category = _get_category(entity_type)

    detection_context = {
        **context,
        "entity_type": entity_type,
        "entity_category": entity_category,
    }

    # Filter enabled rules for this entity type
    matching_rules = [
        r for r in policies
        if r.get("is_enabled", True)
        and r.get("entity_type") == entity_type
        and _matches_context(r, detection_context)
    ]

    if not matching_rules:
        # No specific rule — use default from mode
        return context.get("default_action", "tokenise"), None, False

    # Sort by priority (lower number = higher priority), then by action restrictiveness
    matching_rules.sort(
        key=lambda r: (r.get("priority", 100), -ACTION_PRIORITY.get(r.get("action", "tokenise"), 0))
    )

    # Take the highest priority rule
    best_rule = matching_rules[0]
    action = best_rule.get("action", "tokenise")
    regulation_ref = best_rule.get("regulation_ref")
    requires_approval = best_rule.get("requires_approval", False)

    return action, regulation_ref, requires_approval


def apply_policies(
    detections: List[Detection],
    policies: List[Dict],
    context: Dict,
) -> List[Detection]:
    """
    Apply contextual policies to all detections.
    Mutates detection.action in place based on policy evaluation.
    Returns the updated detections list.
    """
    for detection in detections:
        action, regulation_ref, requires_approval = evaluate_policies(
            detection, policies, context
        )

        # Map policy actions to detection actions
        if action == "block":
            detection.action = "blocked"
        elif action in ("anonymise", "anonymise_irreversible"):
            detection.action = "anonymised"
        elif action == "pseudonymise":
            detection.action = "pseudonymised"
        elif action == "tokenise":
            detection.action = "tokenised"
        else:
            detection.action = "tokenised"  # safe default

    return detections


def compute_risk_score(
    detections: List[Detection],
    provider_risk_level: str = "medium",
    agent_mode: bool = False,
    leaked_count: int = 0,
) -> float:
    """
    Compute risk_score (0.0–1.0) for a request.

    Formula:
    risk_score = Σ(entity_weight × confidence) normalized
                 + provider_risk_factor
                 + agent_mode_factor
                 + leaked_penalty
    """
    if not detections:
        return 0.0

    entity_score = sum(
        ENTITY_RISK_WEIGHTS.get(d.type, 0.3) * d.confidence
        for d in detections
    )
    # Normalize entity score: cap at 1.0, scale by number of detections
    entity_normalized = min(1.0, entity_score / max(len(detections), 1))

    provider_factor = PROVIDER_RISK_FACTORS.get(provider_risk_level, 0.1)
    agent_factor = 0.15 if agent_mode else 0.0
    leaked_penalty = min(0.4, leaked_count * 0.15)

    raw = entity_normalized + provider_factor + agent_factor + leaked_penalty
    return round(min(1.0, raw), 4)


def _get_category(entity_type: str) -> str:
    categories = {
        "dni": "personal", "nie": "personal", "ssn": "personal",
        "full_name": "personal", "email": "personal",
        "phone": "personal", "ip_address": "personal", "date_of_birth": "personal",
        "iban": "financial", "credit_card": "financial",
        "health_record": "special",
    }
    return categories.get(entity_type, "personal")
