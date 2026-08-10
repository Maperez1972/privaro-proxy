"""
Manual sanity check for the output-direction PII feature — no live server,
no Supabase, no presidio required. Exercises detector.detect() +
policy_engine.apply_policies() directly, exactly as relay.py's
_scan_output_for_pii() and proxy.py's /protect-output do.

Run: python3 test_output_direction.py
"""
import sys
sys.path.insert(0, ".")

from app.services import detector
from app.services import policy_engine as pe

SAMPLE_OUTPUT = (
    "Según nuestros registros, el cliente Juan Perez (DNI 12345678Z) "
    "tiene un IBAN ES91 2100 0418 4502 0005 1332 asociado a su cuenta."
)

print("=" * 70)
print("1. Detector is direction-agnostic (as expected — same function used")
print("   for input and output; direction only affects POLICY, not detection)")
print("=" * 70)
detections = detector.detect(SAMPLE_OUTPUT)
for d in detections:
    print(f"  - {d.type:15s} conf={d.confidence:.2f} span=({d.start},{d.end}) detector={d.detector}")
assert len(detections) >= 2, "expected at least DNI + IBAN detected"
print(f"  -> {len(detections)} entities detected. OK\n")

print("=" * 70)
print("2. A rule authored with direction='input' (or legacy/unset, which the")
print("   migration backfilled to 'input') must NOT fire against an OUTPUT")
print("   context — this is the backward-compatibility guarantee for every")
print("   pre-existing policy_rules row.")
print("=" * 70)
input_only_rule = {
    "entity_type": "dni", "category": "personal", "action": "block",
    "is_enabled": True, "direction": "input", "priority": 10,
}
detections_output_ctx = detector.detect(SAMPLE_OUTPUT)
resolved = pe.apply_policies(
    [d for d in detections_output_ctx if d.type == "dni"],
    [input_only_rule],
    {"provider": "openai", "user_role": "developer", "data_region": "EU",
     "agent_mode": False, "pipeline_sector": "general", "default_action": "tokenise",
     "direction": "output"},
)
assert resolved[0].action == "tokenised", (
    f"expected fallback to default_action 'tokenise' since the input-only rule "
    f"must not match an output context, got {resolved[0].action!r}"
)
print("  -> input-only rule correctly ignored in output context "
      f"(fell back to default_action='tokenise', got action={resolved[0].action!r}). OK\n")

print("=" * 70)
print("3. A rule authored with direction='output' DOES fire for an output")
print("   context, and must ALSO fire for direction='both'.")
print("=" * 70)
output_rule = {
    "entity_type": "dni", "category": "personal", "action": "block",
    "is_enabled": True, "direction": "output", "priority": 10,
}
resolved2 = pe.apply_policies(
    [d for d in detections_output_ctx if d.type == "dni"],
    [output_rule],
    {"provider": "openai", "user_role": "developer", "data_region": "EU",
     "agent_mode": False, "pipeline_sector": "general", "default_action": "tokenise",
     "direction": "output"},
)
assert resolved2[0].action == "blocked", f"expected 'blocked', got {resolved2[0].action!r}"
print(f"  -> output-scoped rule correctly fired (action={resolved2[0].action!r}). OK\n")

both_rule = dict(output_rule, direction="both")
for direction in ("input", "output"):
    d = detector.detect(SAMPLE_OUTPUT)
    d = [x for x in d if x.type == "dni"]
    r = pe.apply_policies(d, [both_rule], {
        "provider": "openai", "user_role": "developer", "data_region": "EU",
        "agent_mode": False, "pipeline_sector": "general", "default_action": "tokenise",
        "direction": direction,
    })
    assert r[0].action == "blocked", f"'both' rule should fire for direction={direction}"
print("  -> 'both'-scoped rule correctly fires for input AND output. OK\n")

print("=" * 70)
print("4. Existing (pre-migration-shape) rules with NO 'direction' key at all")
print("   default to 'input' in the policy engine (matches DB column default)")
print("   and so must be ignored for an output context — simulates a rule")
print("   dict fetched before any code ever wrote a 'direction' field.")
print("=" * 70)
legacy_rule_no_direction_key = {
    "entity_type": "dni", "category": "personal", "action": "block",
    "is_enabled": True, "priority": 10,   # no 'direction' key at all
}
d = detector.detect(SAMPLE_OUTPUT)
d = [x for x in d if x.type == "dni"]
r = pe.apply_policies(d, [legacy_rule_no_direction_key], {
    "provider": "openai", "user_role": "developer", "data_region": "EU",
    "agent_mode": False, "pipeline_sector": "general", "default_action": "tokenise",
    "direction": "output",
})
assert r[0].action == "tokenised", f"expected fallback, got {r[0].action!r}"
print("  -> rule with no 'direction' key treated as 'input', ignored for "
      f"output context (action={r[0].action!r}). OK\n")

print("ALL CHECKS PASSED")
