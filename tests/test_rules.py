from pathlib import Path

import yaml

from hunter_org_attribution.rules.loader import load_rules


ROOT = Path(__file__).parents[1]
RULE_PATHS = [ROOT / "rules" / name for name in ("categories.yaml", "organization_patterns.yaml", "domain_patterns.yaml")]


def test_all_migrated_rules_have_required_records():
    rules = load_rules(RULE_PATHS)
    assert rules
    for rule in rules:
        assert {"rule_id", "target", "field", "operator", "pattern", "source", "notes"} <= set(rule)
        assert rule["source"] == "LENS-20260602"


def test_lens_migration_inventory_count_is_frozen():
    rules = load_rules(RULE_PATHS)
    executable = [rule for rule in rules if rule.get("executable", True)]
    unsupported = [rule for rule in rules if not rule.get("executable", True)]
    assert len(rules) == 15
    assert len(executable) == 12
    assert len(unsupported) == 3


def test_unsupported_lens_fields_are_documented_and_not_executable():
    payload = yaml.safe_load((ROOT / "rules" / "categories.yaml").read_text(encoding="utf-8"))
    unsupported = [rule for rule in payload["rules"] if not rule.get("executable", True)]
    assert {rule["field"] for rule in unsupported} == {"fofa_body", "fofa_server", "fofa_app"}


def test_field_mapping_does_not_invent_hunter_fields():
    payload = yaml.safe_load((ROOT / "rules" / "field_mapping.yaml").read_text(encoding="utf-8"))
    mappings = {row["lens_field"]: row for row in payload["mappings"]}
    assert mappings["org"]["hunter_field"] == "asn_organization"
    assert mappings["org"]["status"] == "supported_with_semantic_narrowing"
    for field in ("body", "server", "app"):
        assert mappings[field]["hunter_field"] is None
        assert mappings[field]["status"] == "unsupported"
