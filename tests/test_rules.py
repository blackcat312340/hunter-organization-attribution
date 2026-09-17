from pathlib import Path

import yaml

from hunter_org_attribution.rules.loader import load_rules


ROOT = Path(__file__).parents[1]


def test_all_migrated_rules_have_required_records():
    paths = [ROOT / "rules" / name for name in ("categories.yaml", "organization_patterns.yaml", "domain_patterns.yaml")]
    rules = load_rules(paths)
    assert rules
    for rule in rules:
        assert {"rule_id", "target", "field", "operator", "pattern", "source", "notes"} <= set(rule)
        assert rule["source"] == "LENS-20260602"


def test_unsupported_lens_fields_are_documented_and_not_executable():
    payload = yaml.safe_load((ROOT / "rules" / "categories.yaml").read_text(encoding="utf-8"))
    unsupported = [rule for rule in payload["rules"] if not rule.get("executable", True)]
    assert {rule["field"] for rule in unsupported} == {"fofa_body", "fofa_server", "fofa_app"}

