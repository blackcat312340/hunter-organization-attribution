from pathlib import Path

import yaml

from hunter_org_attribution.rules.loader import load_rules


ROOT = Path(__file__).parents[1]
RULE_PATHS = [ROOT / "rules" / name for name in ("categories.yaml", "organization_patterns.yaml", "domain_patterns.yaml")]
LENS_FILE_SHA = "b4faa14c6a6fe0b0ef6e62c6e3d339d547a5f1cf6348788a85224856426f7e29"
LENS_ARCHIVE_SHA = "0e76e38b27859339f952ae34d49302c8fdd358458a4d5c3b29fbfccc1221f10c"
SOURCE_PATTERNS = {
    "EDU_RESEARCH_PAT": r"cernet|education and research|\.edu\.|university|college|教育|大学|学院|academy of sciences|科学院|cnic-cas|中科院|research network",
    "GOV_PAT": r"gov\.|government|人民政府|ministry|国务院|公安|police",
    "FINANCE_PAT": r"bank|银行|证券|保险|finance|trust co",
    "HEALTH_PAT": r"hospital|医院|health",
    "SOE_PAT": r"state grid|国家电网|petrochina|中石油|sinopec|中石化",
    "CLOUD_PAT": r"alibaba|aliyun|tencent|huawei cloud|baidu|volcano engine|bytedance|ucloud|qingcloud|jd cloud|kingsoft|amazon\.com|google llc|microsoft|digitalocean|ovh|hetzner|cloudflare|linode|vultr",
    "ISP_PAT": r"^chinanet$|^china telecom|^china unicom|^china mobile|^chinanet |chinatelecom|chinamobile|china169|unicom|telecom group|communications group|idc network|province.*network|backbone|comcast|charter|verizon|att |at&t|ntt |kddi|sk broadband|deutsche telekom",
}


def test_all_executable_rules_have_required_records():
    rules = load_rules(RULE_PATHS)
    assert rules
    for rule in rules:
        assert {"rule_id", "target", "field", "operator", "pattern", "source", "notes"} <= set(rule)


def test_source_verified_migration_inventory_count_is_frozen():
    rules = load_rules(RULE_PATHS)
    assert len(rules) == 16
    assert sum(rule["source"] == "LENS-20260602" for rule in rules) == 13
    assert sum(rule["source"] == "method-adaptation" for rule in rules) == 3


def test_exact_lens_source_patterns_are_preserved():
    rules = load_rules(RULE_PATHS)
    lens_rules = [rule for rule in rules if rule["source"] == "LENS-20260602"]
    assert {rule["source_symbol"] for rule in lens_rules} == set(SOURCE_PATTERNS)
    for rule in lens_rules:
        assert rule["pattern"] == SOURCE_PATTERNS[rule["source_symbol"]]
        assert rule["source_path"] == "utils/cn_org_ip_stats.py"
        assert rule["source_sha256"] == LENS_FILE_SHA
        assert rule["archive_sha256"] == LENS_ARCHIVE_SHA


def test_soe_source_family_is_executable_on_org_and_domain():
    rules = load_rules(RULE_PATHS)
    soe = [rule for rule in rules if rule.get("source_symbol") == "SOE_PAT" and rule["source"] == "LENS-20260602"]
    assert {rule["field"] for rule in soe} == {"asn_organization", "domain"}
    assert {rule["resolved_category"] for rule in soe} == {"state_owned_enterprise"}


def test_sensitive_classifier_is_preserved_reference_only():
    payload = yaml.safe_load((ROOT / "rules" / "sensitive_reference.yaml").read_text(encoding="utf-8"))
    assert payload["runtime_status"] == "reference_only"
    assert payload["source"]["file_sha256"] == LENS_FILE_SHA
    assert payload["source"]["archive_sha256"] == LENS_ARCHIVE_SHA
    rules = payload["rules"]
    assert len(rules) == 12
    assert sum(rule["kind"] == "sensitive_rule" for rule in rules) == 10
    assert sum(rule["kind"] == "guard" for rule in rules) == 2
    assert all(rule["executable"] is False for rule in rules)
    assert {rule["label"] for rule in rules if rule["kind"] == "sensitive_rule"} >= {
        "government",
        "state_owned_critical",
        "education_research_sensitive",
    }


def test_field_mapping_does_not_invent_hunter_fields():
    payload = yaml.safe_load((ROOT / "rules" / "field_mapping.yaml").read_text(encoding="utf-8"))
    mappings = {row["lens_field"]: row for row in payload["mappings"]}
    assert mappings["org"]["hunter_field"] == "asn_organization"
    assert mappings["org"]["status"] == "supported_with_semantic_narrowing"
    assert mappings["country"]["hunter_field"] == "hunter_reported_country"
    for field in ("body", "server", "app"):
        assert mappings[field]["hunter_field"] is None
        assert mappings[field]["status"] == "unsupported"
    assert mappings["platform"]["status"] == "deliberately_not_migrated"
