from hunter_org_attribution import AttributionEngine, normalize_hunter_record
from hunter_org_attribution.provenance import LoadedAuthority


def authority(authority_type, rows, source="synthetic-reconciliation", sha="a" * 64):
    return LoadedAuthority(
        authority_type=authority_type,
        source=source,
        sha256=sha,
        rows=tuple(rows),
        audit={"schema": authority_type, "source": source},
    )


def range_authority(organization, organization_id=None, start="192.0.2.0", end="192.0.2.255"):
    row = {"rule_id": "syn.range", "start_ip": start, "end_ip": end, "organization": organization}
    if organization_id:
        row["organization_id"] = organization_id
    return authority("ipv4_ranges", [row])


def exact_authority(organization, organization_id=None, ip="192.0.2.10"):
    row = {"rule_id": "syn.exact", "ip": ip, "organization": organization}
    if organization_id:
        row["organization_id"] = organization_id
    return authority("exact_ip", [row])


def domain_authority(organization, organization_id=None, domain="foo.edu"):
    row = {"rule_id": "syn.domain", "domain": domain, "organization": organization}
    if organization_id:
        row["organization_id"] = organization_id
    return authority("domains", [row])


def engine_with(*authorities):
    return AttributionEngine(authorities=authorities)


def resolve(engine, **values):
    return engine.attribute(normalize_hunter_record({"ip": "192.0.2.10", **values})).resolution


# --------------------------------------------------------------------------
# Explicit reconciliation rules
# --------------------------------------------------------------------------

def test_rule1_same_identifier_and_name_agrees():
    engine = engine_with(range_authority("Foo University", "org-1"), exact_authority("Foo University", "org-1"))
    result = resolve(engine)
    assert result.status == "resolved"
    assert result.organization_id == "org-1"
    assert result.organization_name == "Foo University"
    assert result.agreement_status == "multi_rule_agreement"


def test_rule1_same_identifier_with_different_display_names_agrees():
    engine = engine_with(
        range_authority("Foo University", "org-1"),
        exact_authority("Foo University School", "org-1"),
    )
    result = resolve(engine)
    assert result.status == "resolved"
    assert result.organization_id == "org-1"
    # differing names stay visible per evidence row rather than becoming a conflict
    engine_evidence = engine.attribute(normalize_hunter_record({"ip": "192.0.2.10"})).evidence
    assert {e.resolved_organization for e in engine_evidence} == {"Foo University", "Foo University School"}


def test_rule2_identifier_plus_null_identifier_with_same_name_agrees():
    engine = engine_with(range_authority("Foo University", "org-1"), domain_authority("Foo University"))
    result = resolve(engine, domain="foo.edu")
    assert result.status == "resolved"
    assert result.organization_id == "org-1"
    assert result.organization_name == "Foo University"


def test_rule3_both_null_identifiers_with_same_name_agrees():
    engine = engine_with(range_authority("Foo University"), domain_authority("Foo University"))
    result = resolve(engine, domain="foo.edu")
    assert result.status == "resolved"
    assert result.organization_id is None
    assert result.organization_name == "Foo University"
    assert result.agreement_status == "multi_rule_agreement"


def test_rule4_different_identifiers_do_not_merge_even_with_same_name():
    engine = engine_with(range_authority("Foo University", "org-1"), exact_authority("Foo University", "org-2"))
    result = resolve(engine)
    assert result.status == "conflict"
    assert result.organization_name is None
    assert result.conflicting_organizations == ("Foo University",)


def test_rule4_different_identifiers_and_different_names_conflict():
    engine = engine_with(range_authority("Foo University", "org-1"), exact_authority("Bar Institute", "org-2"))
    result = resolve(engine)
    assert result.status == "conflict"
    assert result.conflicting_organizations == ("Bar Institute", "Foo University")


def test_rule5_identifier_versus_null_identifier_with_different_name_conflicts():
    engine = engine_with(range_authority("Foo University", "org-1"), domain_authority("Bar Institute"))
    result = resolve(engine, domain="foo.edu")
    assert result.status == "conflict"
    assert result.conflicting_organizations == ("Bar Institute", "Foo University")


def test_canonical_name_comparison_ignores_case_and_whitespace():
    engine = engine_with(range_authority("Foo University", "org-1"), domain_authority("  foo   UNIVERSITY "))
    result = resolve(engine, domain="foo.edu")
    assert result.status == "resolved"
    assert result.organization_id == "org-1"


# --------------------------------------------------------------------------
# multi_rule semantics must survive the reconciliation change
# --------------------------------------------------------------------------

def test_range_and_domain_agreement_is_multi_rule():
    engine = engine_with(range_authority("Foo University"), domain_authority("Foo University"))
    result = resolve(engine, domain="foo.edu")
    assert result.status == "resolved"
    assert "multi_rule" in result.association_types
    assert result.agreement_status == "multi_rule_agreement"


def test_range_and_exact_ip_agreement_is_multi_rule():
    engine = engine_with(range_authority("Foo University"), exact_authority("Foo University"))
    result = resolve(engine)
    assert result.status == "resolved"
    assert "multi_rule" in result.association_types


def test_domain_and_exact_ip_agreement_is_multi_rule():
    engine = engine_with(
        exact_authority("Foo University"),
        domain_authority("Foo University"),
    )
    result = resolve(engine, domain="foo.edu")
    assert result.status == "resolved"
    assert "multi_rule" in result.association_types


def test_three_identity_sources_agreeing_is_multi_rule():
    engine = engine_with(
        range_authority("Foo University"),
        exact_authority("Foo University"),
        domain_authority("Foo University"),
    )
    result = resolve(engine, domain="foo.edu")
    assert result.status == "resolved"
    assert result.agreement_status == "multi_rule_agreement"
    assert result.organization_name == "Foo University"


def test_single_identity_evidence_is_not_multi_rule():
    engine = engine_with(range_authority("Foo University"))
    result = resolve(engine)
    assert result.status == "resolved"
    assert result.agreement_status == "single_identity_evidence"
    assert "multi_rule" not in result.association_types


def test_two_identity_sources_disagreeing_conflict_and_preserve_both():
    engine = engine_with(range_authority("Foo University"), domain_authority("Bar Institute"))
    result = resolve(engine, domain="foo.edu")
    assert result.status == "conflict"
    assert result.ambiguity_status == "ambiguous_conflict"
    assert result.agreement_status == "conflict"
    evidence = engine.attribute(normalize_hunter_record({"ip": "192.0.2.10", "domain": "foo.edu"})).evidence
    assert {e.resolved_organization for e in evidence} == {"Foo University", "Bar Institute"}


def test_category_evidence_plus_identity_is_not_multi_rule():
    engine = AttributionEngine.from_repository_defaults([range_authority("Foo University")])
    result = engine.attribute(normalize_hunter_record({
        "ip": "192.0.2.10",
        "asn_organization": "Some University Research Network",
    })).resolution
    assert result.status == "resolved"
    assert result.organization_name == "Foo University"
    assert result.agreement_status == "single_identity_evidence"
    assert "multi_rule" not in result.association_types


def test_infrastructure_evidence_plus_identity_is_not_multi_rule():
    engine = AttributionEngine.from_repository_defaults([range_authority("Foo University")])
    result = engine.attribute(normalize_hunter_record({
        "ip": "192.0.2.10",
        "domain": "assets.cloudflare.com",
    })).resolution
    assert result.status == "resolved"
    assert result.organization_name == "Foo University"
    assert result.agreement_status == "single_identity_evidence"
    assert "multi_rule" not in result.association_types
    assert "cloud_vendor" in result.infrastructure_categories
    assert "cloud_vendor" not in result.categories
