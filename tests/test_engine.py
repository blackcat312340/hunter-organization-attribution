from hunter_org_attribution import AttributionEngine, normalize_hunter_record
from hunter_org_attribution.export import to_json
from hunter_org_attribution.provenance import LoadedAuthority


def attr(engine, **values):
    return engine.attribute(normalize_hunter_record({"ip": "203.0.113.9", **values}))


def test_direct_institutional_range_match(engine):
    result = attr(engine, ip="192.0.2.50")
    assert result.resolution.organization == "Example University"
    assert "direct_range" in result.resolution.evidence_types


def test_domain_organization_match(engine):
    result = attr(engine, domain="lab.example.edu")
    assert result.resolution.organization == "Example University"
    assert any(e.rule_type == "official_domain" for e in result.evidence)


def test_specific_official_subdomain_is_not_lost_when_root_domain_differs():
    authority = LoadedAuthority(
        authority_type="domains",
        source="synthetic-specific-domain",
        sha256="1" * 64,
        rows=({
            "rule_id": "test.domain.lab",
            "domain": "lab.example.edu",
            "organization": "Example Research Lab",
        },),
        audit={"schema": "domains", "source": "synthetic-specific-domain"},
    )
    local_engine = AttributionEngine(authorities=(authority,))
    result = local_engine.attribute(normalize_hunter_record({
        "ip": "203.0.113.10",
        "domain": "service.lab.example.edu",
        "root_domain": "example.edu",
    }))
    assert result.resolution.organization == "Example Research Lab"
    evidence = next(e for e in result.evidence if e.rule_id == "test.domain.lab")
    assert evidence.matched_field == "domain"
    assert evidence.pattern == "lab.example.edu"


def test_asn_organization_match(engine):
    result = attr(engine, asn=64510, asn_organization="Example University")
    assert result.resolution.organization == "Example University"
    assert "organization_asn" in result.resolution.evidence_types


def test_education_research_regex_classification(engine):
    result = attr(engine, web_title="National Academy of Sciences Research Portal")
    assert result.resolution.status == "category_only"
    assert result.resolution.organization is None
    assert "education_research" in result.resolution.categories


def test_generic_aws_plus_university_domain(engine):
    result = attr(
        engine,
        domain="lab.example.edu",
        asn=64512,
        asn_organization="Amazon.com, Inc.",
    )
    assert result.resolution.organization == "Example University"
    assert "Amazon Web Services" in result.resolution.infrastructure_organizations
    assert "Amazon Web Services" not in result.resolution.conflicting_organizations


def test_institution_range_plus_education_network_asn(engine):
    result = attr(
        engine,
        ip="192.0.2.50",
        asn=64511,
        asn_organization="China Education and Research Network CERNET",
    )
    assert result.resolution.organization == "Example University"
    assert "CERNET" in result.resolution.infrastructure_organizations


def test_category_only_does_not_invent_identity(engine):
    result = attr(engine, asn_organization="Some University Research Network")
    assert result.resolution.status == "category_only"
    assert result.resolution.organization is None


def test_multiple_nonidentity_matches_do_not_claim_multi_rule_identity_agreement(engine):
    result = attr(
        engine,
        web_title="Example University Portal",
        asn_organization="Amazon.com, Inc.",
    )
    assert result.resolution.status == "category_only"
    assert len(result.evidence) >= 2
    assert result.resolution.agreement_status == "not_applicable"
    assert "multi_rule" not in result.resolution.association_types


def test_conflicting_organization_rules_are_explicit(engine):
    result = attr(engine, ip="198.51.100.5", domain="service.other.edu")
    assert result.resolution.status == "conflict"
    assert result.resolution.organization is None
    assert result.resolution.conflicting_organizations == ("Conflicting Institute", "Other University")
    assert len(result.evidence) >= 2
    assert "multi_rule" not in result.resolution.association_types


def test_overlapping_ranges_preserve_all_conflicting_identity_evidence():
    authority = LoadedAuthority(
        authority_type="ipv4_ranges",
        source="synthetic-overlap",
        sha256="2" * 64,
        rows=(
            {
                "rule_id": "test.range.a",
                "start_ip": "192.0.2.0",
                "end_ip": "192.0.2.100",
                "organization": "Organization A",
            },
            {
                "rule_id": "test.range.b",
                "start_ip": "192.0.2.50",
                "end_ip": "192.0.2.150",
                "organization": "Organization B",
            },
        ),
        audit={"schema": "ipv4_ranges", "source": "synthetic-overlap"},
    )
    local_engine = AttributionEngine(authorities=(authority,))
    result = local_engine.attribute(normalize_hunter_record({"ip": "192.0.2.75"}))
    assert result.resolution.status == "conflict"
    assert result.resolution.conflicting_organizations == ("Organization A", "Organization B")
    assert {e.rule_id for e in result.evidence} == {"test.range.a", "test.range.b"}


def test_multi_rule_agreement_preserves_all_matches(engine):
    result = attr(
        engine,
        ip="192.0.2.10",
        domain="lab.example.edu",
        asn=64510,
        asn_organization="Example University",
    )
    assert result.resolution.status == "resolved"
    assert result.resolution.organization == "Example University"
    assert "multi_rule" in result.resolution.evidence_types
    identity_evidence = [e for e in result.evidence if e.resolved_organization]
    assert {e.rule_type for e in identity_evidence} == {
        "direct_range", "exact_ip_mapping", "official_domain", "organization_asn"
    }


def test_evidence_preserves_mandatory_fields(engine):
    result = attr(engine, domain="lab.example.edu")
    evidence = next(e for e in result.evidence if e.rule_type == "official_domain")
    assert evidence.rule_id
    assert evidence.rule_type
    assert evidence.matched_field
    assert evidence.observed_value
    assert evidence.matched_pattern
    assert evidence.authority
    assert evidence.resolved_organization == "Example University"
    assert evidence.resolved_category == "education_research"


def test_deterministic_outputs(engine):
    record = normalize_hunter_record({
        "ip": "192.0.2.10",
        "domain": "lab.example.edu",
        "title": "Example University",
        "asn": 64512,
        "asn_org": "Amazon.com, Inc.",
    })
    first = to_json(engine.attribute(record))
    for _ in range(10):
        assert to_json(engine.attribute(record)) == first
