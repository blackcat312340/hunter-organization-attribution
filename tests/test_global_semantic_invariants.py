"""Phase 5 semantic invariants.

Each test pins one invariant that must hold regardless of how the global
authorities are composed. These are the properties the Phase 5 report re-verifies
against real authority data.
"""

from pathlib import Path

from hunter_org_attribution import (
    ROR_NAMESPACE,
    AttributionEngine,
    project_measurement212_hunter_record,
    load_caida_as2org_authority_from_text,
    load_cisa_dotgov_authority,
    load_ror_domain_authority,
    normalize_hunter_record,
)
from hunter_org_attribution.provenance import LoadedAuthority, sha256_file


GLOBAL = Path(__file__).parent / "fixtures" / "global"
CAIDA_FIXTURE = GLOBAL / "caida_as2org_minimal.txt"
CISA_FIXTURE = GLOBAL / "cisa_dotgov_minimal.csv"
ROR_FIXTURE = GLOBAL / "ror_v2_minimal.json"


def global_engine() -> AttributionEngine:
    return AttributionEngine.from_repository_defaults(
        authorities=[
            load_cisa_dotgov_authority(CISA_FIXTURE, expected_sha256=sha256_file(CISA_FIXTURE)),
            load_ror_domain_authority(ROR_FIXTURE, expected_sha256=sha256_file(ROR_FIXTURE)),
        ],
        asn_organization_authorities=[
            load_caida_as2org_authority_from_text(
                CAIDA_FIXTURE.read_text(encoding="utf-8"),
                sha256=sha256_file(CAIDA_FIXTURE),
                version="202601",
            )
        ],
    )


def attribute(**values):
    return global_engine().attribute(normalize_hunter_record({"ip": "203.0.113.9", **values}))


# 1. CAIDA as2org never creates organization identity.
def test_invariant_caida_never_creates_identity():
    for asn in (64500, 64501, 64502, 64503, 64506, 64507):
        result = attribute(asn=asn)
        assert result.resolution.organization_name is None
        assert result.resolution.organization_id is None
        assert result.resolution.status in {"category_only", "unresolved"}


# 2. CISA creates identity only via a matching domain.
def test_invariant_cisa_identity_requires_a_matching_domain():
    assert attribute(domain="exampleagency.gov").resolution.organization_name == "Example Federal Agency"
    assert attribute(domain="unregistered.gov").resolution.organization_name is None
    assert attribute(root_domain="exampleagency.gov.evil.example").resolution.organization_name is None


# 3. ROR creates identity only via a source-provided domain.
def test_invariant_ror_identity_requires_a_source_provided_domain():
    assert attribute(domain="example-institute.edu").resolution.organization_name == "Example Institute of Technology"
    assert attribute(domain="not-in-the-dump.edu").resolution.organization_name is None


# 4. ROR empty domains create nothing.
def test_invariant_ror_empty_domains_create_nothing():
    result = attribute(domain="domainless.example.org")
    assert result.resolution.organization_name is None
    assert result.evidence == ()


# 5. Ambiguous ROR domain creates nothing.
def test_invariant_ambiguous_ror_domain_creates_nothing():
    result = attribute(domain="shared.example.net")
    assert result.resolution.organization_name is None
    assert result.evidence == ()


# 6. Network organization text may create category evidence.
def test_invariant_network_text_may_create_category_evidence():
    result = attribute(asn=64500)
    assert result.resolution.status == "category_only"
    assert "education_research" in result.resolution.categories


# 7. Cloud/ISP network text stays infrastructure, never hosted identity.
def test_invariant_cloud_and_isp_text_stays_infrastructure():
    for asn, category in ((64502, "cloud_vendor"), (64503, "isp_carrier")):
        result = attribute(asn=asn)
        assert result.resolution.organization_name is None
        assert category in result.resolution.infrastructure_categories
        assert category not in result.resolution.categories


# 8. Country remains non-inference metadata.
def test_invariant_country_is_not_inferred_into_category_or_identity():
    result = attribute(asn=64500, hunter_reported_country="CN")
    assert result.resolution.organization_name is None
    assert "government" not in result.resolution.categories
    assert all("country" not in evidence.matched_field for evidence in result.evidence)


# 9. Organization / category / infrastructure remain orthogonal.
def test_invariant_three_layers_stay_orthogonal():
    result = attribute(domain="example.edu", asn=64502)
    assert result.resolution.organization_name == "Example Research University"
    assert "education_research" in result.resolution.categories
    assert "cloud_vendor" in result.resolution.infrastructure_categories
    assert "cloud_vendor" not in result.resolution.categories
    assert "education_research" not in result.resolution.infrastructure_categories


# 10. multi_rule counts only direct identity evidence.
def test_invariant_multi_rule_counts_only_identity_evidence():
    result = attribute(domain="example.edu", asn=64500)
    assert result.resolution.agreement_status == "single_identity_evidence"
    assert "multi_rule" not in result.resolution.association_types
    assert any(e.rule_family == "asn_org_regex" for e in result.evidence)


# 11. Conflict retains all identity evidence.
def test_invariant_conflict_retains_all_identity_evidence():
    engine = AttributionEngine(
        authorities=[
            LoadedAuthority(
                "domains", "authority-a", "a" * 64,
                ({"rule_id": "a", "domain": "x.example", "organization": "Organization A"},),
                {"schema": "domains", "source": "authority-a"},
            ),
            LoadedAuthority(
                "domains", "authority-b", "b" * 64,
                ({"rule_id": "b", "domain": "x.example", "organization": "Organization B"},),
                {"schema": "domains", "source": "authority-b"},
            ),
        ]
    )
    result = engine.attribute(normalize_hunter_record({"ip": "203.0.113.9", "domain": "x.example"}))
    assert result.resolution.status == "conflict"
    assert {e.resolved_organization for e in result.evidence} == {"Organization A", "Organization B"}


# 12. ASN infrastructure enrichment still does not fabricate asn_organization.
def test_invariant_asn_infrastructure_lookup_does_not_fabricate_asn_organization():
    engine = AttributionEngine.from_repository_defaults(
        asn_organization_authorities=[
            load_caida_as2org_authority_from_text(
                CAIDA_FIXTURE.read_text(encoding="utf-8"), sha256=sha256_file(CAIDA_FIXTURE), version="202601"
            )
        ]
    )
    projection = project_measurement212_hunter_record(
        {"ip": "192.0.2.44", "asn": "64502"},
        asn_enrichment={"asn": "64502", "asn_category": "cloud_hyperscaler", "provider_family": "Example Cloud"},
    )
    # The infrastructure lookup contributes infrastructure_category/provider_family only.
    assert projection.record.infrastructure_category == "cloud_hyperscaler"
    assert projection.record.provider_family == "Example Cloud"
    assert projection.record.asn_organization is None

    result = engine.attribute(projection.record)
    # asn_organization is then sourced from CAIDA, not from the lookup.
    assert result.record.asn_organization == "Amazon.com, Inc."


# 13. CAIDA is the source of asn_organization when enriched.
def test_invariant_caida_is_the_asn_organization_source_when_enriched():
    result = attribute(asn=64500)
    assert result.record.asn_organization == "Example University"
    evidence = next(e for e in result.evidence if e.rule_family == "asn_org_regex")
    block = evidence.provenance["asn_organization_enrichment"]
    assert block["source"] == "caida_as2org"
    assert block["origin"] == "enrichment"
    assert block["asn"] == 64500


# 14. Source-specific identifiers remain namespace-separated.
def test_invariant_source_identifiers_stay_namespace_separated():
    ror_result = attribute(domain="example.edu")
    caida_result = attribute(asn=64500)
    caida_block = next(
        e for e in caida_result.evidence if e.rule_family == "asn_org_regex"
    ).provenance["asn_organization_enrichment"]

    assert ror_result.resolution.organization_id.startswith(f"{ROR_NAMESPACE}:")
    assert caida_block["network_organization_id_namespace"] == "caida-as2org"
    # A CAIDA handle is never presented as an organization_id.
    assert caida_block["network_organization_id"] not in {
        evidence.resolved_organization_id for evidence in caida_result.evidence
    }
