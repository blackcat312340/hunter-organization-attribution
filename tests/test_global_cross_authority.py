"""Cross-authority composition: identity, category and infrastructure stays orthogonal.

These tests exercise the Phase 3 reconciliation contract against the new Phase 5
authorities. The load-bearing rule: only *identity* evidence reconciles. CAIDA
network text supplies category/infrastructure context and never joins an identity
cluster, so it can never manufacture ``multi_rule`` agreement.
"""

from pathlib import Path

import pytest

from hunter_org_attribution import (
    AttributionEngine,
    load_caida_as2org_authority_from_text,
    normalize_hunter_record,
)
from hunter_org_attribution.provenance import LoadedAuthority, sha256_file


FIXTURE = Path(__file__).parent / "fixtures" / "global" / "caida_as2org_minimal.txt"
CAIDA_TEXT = FIXTURE.read_text(encoding="utf-8")


def caida_authority():
    return load_caida_as2org_authority_from_text(
        CAIDA_TEXT, sha256=sha256_file(FIXTURE), version="202601"
    )


def domain_authority(organization, *, domain, organization_id=None, source="synthetic-domains", sha="a" * 64):
    row = {"rule_id": f"{source}:{domain}", "domain": domain, "organization": organization}
    if organization_id:
        row["organization_id"] = organization_id
    return LoadedAuthority("domains", source, sha, (row,), {"schema": "domains", "source": source})


def range_authority(organization, *, start="192.0.2.0", end="192.0.2.255", source="synthetic-ranges", sha="b" * 64):
    row = {"rule_id": f"{source}:range", "start_ip": start, "end_ip": end, "organization": organization}
    return LoadedAuthority("ipv4_ranges", source, sha, (row,), {"schema": "ipv4_ranges", "source": source})


def exact_authority(organization, *, ip="192.0.2.10", source="synthetic-exact", sha="c" * 64):
    row = {"rule_id": f"{source}:exact", "ip": ip, "organization": organization}
    return LoadedAuthority("exact_ip", source, sha, (row,), {"schema": "exact_ip", "source": source})


def build(*authorities, caida=None):
    caidas = [caida] if caida is not None else []
    return AttributionEngine.from_repository_defaults(authorities=authorities, asn_organization_authorities=caidas)


def attribute(engine, **values):
    return engine.attribute(normalize_hunter_record({"ip": "203.0.113.9", **values}))


def cisa(organization="Example Federal Agency", domain="example.gov", **kwargs):
    return domain_authority(organization, domain=domain, source="cisa_dotgov_data", **kwargs)


def ror(organization="Example Research University", domain="example.edu", organization_id="ror:0example01", **kwargs):
    return domain_authority(organization, domain=domain, organization_id=organization_id, source="ror_domains", **kwargs)


# --------------------------------------------------------------------------
# Independent direct-identity authorities agreeing
# --------------------------------------------------------------------------

def test_cisa_and_ror_agreeing_on_one_domain_is_multi_rule():
    engine = build(
        cisa(domain="example.gov"),
        ror("Example Federal Agency", domain="example.gov", organization_id="ror:0gov01"),
    )
    result = attribute(engine, domain="example.gov")
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_name == "Example Federal Agency"
    assert result.resolution.agreement_status == "multi_rule_agreement"
    assert "multi_rule" in result.resolution.association_types


def test_existing_domain_authority_and_ror_agreeing_is_multi_rule():
    engine = build(
        domain_authority("Example Research University", domain="example.edu", source="submission_domains"),
        ror(),
    )
    result = attribute(engine, domain="example.edu")
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_id == "ror:0example01"
    assert "multi_rule" in result.resolution.association_types


def test_range_and_ror_agreeing_is_multi_rule():
    engine = build(
        range_authority("Example Research University"),
        ror(),
    )
    result = attribute(engine, ip="192.0.2.50", domain="example.edu")
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_name == "Example Research University"
    assert "multi_rule" in result.resolution.association_types


def test_exact_ip_and_cisa_agreeing_is_multi_rule():
    engine = build(
        exact_authority("Example Federal Agency"),
        cisa(),
    )
    result = attribute(engine, ip="192.0.2.10", domain="example.gov")
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_name == "Example Federal Agency"
    assert "multi_rule" in result.resolution.association_types


# --------------------------------------------------------------------------
# Orthogonality: identity vs category vs infrastructure
# --------------------------------------------------------------------------

def test_ror_identity_with_caida_university_asn_keeps_three_layers_separate():
    engine = build(ror(), caida=caida_authority())
    result = attribute(engine, domain="example.edu", asn=64500)

    # Identity comes only from the ROR domain authority.
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_name == "Example Research University"
    assert result.resolution.organization_id == "ror:0example01"

    # CAIDA network text supplies category context, not identity agreement.
    assert "education_research" in result.resolution.categories
    assert "multi_rule" not in result.resolution.association_types
    assert result.resolution.agreement_status == "single_identity_evidence"


def test_caida_network_text_never_becomes_conflicting_identity_evidence():
    engine = build(ror(), caida=caida_authority())
    result = attribute(engine, domain="example.edu", asn=64500)
    assert result.resolution.conflicting_organizations == ()
    assert all(
        evidence.resolved_organization is None
        for evidence in result.evidence
        if evidence.rule_family == "asn_org_regex"
    )


def test_ror_organization_with_aws_infrastructure_stays_orthogonal():
    engine = build(ror(), caida=caida_authority())
    result = attribute(engine, domain="example.edu", asn=64502)

    assert result.resolution.organization_name == "Example Research University"
    assert "Amazon Web Services" in result.resolution.infrastructure_organizations
    assert "cloud_vendor" in result.resolution.infrastructure_categories
    assert "cloud_vendor" not in result.resolution.categories
    assert result.resolution.conflicting_organizations == ()


def test_cisa_government_organization_with_isp_asn_keeps_identity_and_network():
    engine = build(cisa(), caida=caida_authority())
    result = attribute(engine, domain="example.gov", asn=64503)

    assert result.resolution.organization_name == "Example Federal Agency"
    assert "isp_carrier" in result.resolution.infrastructure_categories
    assert "isp_carrier" not in result.resolution.categories


# --------------------------------------------------------------------------
# Authorities disagreeing
# --------------------------------------------------------------------------

def test_two_direct_domain_authorities_disagreeing_is_a_conflict():
    engine = build(
        cisa("Example Federal Agency", domain="example.gov"),
        ror("Example State Department", domain="example.gov", organization_id="ror:0state01"),
    )
    result = attribute(engine, domain="example.gov")
    assert result.resolution.status == "conflict"
    assert result.resolution.organization_name is None
    assert result.resolution.conflicting_organizations == (
        "Example Federal Agency",
        "Example State Department",
    )
    assert "multi_rule" not in result.resolution.association_types


def test_ror_identifier_does_not_merge_two_distinct_ror_identities_by_name():
    # Two genuinely distinct reviewed authorities publishing the same domain with
    # different ROR identifiers: rule 4 forbids merging them by name.
    engine = build(
        domain_authority(
            "Example Research University", domain="a.example.edu",
            organization_id="ror:00000001", source="ror_domains", sha="1" * 64,
        ),
        domain_authority(
            "Example Research University", domain="a.example.edu",
            organization_id="ror:00000002", source="ror_domains", sha="2" * 64,
        ),
    )
    result = attribute(engine, domain="a.example.edu")
    assert result.resolution.status == "conflict"
    assert result.resolution.organization_name is None
