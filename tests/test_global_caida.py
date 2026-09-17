"""CAIDA AS Organizations (as2org) adapter and enrichment semantics.

The load-bearing invariant of this file: CAIDA network-registration text may
create *category* and *infrastructure* evidence, and may populate
``asn_organization``, but it must never create organization identity and must
never populate ``organization_id`` / ``resolved_organization``.
"""

from pathlib import Path

import pytest

from hunter_org_attribution import (
    CAIDA_AS2ORG_ADAPTER,
    CAIDA_AS2ORG_NAMESPACE,
    AsnOrganizationAuthority,
    AsnOrganizationEnrichmentConflict,
    AttributionEngine,
    AuthoritySourceError,
    adapt_caida_as2org,
    load_caida_as2org_authority,
    load_caida_as2org_authority_from_text,
    normalize_hunter_record,
)
from hunter_org_attribution.provenance import sha256_file


FIXTURE = Path(__file__).parent / "fixtures" / "global" / "caida_as2org_minimal.txt"
# One embedding of the reviewed fixture, used to build in-memory authorities.
FIXTURE_TEXT = FIXTURE.read_text(encoding="utf-8")


def load_fixture_authority() -> AsnOrganizationAuthority:
    return load_caida_as2org_authority_from_text(
        FIXTURE_TEXT, sha256=sha256_file(FIXTURE), version="202601"
    )


def engine_with(authority: AsnOrganizationAuthority | None = None) -> AttributionEngine:
    authorities = [authority] if authority is not None else [load_fixture_authority()]
    return AttributionEngine.from_repository_defaults(asn_organization_authorities=authorities)


def attribute(authority: AsnOrganizationAuthority, **values):
    return engine_with(authority).attribute(normalize_hunter_record({"ip": "203.0.113.9", **values}))


# --------------------------------------------------------------------------
# Adapter: real-format parsing and projection
# --------------------------------------------------------------------------

def test_caida_minimal_fixture_parses_into_canonical_counts():
    rows, counts = adapt_caida_as2org(FIXTURE_TEXT)
    assert counts["organization_records"] == 5
    assert counts["asn_rows_read"] == 12
    assert counts["unresolved_organization_reference"] == 1
    assert counts["blank_organization"] == 1
    assert counts["duplicate_asn_rows"] == 1
    assert counts["asn_mapping_conflicts"] == 1
    assert counts["conflicting_keys_excluded"] == 1
    assert counts["invalid_asn_rows"] == 1
    assert counts["usable_asn_mappings"] == 6
    assert [row["asn"] for row in rows] == [64500, 64501, 64502, 64503, 64506, 64507]


def test_caida_asn_resolves_to_network_organization_text():
    authority = load_fixture_authority()
    row = authority.lookup(64500)
    assert row is not None
    assert row.asn_organization == "Example University"


def test_caida_organization_reference_resolution_keeps_namespace():
    authority = load_fixture_authority()
    row = authority.lookup(64503)
    assert row.network_organization_id == "EXC-4-RIPE"
    assert row.network_organization_id_namespace == CAIDA_AS2ORG_NAMESPACE
    assert row.network_organization_source == "RIPE"


def test_caida_duplicate_same_mapping_is_deduplicated():
    authority = load_fixture_authority()
    assert authority.lookup(64507).asn_organization == "Example University"


def test_caida_conflicting_asn_mapping_excludes_the_key():
    authority = load_fixture_authority()
    # CAIDA_ASN_MAPPING_CONFLICT at key granularity: no mapping is invented.
    assert authority.lookup(64508) is None
    assert authority.asn_count == 6


def test_caida_missing_referenced_organization_is_dropped():
    authority = load_fixture_authority()
    assert authority.lookup(64505) is None


def test_caida_blank_organization_name_is_dropped():
    authority = load_fixture_authority()
    assert authority.lookup(64504) is None


def test_caida_invalid_asn_is_dropped():
    authority = load_fixture_authority()
    assert authority.lookup(64500) is not None
    assert all(row.asn > 0 for row in authority.records)


def test_caida_malformed_record_fails_closed():
    malformed = FIXTURE_TEXT.replace("64500|20240101|EXU-AS|EXU-1-ARIN|opaque-exu|ARIN", "64500|20240101|EXU-AS")
    with pytest.raises(AuthoritySourceError, match="ASN record must have 6 fields"):
        adapt_caida_as2org(malformed)


def test_caida_malformed_organization_record_fails_closed():
    malformed = FIXTURE_TEXT.replace("EXU-1-ARIN|20240101|Example University|US|ARIN", "EXU-1-ARIN|20240101|Example University")
    with pytest.raises(AuthoritySourceError, match="organization record must have 5 fields"):
        adapt_caida_as2org(malformed)


def test_caida_duplicate_organization_id_fails_closed():
    malformed = FIXTURE_TEXT.replace(
        "EXG-2-ARIN|20240101|Example Government Ministry|US|ARIN",
        "EXU-1-ARIN|20240101|Example Government Ministry|US|ARIN",
    )
    with pytest.raises(AuthoritySourceError, match="duplicate organization id"):
        adapt_caida_as2org(malformed)


def test_caida_data_row_before_format_header_fails_closed():
    with pytest.raises(AuthoritySourceError, match="before any"):
        adapt_caida_as2org("64500|20240101|EXU-AS|EXU-1-ARIN|opaque|ARIN\n")


def test_caida_loader_verifies_sha_and_records_provenance():
    loaded = load_caida_as2org_authority(
        FIXTURE,
        expected_sha256=sha256_file(FIXTURE),
        source="caida_as2org",
        version="202601",
        provenance={"source_url": "https://data.caida.org/datasets/as-organizations/"},
    )
    assert loaded.adapter == CAIDA_AS2ORG_ADAPTER
    assert loaded.version == "202601"
    assert loaded.audit["schema"] == "asn_organization"
    assert loaded.audit["provenance"]["source_url"].startswith("https://data.caida.org/")
    assert "identity" in loaded.audit["semantics"]


def test_caida_loader_sha_mismatch_fails_closed():
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_caida_as2org_authority(FIXTURE, expected_sha256="0" * 64)


def test_caida_loader_expected_asn_count_fails_closed():
    with pytest.raises(ValueError, match="ASN-count mismatch"):
        load_caida_as2org_authority(FIXTURE, expected_asns=999)


# --------------------------------------------------------------------------
# Enrichment populates text only
# --------------------------------------------------------------------------

def test_caida_enrichment_populates_asn_organization():
    authority = load_fixture_authority()
    result = attribute(authority, asn=64500)
    assert result.record.asn_organization == "Example University"
    assert result.resolution.organization_name is None
    assert result.resolution.organization_id is None


def test_caida_no_match_leaves_record_untouched():
    authority = load_fixture_authority()
    result = attribute(authority, asn=64999)
    assert result.record.asn_organization is None
    assert result.evidence == ()


def test_caida_without_configured_source_leaves_record_untouched():
    engine = AttributionEngine.from_repository_defaults()
    result = engine.attribute(normalize_hunter_record({"ip": "203.0.113.9", "asn": 64500}))
    assert result.record.asn_organization is None


# --------------------------------------------------------------------------
# CAIDA text never becomes identity
# --------------------------------------------------------------------------

def test_caida_university_text_yields_category_only_no_identity():
    result = attribute(load_fixture_authority(), asn=64500)
    assert result.resolution.status == "category_only"
    assert result.resolution.organization_name is None
    assert result.resolution.organization_id is None
    assert "education_research" in result.resolution.categories


def test_caida_government_text_yields_category_only_no_identity():
    result = attribute(load_fixture_authority(), asn=64501)
    assert result.resolution.status == "category_only"
    assert result.resolution.organization_name is None
    assert "government" in result.resolution.categories


def test_caida_cloud_text_yields_infrastructure_only_no_identity():
    result = attribute(load_fixture_authority(), asn=64502)
    assert result.resolution.status == "unresolved"
    assert result.resolution.organization_name is None
    assert "cloud_vendor" in result.resolution.infrastructure_categories
    assert "cloud_vendor" not in result.resolution.categories


def test_caida_isp_text_yields_infrastructure_only_no_identity():
    result = attribute(load_fixture_authority(), asn=64503)
    assert result.resolution.status == "unresolved"
    assert result.resolution.organization_name is None
    assert "isp_carrier" in result.resolution.infrastructure_categories


def test_caida_never_sets_organization_id_on_any_evidence():
    authority = load_fixture_authority()
    for asn in (64500, 64501, 64502, 64503, 64506, 64507):
        result = attribute(authority, asn=asn)
        for evidence in result.evidence:
            assert evidence.resolved_organization_id is None
            assert evidence.resolved_organization is None


def test_caida_source_local_id_is_namespaced_and_not_an_identity_id():
    authority = load_fixture_authority()
    row = authority.lookup(64500)
    provenance = authority.enrichment_provenance(row)
    assert provenance["network_organization_id_namespace"] == "caida-as2org"
    assert provenance["network_organization_id"] == "EXU-1-ARIN"
    assert "organization_id" not in provenance


# --------------------------------------------------------------------------
# Field-level enrichment provenance
# --------------------------------------------------------------------------

def test_caida_rule_evidence_carries_enrichment_provenance():
    authority = load_fixture_authority()
    result = attribute(authority, asn=64500)
    evidence = next(e for e in result.evidence if e.rule_id == "lens.category.education_research.asn_org")
    block = evidence.provenance["asn_organization_enrichment"]
    assert block["adapter"] == CAIDA_AS2ORG_ADAPTER
    assert block["source"] == "caida_as2org"
    assert block["authority_sha256"] == authority.sha256
    assert block["authority_version"] == "202601"
    assert block["asn"] == 64500
    assert block["network_organization_id"] == "EXU-1-ARIN"
    assert block["network_organization_id_namespace"] == "caida-as2org"
    assert block["origin"] == "enrichment"


def test_caida_rule_evidence_answers_where_the_text_came_from():
    authority = load_fixture_authority()
    result = attribute(authority, asn=64502)
    evidence = next(e for e in result.evidence if e.rule_id == "lens.infrastructure.cloud.asn_org")
    assert evidence.observed_value == "Amazon.com, Inc."
    block = evidence.provenance["asn_organization_enrichment"]
    assert block["origin"] == "enrichment"
    assert block["authority_sha256"] == authority.sha256


# --------------------------------------------------------------------------
# Raw value vs enrichment conflict
# --------------------------------------------------------------------------

def test_caida_raw_value_agreement_is_accepted():
    result = attribute(load_fixture_authority(), asn=64500, asn_organization="Example University")
    assert result.record.asn_organization == "Example University"
    evidence = next(e for e in result.evidence if e.rule_id == "lens.category.education_research.asn_org")
    assert evidence.provenance["asn_organization_enrichment"]["origin"] == "record"


def test_caida_raw_value_agreement_ignores_case_and_whitespace():
    result = attribute(load_fixture_authority(), asn=64500, asn_organization="  example   UNIVERSITY ")
    # The Hunter adapter collapses whitespace; comparison is additionally case-folded.
    assert result.record.asn_organization == "example UNIVERSITY"
    assert result.resolution.status == "category_only"


def test_caida_raw_value_disagreement_fails_closed():
    with pytest.raises(AsnOrganizationEnrichmentConflict, match="disagrees with reviewed"):
        attribute(load_fixture_authority(), asn=64500, asn_organization="Some Other University")


def test_caida_raw_value_on_unmapped_asn_is_untouched():
    result = attribute(load_fixture_authority(), asn=64999, asn_organization="Some Other University")
    assert result.record.asn_organization == "Some Other University"


def test_two_caida_sources_disagreeing_for_one_asn_fail_closed():
    first = load_caida_as2org_authority_from_text(
        "# format:org_id|changed|org_name|country|source\n"
        "A-1-ARIN|20240101|Organization A|US|ARIN\n"
        "# format:aut|changed|aut_name|org_id|opaque_id|source\n"
        "64500|20240101|A-AS|A-1-ARIN|opaque-a|ARIN\n",
        source="caida-a",
    )
    second = load_caida_as2org_authority_from_text(
        "# format:org_id|changed|org_name|country|source\n"
        "B-2-ARIN|20240101|Organization B|US|ARIN\n"
        "# format:aut|changed|aut_name|org_id|opaque_id|source\n"
        "64500|20240101|B-AS|B-2-ARIN|opaque-b|ARIN\n",
        source="caida-b",
    )
    engine = AttributionEngine.from_repository_defaults(asn_organization_authorities=[first, second])
    with pytest.raises(AsnOrganizationEnrichmentConflict, match="sources disagree for ASN 64500"):
        engine.attribute(normalize_hunter_record({"ip": "203.0.113.9", "asn": 64500}))


def test_caida_enrichment_never_sets_provenance_when_no_source_matches():
    authority = load_fixture_authority()
    result = attribute(authority, asn=64999)
    assert result.evidence == ()
    assert result.record.asn_organization is None
