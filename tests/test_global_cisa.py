"""CISA dotgov-data (.gov registrar) direct domain identity semantics.

CISA asserts *only* that a named government organization holds a registrable
domain. It publishes no organization identifier, so ``organization_id`` stays
null, and it must never be reached by substring matching or by inferring a
government category from the ``.gov`` suffix.
"""

from pathlib import Path

import pytest

from hunter_org_attribution import (
    GOV_DOMAIN_REGISTRY_ADAPTER,
    AttributionEngine,
    AuthoritySourceError,
    adapt_cisa_dotgov,
    load_cisa_dotgov_authority,
    normalize_hunter_record,
)
from hunter_org_attribution.provenance import sha256_file


FIXTURE = Path(__file__).parent / "fixtures" / "global" / "cisa_dotgov_minimal.csv"


def load_fixture_authority():
    return load_cisa_dotgov_authority(
        FIXTURE,
        expected_sha256=sha256_file(FIXTURE),
        source="cisa_dotgov_data",
        provenance={"source_url": "https://github.com/cisagov/dotgov-data"},
    )


def engine_with(authority) -> AttributionEngine:
    return AttributionEngine.from_repository_defaults(authorities=[authority])


def attribute(authority, **values):
    return engine_with(authority).attribute(normalize_hunter_record({"ip": "203.0.113.9", **values}))


# --------------------------------------------------------------------------
# Adapter
# --------------------------------------------------------------------------

def test_cisa_fixture_projects_registered_domains_to_identity_rows():
    rows, counts = adapt_cisa_dotgov([
        {"Domain name": "ExampleAgency.gov", "Organization name": "Example Federal Agency"},
        {"Domain name": "exampledept.gov", "Organization name": "Example State Department"},
    ])
    assert rows == [
        {"domain": "exampleagency.gov", "organization": "Example Federal Agency"},
        {"domain": "exampledept.gov", "organization": "Example State Department"},
    ]
    assert counts["unmapped_rows"] == 0
    assert "organization_id" not in rows[0]


def test_cisa_loader_deduplicates_case_variant_of_the_same_domain():
    loaded = load_fixture_authority()
    assert loaded.authority_type == "domains"
    assert loaded.audit["provenance"]["adapter"] == GOV_DOMAIN_REGISTRY_ADAPTER
    assert loaded.audit["provenance"]["duplicate_rows_removed"] == 1
    assert len(loaded.rows) == 3
    assert {row["domain"] for row in loaded.rows} == {
        "exampleagency.gov", "exampledept.gov", "examplecity.gov"
    }


def test_cisa_blank_organization_is_dropped_and_counted():
    rows, counts = adapt_cisa_dotgov([
        {"Domain name": "exampleagency.gov", "Organization name": "Example Federal Agency"},
        {"Domain name": "unmapped.gov", "Organization name": "  "},
    ])
    assert len(rows) == 1
    assert counts["unmapped_rows"] == 1


def test_cisa_invalid_domain_fails_closed():
    with pytest.raises(AuthoritySourceError, match="invalid domain"):
        adapt_cisa_dotgov([{"Domain name": "not a domain", "Organization name": "Example Agency"}])


def test_cisa_missing_organization_column_fails_closed():
    with pytest.raises(AuthoritySourceError, match="missing source columns"):
        adapt_cisa_dotgov([{"Domain name": "exampleagency.gov"}])


def test_cisa_conflicting_mapping_fails_closed(tmp_path):
    path = tmp_path / "cisa_conflict.csv"
    path.write_text(
        "Domain name,Domain type,Organization name\n"
        "exampleagency.gov,Federal,Example Federal Agency\n"
        "exampleagency.gov,Federal,A Different Agency\n",
        encoding="utf-8",
    )
    with pytest.raises(AuthoritySourceError, match="Conflicting domains rows"):
        load_cisa_dotgov_authority(path, expected_sha256=sha256_file(path))


def test_cisa_loader_sha_mismatch_fails_closed():
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_cisa_dotgov_authority(FIXTURE, expected_sha256="0" * 64)


# --------------------------------------------------------------------------
# Direct identity
# --------------------------------------------------------------------------

def test_cisa_registered_domain_resolves_identity():
    result = attribute(load_fixture_authority(), domain="exampleagency.gov")
    assert result.resolution.organization_name == "Example Federal Agency"
    assert result.resolution.organization_id is None
    assert "official_domain" in result.resolution.association_types


def test_cisa_identity_evidence_carries_source_provenance():
    result = attribute(load_fixture_authority(), domain="exampledept.gov")
    evidence = next(e for e in result.evidence if e.rule_family == "official_domain")
    assert evidence.source == "cisa_dotgov_data"
    assert evidence.provenance["provenance"]["source_url"].startswith("https://github.com/cisagov/")
    assert evidence.provenance["provenance"]["source_columns"] == ["Domain name", "Organization name"]
    assert evidence.provenance["provenance"]["adapter"] == GOV_DOMAIN_REGISTRY_ADAPTER


def test_cisa_subdomain_of_registered_domain_matches_on_label_boundary():
    result = attribute(load_fixture_authority(), root_domain="portal.exampleagency.gov")
    assert result.resolution.organization_name == "Example Federal Agency"


def test_cisa_neighbour_domain_does_not_match_by_substring():
    result = attribute(load_fixture_authority(), domain="notexampleagency.gov")
    assert result.resolution.organization_name is None
    assert result.evidence == ()


def test_cisa_suffix_host_of_registered_domain_does_not_match():
    result = attribute(load_fixture_authority(), domain="exampleagency.gov.evil.example")
    # The registered domain is a prefix label run, not a registrable suffix here.
    assert result.resolution.organization_name is None
    assert all(e.rule_family != "official_domain" for e in result.evidence)


def test_cisa_unregistered_gov_domain_does_not_match():
    result = attribute(load_fixture_authority(), domain="notregistered.gov")
    assert result.resolution.organization_name is None
    assert result.evidence == ()


def test_cisa_does_not_infer_government_category_from_gov_suffix():
    # The registry is a .gov registrar, but identity and category stay separate:
    # no government category is synthesized by the adapter or the engine here.
    result = attribute(load_fixture_authority(), domain="examplecity.gov")
    assert result.resolution.organization_name == "City of Example"
    assert result.resolution.categories == ()
