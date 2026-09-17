"""ROR schema-v2 domains: direct research-organization domain identity.

Only domains the ROR dump itself provides are ingested. A canonical domain
claimed by two distinct ROR identifiers is ambiguous and is dropped per key
rather than resolved by record order. ROR identifiers are compared only inside
the ``ror`` namespace.
"""

import json
from pathlib import Path

import pytest

from hunter_org_attribution import (
    ROR_DOMAIN_AUTHORITY_ADAPTER,
    ROR_NAMESPACE,
    AttributionEngine,
    AuthoritySourceError,
    adapt_ror_domains,
    load_ror_domain_authority,
    normalize_hunter_record,
    ror_identifier,
)
from hunter_org_attribution.provenance import sha256_file


FIXTURE = Path(__file__).parent / "fixtures" / "global" / "ror_v2_minimal.json"
RECORDS = json.loads(FIXTURE.read_text(encoding="utf-8"))


def load_fixture_authority():
    return load_ror_domain_authority(
        FIXTURE,
        expected_sha256=sha256_file(FIXTURE),
        source="ror_domains",
        provenance={"source_url": "https://ror.readme.io/docs/data-dump", "version": "v2.minimal"},
    )


def engine_with(authority) -> AttributionEngine:
    return AttributionEngine.from_repository_defaults(authorities=[authority])


def attribute(authority, **values):
    return engine_with(authority).attribute(normalize_hunter_record({"ip": "203.0.113.9", **values}))


# --------------------------------------------------------------------------
# Adapter
# --------------------------------------------------------------------------

def test_ror_fixture_counts_domains_ambiguity_and_domainless_records():
    rows, counts = adapt_ror_domains(RECORDS)
    assert counts["organizations_read"] == 7
    assert counts["organizations_without_domains"] == 1
    assert counts["domain_entries"] == 9
    assert counts["duplicate_domain_entries"] == 1
    assert counts["ambiguous_domain_keys_dropped"] == 1
    assert counts["invalid_domains"] == 0
    assert counts["usable_unique_domains"] == 6


def test_ror_organization_with_multiple_domains_produces_one_row_each():
    rows, _ = adapt_ror_domains(RECORDS)
    domains = {row["domain"] for row in rows}
    assert {"example.edu", "example.ac.uk"} <= domains


def test_ror_identifier_is_namespaced_and_stable():
    rows, _ = adapt_ror_domains(RECORDS)
    row = next(row for row in rows if row["domain"] == "example.edu")
    assert row["organization_id"] == "ror:0example01"
    assert row["organization"] == "Example Research University"
    assert ror_identifier("0example01") == f"{ROR_NAMESPACE}:0example01"


def test_ror_display_name_is_preferred_over_alias():
    rows, _ = adapt_ror_domains(RECORDS)
    row = next(row for row in rows if row["domain"] == "example.ac.uk")
    assert row["organization"] == "Example Research University"


def test_ror_organization_without_domains_creates_nothing():
    rows, _ = adapt_ror_domains(RECORDS)
    assert all(row["organization"] != "Example Domainless Academy" for row in rows)


def test_ror_shared_domain_is_ambiguous_and_excluded():
    rows, counts = adapt_ror_domains(RECORDS)
    assert all(row["domain"] != "shared.example.net" for row in rows)
    assert counts["ambiguous_domain_keys_dropped"] == 1
    # The organization's other, unambiguous domain still resolves.
    assert any(row["domain"] == "unique-b.example.net" for row in rows)


def test_ror_duplicate_domain_for_same_identifier_is_deduplicated():
    rows, counts = adapt_ror_domains(RECORDS)
    matching = [row for row in rows if row["domain"] == "dup.example.edu"]
    assert len(matching) == 1
    assert counts["duplicate_domain_entries"] == 1


def test_ror_invalid_domain_is_dropped_and_counted():
    rows, counts = adapt_ror_domains([
        {"id": "0valid001", "names": [{"value": "Valid Org", "types": ["ror_display"]}],
         "domains": ["valid.example.edu", "not a domain", "nodot"]},
    ])
    assert [row["domain"] for row in rows] == ["valid.example.edu"]
    assert counts["invalid_domains"] == 2


def test_ror_blank_organization_name_is_dropped_and_counted():
    rows, counts = adapt_ror_domains([
        {"id": "0blank001", "names": [{"value": "  ", "types": ["ror_display"]}], "domains": ["blank.example.edu"]},
    ])
    assert rows == []
    assert counts["blank_organization_names"] == 1


def test_ror_missing_identifier_fails_closed():
    with pytest.raises(AuthoritySourceError, match="missing a ROR id"):
        adapt_ror_domains([{"names": [{"value": "No Id Org"}], "domains": ["noid.example.edu"]}])


def test_ror_loader_reads_json_and_records_provenance():
    loaded = load_fixture_authority()
    assert loaded.authority_type == "domains"
    provenance = loaded.audit["provenance"]
    assert provenance["adapter"] == ROR_DOMAIN_AUTHORITY_ADAPTER
    assert provenance["adapter_counts"]["ambiguous_domain_keys_dropped"] == 1
    assert provenance["adapter_counts"]["usable_unique_domains"] == 6
    assert provenance["adapter_counts"]["organizations_without_domains"] == 1


def test_ror_loader_sha_mismatch_fails_closed():
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_ror_domain_authority(FIXTURE, expected_sha256="0" * 64)


# --------------------------------------------------------------------------
# Direct identity
# --------------------------------------------------------------------------

def test_ror_domain_resolves_namespaced_identity():
    result = attribute(load_fixture_authority(), domain="example.edu")
    assert result.resolution.organization_name == "Example Research University"
    assert result.resolution.organization_id == "ror:0example01"


def test_ror_identity_evidence_carries_namespace_and_source_provenance():
    result = attribute(load_fixture_authority(), domain="example-institute.edu")
    evidence = next(e for e in result.evidence if e.rule_family == "official_domain")
    assert evidence.resolved_organization_id == "ror:0example02"
    assert evidence.source == "ror_domains"
    assert evidence.provenance["provenance"]["source_url"] == "https://ror.readme.io/docs/data-dump"


def test_ror_ambiguous_domain_creates_no_identity():
    result = attribute(load_fixture_authority(), domain="shared.example.net")
    assert result.resolution.organization_name is None
    assert result.evidence == ()


def test_ror_domainless_organization_creates_no_identity():
    result = attribute(load_fixture_authority(), domain="domainless.example.org")
    assert result.resolution.organization_name is None
    assert result.evidence == ()


def test_ror_inactive_organization_domain_is_recorded_as_published():
    # Phase 5 ingests the dump's own domain field; it does not re-derive status
    # semantics or drop records by name.
    rows, _ = adapt_ror_domains(RECORDS)
    assert any(row["domain"] == "retired.example.org" for row in rows)
