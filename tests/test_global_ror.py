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
from hunter_org_attribution.provenance import load_authority_rows, sha256_file


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
    assert counts["usable_unique_domains"] == 5
    # Phase 5.1 status accounting: the single inactive record and its one domain
    # are counted and dropped; ambiguity is resolved among active records only.
    assert counts["active_records"] == 6
    assert counts["inactive_records"] == 1
    assert counts["withdrawn_records"] == 0
    assert counts["active_records_with_domains"] == 5
    assert counts["inactive_records_with_domains"] == 1
    assert counts["inactive_domain_entries_dropped"] == 1
    assert counts["withdrawn_domain_entries_dropped"] == 0


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
        {"id": "0valid001", "status": "active", "names": [{"value": "Valid Org", "types": ["ror_display"]}],
         "domains": ["valid.example.edu", "not a domain", "nodot"]},
    ])
    assert [row["domain"] for row in rows] == ["valid.example.edu"]
    assert counts["invalid_domains"] == 2


def test_ror_blank_organization_name_is_dropped_and_counted():
    rows, counts = adapt_ror_domains([
        {"id": "0blank001", "status": "active", "names": [{"value": "  ", "types": ["ror_display"]}], "domains": ["blank.example.edu"]},
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
    assert provenance["adapter_counts"]["usable_unique_domains"] == 5
    assert provenance["adapter_counts"]["organizations_without_domains"] == 1
    assert "ror_identity_status_policy" in provenance


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


def test_ror_inactive_organization_domain_is_excluded():
    # Phase 5.1 conservative status semantics: an inactive record's domain is
    # counted and dropped, never turned into direct identity.
    rows, counts = adapt_ror_domains(RECORDS)
    assert all(row["domain"] != "retired.example.org" for row in rows)
    assert counts["inactive_records"] == 1
    assert counts["inactive_records_with_domains"] == 1
    assert counts["inactive_domain_entries_dropped"] == 1


# --------------------------------------------------------------------------
# Phase 5.1: ROR production-status semantics (active-only direct identity)
# --------------------------------------------------------------------------

def ror_record(ror_id, status, name, domains, successor=None):
    record = {
        "id": ror_id,
        "status": status,
        "names": [{"value": name, "types": ["ror_display", "label"]}],
        "domains": domains,
    }
    if successor:
        record["successor_relationships"] = [
            {"type": "Successor", "successor_id": successor}
        ]
    return record


def ror_engine(records):
    rows, _ = adapt_ror_domains(records)
    return load_authority_rows(
        rows,
        authority_type="domains",
        source="ror_domains",
        sha256="1" * 64,
        provenance={"ror_identity_status_policy": "active-only"},
    )


def test_ror_active_record_with_valid_domain_produces_identity():
    records = [ror_record("0act0001", "active", "Active Research Lab", ["active.example.edu"])]
    rows, counts = adapt_ror_domains(records)
    assert [row["domain"] for row in rows] == ["active.example.edu"]
    assert rows[0]["ror_status"] == "active"
    assert counts["active_records"] == 1
    assert counts["active_records_with_domains"] == 1
    result = attribute(ror_engine(records), domain="active.example.edu")
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_id == "ror:0act0001"


def test_ror_inactive_record_with_valid_domain_produces_no_identity():
    records = [ror_record("0inact01", "inactive", "Retired Lab", ["retired.example.org"])]
    rows, counts = adapt_ror_domains(records)
    assert rows == []
    assert counts["inactive_records"] == 1
    assert counts["inactive_records_with_domains"] == 1
    assert counts["inactive_domain_entries_dropped"] == 1
    result = attribute(ror_engine(records), domain="retired.example.org")
    assert result.resolution.organization_name is None
    assert result.resolution.status == "unresolved"


def test_ror_withdrawn_record_with_valid_domain_produces_no_identity():
    records = [ror_record("0withd01", "withdrawn", "Withdrawn Lab", ["withdrawn.example.org"])]
    rows, counts = adapt_ror_domains(records)
    assert rows == []
    assert counts["withdrawn_records"] == 1
    assert counts["withdrawn_records_with_domains"] == 1
    assert counts["withdrawn_domain_entries_dropped"] == 1
    result = attribute(ror_engine(records), domain="withdrawn.example.org")
    assert result.resolution.organization_name is None


def test_ror_inactive_record_with_successor_creates_no_successor_identity():
    records = [
        ror_record("0old0001", "inactive", "Old Research Lab", ["old.example.org"], successor="0new0002")
    ]
    rows, counts = adapt_ror_domains(records)
    assert rows == []
    assert counts["inactive_records_with_successor"] == 1
    result = attribute(ror_engine(records), domain="old.example.org")
    assert result.resolution.organization_name is None
    assert result.resolution.status == "unresolved"


def test_ror_withdrawn_record_with_successor_creates_no_successor_identity():
    records = [
        ror_record("0wold001", "withdrawn", "Withdrawn Lab", ["w.example.org"], successor="0new0002")
    ]
    rows, counts = adapt_ror_domains(records)
    assert rows == []
    assert counts["withdrawn_records_with_successor"] == 1
    result = attribute(ror_engine(records), domain="w.example.org")
    assert result.resolution.organization_name is None


def test_ror_active_survives_withdrawn_competitor_on_same_domain():
    records = [
        ror_record("0act0002", "active", "Active Org", ["shared.example.net"]),
        ror_record("0withd02", "withdrawn", "Withdrawn Org", ["shared.example.net"]),
    ]
    rows, counts = adapt_ror_domains(records)
    # Ambiguity is computed after status filtering: the withdrawn record cannot
    # make the active claim ambiguous.
    assert any(
        row["domain"] == "shared.example.net" and row["organization_id"] == "ror:0act0002"
        for row in rows
    )
    assert counts["ambiguous_domain_keys_dropped"] == 0
    result = attribute(ror_engine(records), domain="shared.example.net")
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_id == "ror:0act0002"


def test_ror_active_survives_inactive_competitor_on_same_domain():
    records = [
        ror_record("0act0003", "active", "Active Org", ["shared2.example.net"]),
        ror_record("0inact03", "inactive", "Retired Org", ["shared2.example.net"]),
    ]
    rows, counts = adapt_ror_domains(records)
    assert any(
        row["domain"] == "shared2.example.net" and row["organization_id"] == "ror:0act0003"
        for row in rows
    )
    assert counts["ambiguous_domain_keys_dropped"] == 0
    result = attribute(ror_engine(records), domain="shared2.example.net")
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_id == "ror:0act0003"


def test_ror_two_active_competitors_on_same_domain_are_ambiguous():
    records = [
        ror_record("0act0004", "active", "Org A", ["dup.shared.example.net"]),
        ror_record("0act0005", "active", "Org B", ["dup.shared.example.net"]),
    ]
    rows, counts = adapt_ror_domains(records)
    assert all(row["domain"] != "dup.shared.example.net" for row in rows)
    assert counts["ambiguous_domain_keys_dropped"] == 1
    result = attribute(ror_engine(records), domain="dup.shared.example.net")
    assert result.resolution.organization_name is None
    assert result.resolution.status == "unresolved"


def test_ror_active_record_with_empty_domains_creates_no_identity():
    records = [ror_record("0act0006", "active", "Domainless Lab", [])]
    rows, counts = adapt_ror_domains(records)
    assert rows == []
    assert counts["active_records"] == 1
    assert counts["organizations_without_domains"] == 1


def test_ror_identity_evidence_confirms_ror_status_active():
    records = [ror_record("0act0007", "active", "Provenance Lab", ["prov.example.edu"])]
    result = attribute(ror_engine(records), domain="prov.example.edu")
    evidence = next(e for e in result.evidence if e.rule_family == "official_domain")
    assert evidence.resolved_organization_id == "ror:0act0007"
    assert evidence.provenance["ror_status"] == "active"
