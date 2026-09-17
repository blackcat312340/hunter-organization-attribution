import csv

import pytest

from hunter_org_attribution import AuthoritySourceError
from hunter_org_attribution.authority_sources import (
    CHINA_INSTITUTION_RANGE_ADAPTER,
    DOMAIN_ORG_ASSOCIATION_ADAPTER,
    EXACT_IP_ORG_ASSOCIATION_ADAPTER,
    adapt_china_institution_ranges,
    adapt_domain_org,
    adapt_exact_ip_org,
    load_china_institution_range_authority,
    load_domain_org_authority,
    load_exact_ip_org_authority,
)
from hunter_org_attribution.provenance import load_authority_rows, sha256_file


def write_csv(path, header, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        if header:
            writer.writerow(header)
        writer.writerows(rows)
    return path


# --------------------------------------------------------------------------
# China institution range: headerless org,start_ip,end_ip
# --------------------------------------------------------------------------

def test_china_range_positional_rows_project_to_canonical_range_records():
    rows, counts = adapt_china_institution_ranges([
        ["Example University", "192.0.2.0", "192.0.2.255"],
        ["Other Institute", "198.51.100.0", "198.51.100.15"],
    ])
    assert counts == {"unmapped_rows": 0, "out_of_scope_rows": 0}
    assert rows == [
        {"organization": "Example University", "start_ip": "192.0.2.0", "end_ip": "192.0.2.255"},
        {"organization": "Other Institute", "start_ip": "198.51.100.0", "end_ip": "198.51.100.15"},
    ]
    assert "organization_id" not in rows[0]


def test_china_range_mapping_rows_accept_org_alias():
    rows, counts = adapt_china_institution_ranges([
        {"org": "Example University", "start_ip": "192.0.2.0", "end_ip": "192.0.2.255"},
    ])
    assert counts["unmapped_rows"] == 0
    assert rows[0]["organization"] == "Example University"


def test_china_range_blank_organization_is_dropped_and_counted():
    rows, counts = adapt_china_institution_ranges([
        ["Example University", "192.0.2.0", "192.0.2.255"],
        ["", "203.0.113.0", "203.0.113.10"],
    ])
    assert len(rows) == 1
    assert counts["unmapped_rows"] == 1


def test_china_range_malformed_arity_fails_closed():
    with pytest.raises(AuthoritySourceError, match="exactly 3 columns"):
        adapt_china_institution_ranges([["Example University", "192.0.2.0"]])


def test_china_range_invalid_ip_fails_closed():
    with pytest.raises(AuthoritySourceError, match="invalid IP address"):
        adapt_china_institution_ranges([["Example University", "192.0.2.0", "not-an-ip"]])


def test_china_range_inverted_range_fails_closed():
    with pytest.raises(AuthoritySourceError, match="inverted range"):
        adapt_china_institution_ranges([["Example University", "192.0.2.255", "192.0.2.0"]])


def test_china_range_ipv6_rows_are_dropped_as_out_of_scope():
    rows, counts = adapt_china_institution_ranges([["Example University", "2001:db8::", "2001:db8::ff"]])
    assert rows == []
    assert counts["out_of_scope_rows"] == 1


def test_china_range_loader_produces_canonical_authority(tmp_path):
    path = write_csv(tmp_path / "ranges.csv", None, [
        ["Example University", "192.0.2.0", "192.0.2.255"],
    ])
    loaded = load_china_institution_range_authority(
        path, expected_sha256=sha256_file(path), source="synthetic-china-range"
    )
    assert loaded.authority_type == "ipv4_ranges"
    assert loaded.rows == ({"organization": "Example University", "start_ip": "192.0.2.0", "end_ip": "192.0.2.255"},)
    assert loaded.audit["provenance"]["adapter"] == CHINA_INSTITUTION_RANGE_ADAPTER
    assert loaded.audit["provenance"]["source_columns"] == ["org", "start_ip", "end_ip"]


def test_china_range_loader_sha_mismatch_fails_closed(tmp_path):
    path = write_csv(tmp_path / "ranges.csv", None, [["Example University", "192.0.2.0", "192.0.2.255"]])
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_china_institution_range_authority(path, expected_sha256="0" * 64)


def test_china_range_loader_deduplicates_exact_duplicate_rows(tmp_path):
    path = write_csv(tmp_path / "ranges.csv", None, [
        ["Example University", "192.0.2.0", "192.0.2.255"],
        ["Example University", "192.0.2.0", "192.0.2.255"],
    ])
    loaded = load_china_institution_range_authority(path, expected_sha256=sha256_file(path))
    assert len(loaded.rows) == 1
    assert loaded.audit["provenance"]["duplicate_rows_removed"] == 1


def test_china_range_loader_conflicting_rows_fail_closed(tmp_path):
    path = write_csv(tmp_path / "ranges.csv", None, [
        ["Example University", "192.0.2.0", "192.0.2.255"],
        ["Other Institute", "192.0.2.0", "192.0.2.255"],
    ])
    with pytest.raises(AuthoritySourceError, match="Conflicting ipv4_ranges rows"):
        load_china_institution_range_authority(path, expected_sha256=sha256_file(path))


# --------------------------------------------------------------------------
# domain,org
# --------------------------------------------------------------------------

def test_domain_org_rows_project_to_canonical_domain_records():
    rows, counts = adapt_domain_org([{"domain": "Example.EDU", "org": "Example University"}])
    assert counts["unmapped_rows"] == 0
    assert rows == [{"domain": "example.edu", "organization": "Example University"}]


def test_domain_org_blank_organization_is_dropped_and_counted():
    rows, counts = adapt_domain_org([
        {"domain": "example.edu", "org": "Example University"},
        {"domain": "unmapped.example", "org": ""},
    ])
    assert len(rows) == 1
    assert counts["unmapped_rows"] == 1


def test_domain_org_invalid_domain_fails_closed():
    with pytest.raises(AuthoritySourceError, match="invalid domain"):
        adapt_domain_org([{"domain": "not a domain", "org": "Example University"}])


def test_domain_org_missing_organization_column_fails_closed():
    with pytest.raises(AuthoritySourceError, match="organization column"):
        adapt_domain_org([{"domain": "example.edu"}])


def test_domain_org_loader_records_source_member_provenance(tmp_path):
    path = write_csv(tmp_path / "domain_org.csv", ["domain", "org"], [
        ["example.edu", "Example University"],
        ["unmapped.example", ""],
    ])
    loaded = load_domain_org_authority(
        path,
        expected_sha256=sha256_file(path),
        source="synthetic-domain-org",
        provenance={
            "source_zip": "submission_package_2026-08-13.zip",
            "zip_member": "results/domain_org.csv",
            "member_sha256": "f" * 64,
        },
    )
    assert loaded.authority_type == "domains"
    assert loaded.rows == ({"domain": "example.edu", "organization": "Example University"},)
    assert loaded.audit["provenance"]["adapter"] == DOMAIN_ORG_ASSOCIATION_ADAPTER
    assert loaded.audit["provenance"]["unmapped_rows_dropped"] == 1
    assert loaded.audit["provenance"]["out_of_scope_rows_dropped"] == 0
    assert loaded.audit["provenance"]["zip_member"] == "results/domain_org.csv"


def test_domain_org_loader_conflicting_rows_fail_closed(tmp_path):
    path = write_csv(tmp_path / "domain_org.csv", ["domain", "org"], [
        ["example.edu", "Example University"],
        ["example.edu", "Other University"],
    ])
    with pytest.raises(AuthoritySourceError, match="Conflicting domains rows"):
        load_domain_org_authority(path, expected_sha256=sha256_file(path))


# --------------------------------------------------------------------------
# ip,org  (exact IP only)
# --------------------------------------------------------------------------

def test_exact_ip_org_rows_project_to_canonical_exact_ip_records():
    rows, counts = adapt_exact_ip_org([{"ip": "192.0.2.10", "org": "Example University"}])
    assert counts["unmapped_rows"] == 0
    assert rows == [{"ip": "192.0.2.10", "organization": "Example University"}]


def test_exact_ip_org_does_not_expand_to_a_range():
    rows, _ = adapt_exact_ip_org([{"ip": "192.0.2.10", "org": "Example University"}])
    assert set(rows[0]) == {"ip", "organization"}


def test_exact_ip_org_blank_organization_is_dropped_and_counted():
    rows, counts = adapt_exact_ip_org([
        {"ip": "192.0.2.10", "org": "Example University"},
        {"ip": "192.0.2.11", "org": ""},
    ])
    assert len(rows) == 1
    assert counts["unmapped_rows"] == 1


def test_exact_ip_org_invalid_ip_fails_closed():
    with pytest.raises(AuthoritySourceError, match="invalid IP address"):
        adapt_exact_ip_org([{"ip": "192.0.2.999", "org": "Example University"}])


def test_exact_ip_org_ipv6_rows_are_dropped_as_out_of_scope():
    rows, counts = adapt_exact_ip_org([
        {"ip": "2001:db8::1", "org": "Example University"},
        {"ip": "192.0.2.10", "org": "Example University"},
    ])
    assert rows == [{"ip": "192.0.2.10", "organization": "Example University"}]
    assert counts["out_of_scope_rows"] == 1
    assert counts["unmapped_rows"] == 0


def test_exact_ip_org_loader_sha_mismatch_fails_closed(tmp_path):
    path = write_csv(tmp_path / "ip_org.csv", ["ip", "org"], [["192.0.2.10", "Example University"]])
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_exact_ip_org_authority(path, expected_sha256="1" * 64)


def test_exact_ip_org_loader_produces_canonical_authority(tmp_path):
    path = write_csv(tmp_path / "ip_org.csv", ["ip", "org"], [["192.0.2.10", "Example University"]])
    loaded = load_exact_ip_org_authority(path, expected_sha256=sha256_file(path))
    assert loaded.authority_type == "exact_ip"
    assert loaded.rows == ({"ip": "192.0.2.10", "organization": "Example University"},)
    assert loaded.audit["provenance"]["adapter"] == EXACT_IP_ORG_ASSOCIATION_ADAPTER


# --------------------------------------------------------------------------
# Shared canonical loader still fails closed on canonical schema problems
# --------------------------------------------------------------------------

def test_load_authority_rows_enforces_canonical_schema():
    with pytest.raises(ValueError, match="missing required fields"):
        load_authority_rows(
            [{"ip": "192.0.2.10"}], authority_type="exact_ip", source="synthetic", sha256="0" * 64
        )


def test_load_authority_rows_enforces_expected_row_count():
    with pytest.raises(ValueError, match="Row-count mismatch"):
        load_authority_rows(
            [{"ip": "192.0.2.10", "organization": "Example University"}],
            authority_type="exact_ip",
            source="synthetic",
            sha256="0" * 64,
            expected_rows=5,
        )
