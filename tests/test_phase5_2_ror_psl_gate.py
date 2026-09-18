"""Phase 5.2: ROR public-suffix domain quality gate.

The ROR adapter drops a canonical source-provided domain when it is itself a PSL
public suffix (ICANN or PRIVATE section), and does so *before* ambiguity
detection. A generic public-suffix authority key (``edu.cn``) therefore never
becomes a propagatable organization identity root and cannot pollute a real
registrable domain (``tsinghua.edu.cn``) that merely shares its suffix.

The ten previously-identified generic SLDs are exercised as a test matrix; the
gate itself is a PSL algorithm, not a blacklist, so every value in the matrix is
classified by ``PublicSuffixList`` semantics.
"""

from hunter_org_attribution import (
    AttributionEngine,
    PublicSuffixList,
    adapt_ror_domains,
    load_ror_domain_authority,
    normalize_hunter_record,
)
from hunter_org_attribution.provenance import load_authority_rows

from psl_mini import MINI_PSL, build_psl


def ror_record(ror_id, name, domains, status="active"):
    return {
        "id": ror_id,
        "status": status,
        "names": [{"value": name, "types": ["ror_display", "label"]}],
        "domains": domains,
    }


KNOWN_GENERIC_SLDS = [
    "edu.cn",
    "ac.th",
    "edu.in",
    "edu.mx",
    "edu.br",
    "edu.et",
    "edu.ng",
    "edu.np",
    "edu.om",
    "edu.ua",
]


# --------------------------------------------------------------------------
# Generic public suffix -> dropped; registrable subdomain -> retained
# --------------------------------------------------------------------------

def test_psl_gate_drops_edu_cn():
    rows, counts = adapt_ror_domains(
        [ror_record("0gen001", "Generic CN Edu", ["edu.cn"])], psl=build_psl()
    )
    assert rows == []
    assert counts["public_suffix_domain_entries_dropped"] == 1
    assert counts["public_suffix_unique_keys_dropped"] == 1
    assert counts["public_suffix_icann_dropped"] == 1
    assert counts["public_suffix_private_dropped"] == 0
    assert counts["usable_unique_domains"] == 0


def test_psl_gate_retains_tsinghua_edu_cn():
    rows, counts = adapt_ror_domains(
        [ror_record("0tsing01", "Tsinghua University", ["tsinghua.edu.cn"])], psl=build_psl()
    )
    assert [row["domain"] for row in rows] == ["tsinghua.edu.cn"]
    assert counts["public_suffix_domain_entries_dropped"] == 0
    assert counts["usable_unique_domains"] == 1


def test_psl_gate_drops_ac_th():
    rows, counts = adapt_ror_domains(
        [ror_record("0acth01", "Generic TH Acad", ["ac.th"])], psl=build_psl()
    )
    assert rows == []
    assert counts["public_suffix_domain_entries_dropped"] == 1


def test_psl_gate_retains_example_ac_th():
    rows, counts = adapt_ror_domains(
        [ror_record("0acth02", "Example TH Acad", ["example.ac.th"])], psl=build_psl()
    )
    assert [row["domain"] for row in rows] == ["example.ac.th"]
    assert counts["public_suffix_domain_entries_dropped"] == 0


def test_psl_gate_drops_edu_in():
    rows, counts = adapt_ror_domains(
        [ror_record("0edin01", "Generic IN Edu", ["edu.in"])], psl=build_psl()
    )
    assert rows == []
    assert counts["public_suffix_domain_entries_dropped"] == 1


def test_psl_gate_retains_example_edu_in():
    rows, counts = adapt_ror_domains(
        [ror_record("0edin02", "Example IN Edu", ["example.edu.in"])], psl=build_psl()
    )
    assert [row["domain"] for row in rows] == ["example.edu.in"]
    assert counts["public_suffix_domain_entries_dropped"] == 0


# --------------------------------------------------------------------------
# PRIVATE section
# --------------------------------------------------------------------------

def test_psl_gate_drops_private_public_suffix_itself():
    rows, counts = adapt_ror_domains(
        [ror_record("0gh001", "Pages Org", ["github.io"])], psl=build_psl()
    )
    assert rows == []
    assert counts["public_suffix_private_dropped"] == 1
    assert counts["public_suffix_icann_dropped"] == 0
    assert counts["public_suffix_unique_keys_dropped"] == 1


def test_psl_gate_retains_private_section_subdomain():
    rows, counts = adapt_ror_domains(
        [ror_record("0gh002", "User Org", ["myorg.github.io"])], psl=build_psl()
    )
    assert [row["domain"] for row in rows] == ["myorg.github.io"]
    assert counts["public_suffix_domain_entries_dropped"] == 0
    assert counts["public_suffix_unique_keys_dropped"] == 0


# --------------------------------------------------------------------------
# Processing order: PSL gate before ambiguity detection
# --------------------------------------------------------------------------

def test_psl_gate_runs_before_ambiguity_detection():
    records = [
        ror_record("0gen001", "Generic CN Edu", ["edu.cn"]),
        ror_record("0tsing01", "Tsinghua University", ["tsinghua.edu.cn"]),
    ]
    rows, counts = adapt_ror_domains(records, psl=build_psl())
    domains = {row["domain"] for row in rows}
    assert "edu.cn" not in domains
    assert "tsinghua.edu.cn" in domains
    assert counts["ambiguous_domain_keys_dropped"] == 0
    assert counts["public_suffix_unique_keys_dropped"] == 1


def test_psl_gate_prevents_generic_key_from_poisoning_shared_subdomain():
    # Without the gate, the generic edu.cn authority key survives and the
    # engine's suffix matcher makes it over-propagate onto tsinghua.edu.cn,
    # producing an artificial ROR-ROR conflict. With the gate, edu.cn is dropped
    # before ambiguity so tsinghua.edu.cn resolves to its single real claim.
    records = [
        ror_record("0gen001", "Generic CN Edu", ["edu.cn"]),
        ror_record("0tsing01", "Tsinghua University", ["tsinghua.edu.cn"]),
    ]
    ungated_rows, _ = adapt_ror_domains(records)
    assert {r["domain"] for r in ungated_rows} == {"edu.cn", "tsinghua.edu.cn"}
    ungated_engine = AttributionEngine.from_repository_defaults(authorities=[
        load_authority_rows(ungated_rows, authority_type="domains", source="ror_domains", sha256="3" * 64)
    ])
    poisoned = ungated_engine.attribute(normalize_hunter_record({"ip": "203.0.113.9", "domain": "tsinghua.edu.cn"}))
    assert poisoned.resolution.status == "conflict"
    ror_ids = {
        e.resolved_organization_id for e in poisoned.evidence
        if e.resolved_organization_id and e.resolved_organization_id.startswith("ror:")
    }
    assert ror_ids == {"ror:0gen001", "ror:0tsing01"}

    rows, counts = adapt_ror_domains(records, psl=build_psl())
    assert {r["domain"] for r in rows} == {"tsinghua.edu.cn"}
    assert counts["public_suffix_unique_keys_dropped"] == 1
    gated_engine = AttributionEngine.from_repository_defaults(authorities=[
        load_authority_rows(rows, authority_type="domains", source="ror_domains", sha256="2" * 64)
    ])
    result = gated_engine.attribute(normalize_hunter_record({"ip": "203.0.113.9", "domain": "tsinghua.edu.cn"}))
    assert result.resolution.status == "resolved"
    assert result.resolution.organization_id == "ror:0tsing01"


def test_psl_gate_drops_two_generic_claims_without_ambiguity():
    records = [
        ror_record("0a", "Org A", ["ac.th"]),
        ror_record("0b", "Org B", ["ac.th"]),
    ]
    rows, counts = adapt_ror_domains(records, psl=build_psl())
    assert rows == []
    assert counts["ambiguous_domain_keys_dropped"] == 0
    assert counts["public_suffix_domain_entries_dropped"] == 2
    assert counts["public_suffix_unique_keys_dropped"] == 1


def test_psl_gate_does_not_change_active_ambiguity_semantics_for_registrable_domains():
    records = [
        ror_record("0act0004", "Org A", ["dup.shared.example.net"]),
        ror_record("0act0005", "Org B", ["dup.shared.example.net"]),
    ]
    rows, counts = adapt_ror_domains(records, psl=build_psl())
    assert all(row["domain"] != "dup.shared.example.net" for row in rows)
    assert counts["ambiguous_domain_keys_dropped"] == 1
    assert counts["public_suffix_domain_entries_dropped"] == 0


# --------------------------------------------------------------------------
# Status regression through the gated adapter
# --------------------------------------------------------------------------

def test_psl_gate_preserves_active_only_status_semantics():
    psl = build_psl()
    records = [
        ror_record("0act001", "Active Org", ["active.example.edu"], status="active"),
        ror_record("0inact01", "Retired Org", ["retired.example.org"], status="inactive"),
        ror_record("0withd01", "Withdrawn Org", ["withdrawn.example.org"], status="withdrawn"),
        ror_record("0gen001", "Generic CN Edu", ["edu.cn"], status="active"),
    ]
    rows, counts = adapt_ror_domains(records, psl=psl)
    assert {row["domain"] for row in rows} == {"active.example.edu"}
    assert counts["active_records"] == 2
    assert counts["inactive_records"] == 1
    assert counts["withdrawn_records"] == 1
    assert counts["inactive_domain_entries_dropped"] == 1
    assert counts["withdrawn_domain_entries_dropped"] == 1
    assert counts["public_suffix_domain_entries_dropped"] == 1


# --------------------------------------------------------------------------
# Known ten generic SLDs: algorithmic classification, not a blacklist
# --------------------------------------------------------------------------

def test_known_ten_generic_slds_are_public_suffixes_by_algorithm():
    psl = build_psl()
    for sld in KNOWN_GENERIC_SLDS:
        assert psl.is_public_suffix(sld), sld


def test_known_ten_generic_slds_never_become_eligible_ror_identity():
    psl = build_psl()
    for sld in KNOWN_GENERIC_SLDS:
        rows, counts = adapt_ror_domains(
            [ror_record("0matrix01", "Generic Matrix Org", [sld])], psl=psl
        )
        assert rows == [], sld
        assert counts["public_suffix_domain_entries_dropped"] == 1, sld
        assert counts["usable_unique_domains"] == 0, sld


def test_algorithmic_gate_also_drops_unlisted_public_suffixes():
    # co.uk is not one of the ten known values; the algorithm drops it anyway.
    psl = build_psl()
    rows, counts = adapt_ror_domains(
        [ror_record("0cou01", "Generic UK Edu", ["co.uk"])], psl=psl
    )
    assert rows == []
    assert counts["public_suffix_domain_entries_dropped"] == 1


# --------------------------------------------------------------------------
# Positive controls
# --------------------------------------------------------------------------

def test_positive_control_harvard_edu_retained():
    psl = build_psl()
    assert psl.is_public_suffix("harvard.edu") is False
    rows, counts = adapt_ror_domains(
        [ror_record("0harv01", "Harvard University", ["harvard.edu"])], psl=psl
    )
    assert [row["domain"] for row in rows] == ["harvard.edu"]
    assert counts["public_suffix_domain_entries_dropped"] == 0


# --------------------------------------------------------------------------
# Loader provenance
# --------------------------------------------------------------------------

def test_loader_records_psl_provenance(tmp_path):
    import json
    from pathlib import Path

    from hunter_org_attribution.provenance import sha256_file

    psl_file = tmp_path / "psl.dat"
    psl_file.write_text(MINI_PSL, encoding="utf-8")
    ror_file = tmp_path / "ror.json"
    ror_file.write_text(json.dumps([
        ror_record("0gen001", "Generic CN Edu", ["edu.cn"]),
        ror_record("0tsing01", "Tsinghua University", ["tsinghua.edu.cn"]),
    ]), encoding="utf-8")

    loaded = load_ror_domain_authority(
        ror_file,
        expected_sha256=sha256_file(ror_file),
        source="ror_domains",
        provenance={"version": "v2.test"},
        psl_path=psl_file,
        psl_sha256=sha256_file(psl_file),
        psl_source="https://publicsuffix.org/list/public_suffix_list.dat",
        psl_retrieved_at="2026-09-18T00:00:00Z",
    )
    provenance = loaded.audit["provenance"]
    assert provenance["psl_source"] == "https://publicsuffix.org/list/public_suffix_list.dat"
    assert provenance["psl_sha256"] == sha256_file(psl_file)
    assert provenance["psl_retrieved_at"] == "2026-09-18T00:00:00Z"
    assert "psl_quality_policy" in provenance
    assert provenance["adapter_counts"]["public_suffix_domain_entries_dropped"] == 1
    assert provenance["adapter_counts"]["public_suffix_unique_keys_dropped"] == 1
    assert provenance["adapter_counts"]["usable_unique_domains"] == 1
    assert {row["domain"] for row in loaded.rows} == {"tsinghua.edu.cn"}
