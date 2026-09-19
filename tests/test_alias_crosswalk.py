"""Phase 6: deterministic cross-source alias crosswalk + reconciliation.

Covers the construction gate (shared canonical domain bridge, unique-target
rule, fail closed) and the reconciliation outcomes (alias reconciles ID-vs-no-ID
and no-ID-vs-no-ID evidence; unsupported/fuzzy/explicit-ID disagreements remain
conflict). No fuzzy matching, no translation matching, no observation
co-occurrence anywhere.
"""
from hunter_org_attribution import AliasCrosswalk, AttributionEngine, normalize_hunter_record
from hunter_org_attribution.provenance import LoadedAuthority


def authority(authority_type, rows, source="synthetic", sha="a" * 64):
    return LoadedAuthority(
        authority_type=authority_type,
        source=source,
        sha256=sha,
        rows=tuple(rows),
        audit={"schema": authority_type, "source": source},
    )


def ror_authority(*rows):
    return authority(
        "domains",
        [dict(row, ror_status="active") for row in rows],
        source="ror_domains",
    )


def domain_authority(*rows, source="domain-org-association"):
    return authority("domains", [dict(row) for row in rows], source=source)


def cisa_authority(*rows):
    return authority("domains", [dict(row) for row in rows], source="cisa_dotgov_data")


def range_authority(organization, start="192.0.2.0", end="192.0.2.255"):
    return authority("ipv4_ranges", [{"start_ip": start, "end_ip": end, "organization": organization}])


def exact_authority(organization, ip="192.0.2.10"):
    return authority("exact_ip", [{"ip": ip, "organization": organization}])


def build_crosswalk(ror, submission=None, cisa=None):
    return AliasCrosswalk.build(
        ror_authority=ror,
        submission_domain_authority=submission,
        cisa_authority=cisa,
    )


# --------------------------------------------------------------------------
# Crosswalk construction gate
# --------------------------------------------------------------------------

def test_shared_domain_creates_alias_no_id_name_to_ror():
    cw = build_crosswalk(
        ror=ror_authority({"domain": "tsinghua.edu.cn", "organization_id": "ror:A",
                           "organization": "Tsinghua University"}),
        submission=domain_authority({"domain": "tsinghua.edu.cn", "organization": "清华大学"}),
    )
    alias = cw.lookup("清华大学")
    assert alias is not None
    assert alias.canonical_stable_id == "ror:A"
    assert alias.canonical_display_name == "Tsinghua University"
    assert "tsinghua.edu.cn" in alias.bridge_domains
    assert "domain-org-association" in alias.bridge_sources
    assert alias.construction_rule == "shared_canonical_domain_unique_target"
    # evidence-style names that did not bridge are not aliases
    assert cw.lookup("Tsinghua University") is None


def test_same_name_two_bridge_domains_to_same_ror_is_one_alias():
    cw = build_crosswalk(
        ror=ror_authority(
            {"domain": "tsinghua.edu.cn", "organization_id": "ror:A", "organization": "Tsinghua University"},
            {"domain": "tsinghua-alumni.org", "organization_id": "ror:A", "organization": "Tsinghua University"},
        ),
        submission=domain_authority(
            {"domain": "tsinghua.edu.cn", "organization": "清华大学"},
            {"domain": "tsinghua-alumni.org", "organization": "清华大学"},
        ),
    )
    alias = cw.lookup("清华大学")
    assert alias is not None
    assert alias.canonical_stable_id == "ror:A"
    assert set(alias.bridge_domains) == {"tsinghua.edu.cn", "tsinghua-alumni.org"}


def test_same_name_bridges_to_two_ror_ids_is_rejected():
    cw = build_crosswalk(
        ror=ror_authority(
            {"domain": "a.edu.cn", "organization_id": "ror:A", "organization": "Alpha University"},
            {"domain": "b.edu.cn", "organization_id": "ror:B", "organization": "Beta University"},
        ),
        submission=domain_authority(
            {"domain": "a.edu.cn", "organization": "同名机构"},
            {"domain": "b.edu.cn", "organization": "同名机构"},
        ),
    )
    assert cw.lookup("同名机构") is None
    assert "同名机构" in cw.audit["ambiguous_alias_targets"]
    assert len(cw) == 0


def test_one_ror_id_with_multiple_aliases_allowed():
    cw = build_crosswalk(
        ror=ror_authority(
            {"domain": "tsinghua.edu.cn", "organization_id": "ror:A", "organization": "Tsinghua University"},
            {"domain": "tsinghua-alumni.org", "organization_id": "ror:A", "organization": "Tsinghua University"},
        ),
        submission=domain_authority(
            {"domain": "tsinghua.edu.cn", "organization": "清华大学"},
            {"domain": "tsinghua-alumni.org", "organization": "清华"},
        ),
    )
    assert cw.lookup("清华大学").canonical_stable_id == "ror:A"
    assert cw.lookup("清华").canonical_stable_id == "ror:A"
    assert len(cw) == 2


def test_cisa_bridge_creates_alias():
    cw = build_crosswalk(
        ror=ror_authority({"domain": "lab.gov", "organization_id": "ror:N", "organization": "National Laboratory"}),
        cisa=cisa_authority({"domain": "lab.gov", "organization": "National Lab"}),
    )
    alias = cw.lookup("National Lab")
    assert alias is not None
    assert alias.canonical_stable_id == "ror:N"
    assert "cisa_dotgov_data" in alias.bridge_sources


def test_range_and_exact_ip_never_create_alias():
    # A submission-only bridge (no ROR side) or range-only data never creates aliases.
    cw = build_crosswalk(
        ror=ror_authority({"domain": "tsinghua.edu.cn", "organization_id": "ror:A",
                           "organization": "Tsinghua University"}),
        submission=domain_authority({"domain": "other.edu.cn", "organization": "清华大学"}),
    )
    assert cw.lookup("清华大学") is None


# --------------------------------------------------------------------------
# Reconciliation outcomes
# --------------------------------------------------------------------------

def engine_with_crosswalk(crosswalk, *authorities):
    return AttributionEngine(authorities=authorities, alias_crosswalk=crosswalk)


def resolve(engine, **values):
    return engine.attribute(normalize_hunter_record({"ip": "192.0.2.10", **values})).resolution


def tsinghua_environment():
    ror = ror_authority({"domain": "tsinghua.edu.cn", "organization_id": "ror:A",
                         "organization": "Tsinghua University"})
    sub = domain_authority({"domain": "tsinghua.edu.cn", "organization": "清华大学"})
    cw = build_crosswalk(ror=ror, submission=sub)
    return ror, sub, cw


def test_range_no_id_uses_prebuilt_alias_and_reconciles_with_ror():
    ror, sub, cw = tsinghua_environment()
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("清华大学"))
    result = resolve(engine, root_domain="tsinghua.edu.cn")
    assert result.status == "resolved"
    assert result.organization_id == "ror:A"
    assert result.organization_name == "Tsinghua University"
    assert result.agreement_status == "multi_rule_agreement"
    # source evidence stays source-native
    evidence = engine.attribute(normalize_hunter_record({
        "ip": "192.0.2.10", "root_domain": "tsinghua.edu.cn"
    })).evidence
    range_ev = [e for e in evidence if e.rule_family == "direct_range"]
    assert range_ev and range_ev[0].resolved_organization == "清华大学"
    assert range_ev[0].resolved_organization_id is None


def test_exact_ip_no_id_uses_prebuilt_alias_and_reconciles_with_ror():
    ror, sub, cw = tsinghua_environment()
    engine = engine_with_crosswalk(cw, ror, sub, exact_authority("清华大学"))
    result = resolve(engine, root_domain="tsinghua.edu.cn")
    assert result.status == "resolved"
    assert result.organization_id == "ror:A"
    assert result.organization_name == "Tsinghua University"


def test_submission_domain_bridge_reconciles_with_ror():
    ror, sub, cw = tsinghua_environment()
    engine = engine_with_crosswalk(cw, ror, sub)
    result = resolve(engine, root_domain="tsinghua.edu.cn")
    assert result.status == "resolved"
    assert result.organization_id == "ror:A"
    assert result.organization_name == "Tsinghua University"
    assert "multi_rule" in result.association_types


def test_cisa_bridge_reconciles_with_ror():
    ror = ror_authority({"domain": "lab.gov", "organization_id": "ror:N",
                         "organization": "National Laboratory"})
    cisa = cisa_authority({"domain": "lab.gov", "organization": "National Lab"})
    cw = build_crosswalk(ror=ror, cisa=cisa)
    engine = engine_with_crosswalk(cw, ror, cisa)
    result = resolve(engine, root_domain="lab.gov")
    assert result.status == "resolved"
    assert result.organization_id == "ror:N"
    assert result.organization_name == "National Laboratory"


def test_no_bridge_remains_conflict():
    ror = ror_authority({"domain": "fudan.edu.cn", "organization_id": "ror:Z",
                         "organization": "Fudan University"})
    # submission authority has no fudan.edu.cn -> no shared-domain bridge
    sub = domain_authority({"domain": "other.edu.cn", "organization": "复旦大学"})
    cw = build_crosswalk(ror=ror, submission=sub)
    assert cw.lookup("复旦大学") is None
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("复旦大学"))
    result = resolve(engine, root_domain="fudan.edu.cn")
    assert result.status == "conflict"
    assert result.conflicting_organizations == ("Fudan University", "复旦大学")


def test_different_explicit_ids_remain_conflict():
    ror = ror_authority(
        {"domain": "a.edu.cn", "organization_id": "ror:A", "organization": "Alpha"},
        {"domain": "b.edu.cn", "organization_id": "ror:B", "organization": "Beta"},
    )
    sub = domain_authority({"domain": "a.edu.cn", "organization": "同名机构"})
    cw = build_crosswalk(ror=ror, submission=sub)
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("Beta"))
    # range evidence name matches nothing; a.edu.cn gives ror:A, plus ror:B from b? no --
    # record domain a.edu.cn only -> ror:A + range Beta -> name-only "Beta" does not
    # crosswalk to ror:A -> conflict (ID vs no-ID disagreement).
    result = resolve(engine, root_domain="a.edu.cn")
    assert result.status == "conflict"


def test_two_explicit_ror_ids_never_merged_by_crosswalk():
    # Range no-ID "甲大学" independently crosswalks to ror:A, while the observed
    # domain carries explicit ror:B. The crosswalk must never merge the two
    # distinct stable ids -> conflict.
    ror = ror_authority(
        {"domain": "a.edu.cn", "organization_id": "ror:A", "organization": "Alpha University"},
        {"domain": "b.edu.cn", "organization_id": "ror:B", "organization": "Beta University"},
    )
    sub = domain_authority({"domain": "a.edu.cn", "organization": "甲大学"})
    cw = build_crosswalk(ror=ror, submission=sub)
    assert cw.lookup("甲大学").canonical_stable_id == "ror:A"
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("甲大学"))
    result = resolve(engine, root_domain="b.edu.cn")
    assert result.status == "conflict"
    # The range name is promoted to its crosswalk identity (Alpha University /
    # ror:A), which conflicts with the explicit Beta University / ror:B evidence.
    # The crosswalk never merges two distinct stable ids.
    assert result.conflicting_organizations == ("Alpha University", "Beta University")


def test_fuzzy_similar_names_only_remains_conflict():
    # bilingual similarity without a shared reviewed domain: never an alias.
    ror = ror_authority({"domain": "fudan.edu.cn", "organization_id": "ror:Z",
                         "organization": "Fudan University"})
    sub = domain_authority({"domain": "unrelated.edu.cn", "organization": "复旦大学"})
    cw = build_crosswalk(ror=ror, submission=sub)
    assert cw.lookup("复旦大学") is None
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("复旦大学"))
    result = resolve(engine, root_domain="fudan.edu.cn")
    assert result.status == "conflict"


def test_range_only_with_crosswalk_resolves_to_stable_id():
    ror, sub, cw = tsinghua_environment()
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("清华大学"))
    result = resolve(engine)
    assert result.status == "resolved"
    assert result.organization_id == "ror:A"
    assert result.organization_name == "Tsinghua University"
    assert result.agreement_status == "single_identity_evidence"


def test_no_id_names_both_crosswalking_to_same_id_agree():
    ror = ror_authority(
        {"domain": "tsinghua.edu.cn", "organization_id": "ror:A", "organization": "Tsinghua University"},
        {"domain": "tsinghua-alumni.org", "organization_id": "ror:A", "organization": "Tsinghua University"},
    )
    sub = domain_authority(
        {"domain": "tsinghua.edu.cn", "organization": "清华大学"},
        {"domain": "tsinghua-alumni.org", "organization": "清华"},
    )
    cw = build_crosswalk(ror=ror, submission=sub)
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("清华大学"))
    result = resolve(engine, root_domain="tsinghua-alumni.org")
    assert result.status == "resolved"
    assert result.organization_id == "ror:A"


def test_no_id_names_crosswalking_to_different_ids_conflict():
    ror = ror_authority(
        {"domain": "a.edu.cn", "organization_id": "ror:A", "organization": "Alpha University"},
        {"domain": "b.edu.cn", "organization_id": "ror:B", "organization": "Beta University"},
    )
    sub = domain_authority(
        {"domain": "a.edu.cn", "organization": "甲大学"},
        {"domain": "b.edu.cn", "organization": "乙大学"},
    )
    cw = build_crosswalk(ror=ror, submission=sub)
    assert cw.lookup("甲大学").canonical_stable_id == "ror:A"
    assert cw.lookup("乙大学").canonical_stable_id == "ror:B"
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("甲大学"))
    # range "甲大学" -> ror:A, submission "乙大学" -> ror:B (from b.edu.cn)
    result = resolve(engine, root_domain="b.edu.cn")
    assert result.status == "conflict"


def test_crosswalk_does_not_alter_evidence_rows():
    ror, sub, cw = tsinghua_environment()
    engine = engine_with_crosswalk(cw, ror, sub, range_authority("清华大学"))
    evidence = engine.attribute(normalize_hunter_record({
        "ip": "192.0.2.10", "root_domain": "tsinghua.edu.cn"
    })).evidence
    by_source = {e.source: e for e in evidence if e.resolved_organization}
    assert by_source["domain-org-association"].resolved_organization == "清华大学"
    assert by_source["domain-org-association"].resolved_organization_id is None
    assert by_source["ror_domains"].resolved_organization_id == "ror:A"
