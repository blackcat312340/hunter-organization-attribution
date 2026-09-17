from hunter_org_attribution import normalize_hunter_record


def test_normalized_hunter_record_preserves_reviewed_runtime_fields():
    record = normalize_hunter_record({
        "ip": "192.0.2.1",
        "port": "8443",
        "asn": "AS64500",
        "asn_org": "Example Network",
        "domain": "lab.example.edu",
        "title": "Example University",
        "country": "US",
        "infrastructure_category": "cloud",
        "provider_family": "ExampleCloud",
    }, strict=True)
    assert record.port == 8443
    assert record.hunter_reported_country == "US"
    assert record.infrastructure_category == "cloud"
    assert record.provider_family == "ExampleCloud"


def test_evidence_contract_contains_rule_target_operator_source_and_authority(engine):
    result = engine.attribute(normalize_hunter_record({
        "ip": "192.0.2.10",
        "domain": "lab.example.edu",
    }))
    evidence = next(e for e in result.evidence if e.resolved_organization == "Example University")
    assert evidence.rule_id
    assert evidence.rule_family
    assert evidence.target == "organization_identity"
    assert evidence.matched_field
    assert evidence.observed_value
    assert evidence.operator
    assert evidence.pattern
    assert evidence.source
    assert evidence.authority


def test_resolution_exposes_agreement_ambiguity_and_asset_context(engine):
    result = engine.attribute(normalize_hunter_record({
        "ip": "192.0.2.10",
        "domain": "lab.example.edu",
        "asn": 64510,
        "asn_org": "Example University",
        "infrastructure_category": "education_network",
        "provider_family": "ExampleProvider",
    }))
    assert result.schema_version == "1.1.0"
    assert result.resolution.organization_name == "Example University"
    assert result.resolution.ambiguity_status == "unambiguous"
    assert result.resolution.agreement_status == "multi_rule_agreement"
    assert "multi_rule" in result.resolution.association_types
    assert result.resolution.infrastructure_category == "education_network"
    assert result.resolution.provider_family == "ExampleProvider"


def test_conflict_is_not_silently_overwritten(engine):
    result = engine.attribute(normalize_hunter_record({
        "ip": "198.51.100.5",
        "domain": "service.other.edu",
    }))
    assert result.resolution.status == "conflict"
    assert result.resolution.ambiguity_status == "ambiguous_conflict"
    assert result.resolution.agreement_status == "conflict"
    assert result.resolution.organization_name is None
    assert len(result.resolution.conflicting_organizations) == 2
