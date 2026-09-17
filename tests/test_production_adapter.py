import pytest

from hunter_org_attribution import AttributionEngine, project_measurement212_hunter_record
from hunter_org_attribution.production_adapter import MEASUREMENT212_SOURCE_SHA


def production_row(**overrides):
    row = {
        "ip": "192.0.2.44",
        "port": "8443",
        "asn": "64500",
        "root_domain": "example.edu",
        "domain": "lab.example.edu",
        "host": "https://lab.example.edu:8443",
        "web_title": "Example Research Portal",
        "country": "US",
        # Reviewed production fields that are deliberately not attribution inputs.
        "full_name": "example/service",
        "http_head": "HTTP/1.1 200 OK\r\nServer: example\r\n",
        "protocol_type": "https",
        "favicon": "deadbeef",
        "is_web": True,
        "city": "Example City",
        "updated_at": "2026-04-29T17:30:00Z",
        "banner_info": "opaque upstream metadata",
    }
    row.update(overrides)
    return row


def test_production_projection_consumes_only_reviewed_attribution_fields():
    projection = project_measurement212_hunter_record(production_row())
    record = projection.record

    assert record.ip == "192.0.2.44"
    assert record.port == 8443
    assert record.asn == 64500
    assert record.root_domain == "example.edu"
    assert record.domain == "lab.example.edu"
    assert record.web_title == "Example Research Portal"
    assert record.hunter_reported_country == "US"
    assert projection.source_sha == MEASUREMENT212_SOURCE_SHA
    assert projection.unknown_fields == ()

    assert set(projection.ignored_known_fields) == {
        "banner_info",
        "city",
        "favicon",
        "full_name",
        "http_head",
        "is_web",
        "protocol_type",
        "updated_at",
    }
    for field in projection.ignored_known_fields:
        assert not hasattr(record, field)


def test_upstream_updated_at_is_not_observation_provenance():
    projection = project_measurement212_hunter_record(
        production_row(updated_at="2026-04-29T17:30:00Z")
    )
    assert projection.record.observed_at is None
    assert "updated_at" in projection.ignored_known_fields

    explicit = project_measurement212_hunter_record(
        production_row(updated_at="2026-04-29T17:30:00Z"),
        observed_at="2026-04-30",
    )
    assert explicit.record.observed_at == "2026-04-30"


def test_upstream_matching_only_web_body_remains_outside_stored_contract():
    with pytest.raises(ValueError, match="Unreviewed Measurement 212 Hunter fields: web_body"):
        project_measurement212_hunter_record(production_row(web_body="must-not-enter-attribution"))


def test_service_label_cannot_become_organization_evidence():
    projection = project_measurement212_hunter_record(production_row(
        root_domain="",
        domain="",
        host="",
        web_title="",
        asn="",
        full_name="university/very-sensitive-service-name",
    ))
    result = AttributionEngine.from_repository_defaults().attribute(projection.record)

    assert result.resolution.organization_name is None
    assert result.resolution.categories == ()
    assert result.resolution.status == "unresolved"
    assert result.evidence == ()


def test_asn_enrichment_maps_only_network_context():
    projection = project_measurement212_hunter_record(
        production_row(asn="AS64500"),
        asn_enrichment={
            "asn": "64500",
            "asn_category": "cloud_hyperscaler",
            "provider_family": "Example Cloud",
            "is_cloud_provider": "true",
            "is_cloud_or_hosting_infra": "true",
            "classification_confidence": "high",
            "classification_rule": "synthetic-test-rule",
        },
    )

    assert projection.record.asn == 64500
    assert projection.record.infrastructure_category == "cloud_hyperscaler"
    assert projection.record.provider_family == "Example Cloud"
    assert projection.record.asn_organization is None
    assert "asn_category" in projection.enrichment_fields
    assert "provider_family" in projection.enrichment_fields


def test_asn_enrichment_mismatch_fails_closed():
    with pytest.raises(ValueError, match="ASN enrichment mismatch"):
        project_measurement212_hunter_record(
            production_row(asn="64500"),
            asn_enrichment={"asn": "64501", "asn_category": "isp_carrier"},
        )


def test_asn_enrichment_requires_record_asn():
    with pytest.raises(ValueError, match="requires a Hunter record ASN"):
        project_measurement212_hunter_record(
            production_row(asn=""),
            asn_enrichment={"asn": "64500", "asn_category": "isp_carrier"},
        )


def test_asn_enrichment_requires_lookup_asn_key():
    with pytest.raises(ValueError, match="row is missing its ASN key"):
        project_measurement212_hunter_record(
            production_row(asn="64500"),
            asn_enrichment={"asn_category": "isp_carrier"},
        )


def test_unreviewed_production_field_fails_closed_by_default():
    with pytest.raises(ValueError, match="Unreviewed Measurement 212 Hunter fields: mystery"):
        project_measurement212_hunter_record(production_row(mystery="value"))


def test_nonstrict_projection_reports_but_does_not_expose_unknown_fields():
    projection = project_measurement212_hunter_record(
        production_row(mystery="value"),
        strict_contract=False,
    )
    assert projection.unknown_fields == ("mystery",)
    assert not hasattr(projection.record, "mystery")


def test_unreviewed_asn_enrichment_field_fails_closed():
    with pytest.raises(ValueError, match="Unreviewed Measurement 212 ASN enrichment fields: asn_org"):
        project_measurement212_hunter_record(
            production_row(),
            asn_enrichment={"asn": "64500", "asn_org": "Invented Organization"},
        )


def test_projection_can_attach_external_record_metadata_without_using_it_as_evidence():
    projection = project_measurement212_hunter_record(
        production_row(),
        observed_at="2026-04-30",
        hunter_record_id="snapshot-20260430-line-17",
    )
    assert projection.record.observed_at == "2026-04-30"
    assert projection.record.hunter_record_id == "snapshot-20260430-line-17"
