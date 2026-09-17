import pytest

from hunter_org_attribution import normalize_hunter_record


def test_normalized_hunter_schema_and_aliases():
    record = normalize_hunter_record({
        "ip": "192.0.2.1",
        "domain": "Lab.Example.EDU.",
        "title": "  Example   Lab ",
        "asn": "AS64500",
        "asn_org": "Example Network",
    })
    assert record.ip == "192.0.2.1"
    assert record.domain == "lab.example.edu"
    assert record.root_domain == "example.edu"
    assert record.web_title == "Example Lab"
    assert record.asn == 64500


def test_unsupported_hunter_field_is_rejected_in_strict_mode():
    with pytest.raises(ValueError, match="Unsupported Hunter fields: body"):
        normalize_hunter_record({"ip": "192.0.2.1", "body": "University"}, strict=True)


def test_unsupported_field_is_never_exposed_to_rules():
    record = normalize_hunter_record({"ip": "203.0.113.1", "body": "University"})
    assert not hasattr(record, "body")


def test_conflicting_alias_values_fail_closed_in_strict_mode():
    with pytest.raises(ValueError, match="Conflicting Hunter fields: web_title and alias title"):
        normalize_hunter_record({
            "ip": "192.0.2.1",
            "web_title": "Canonical Title",
            "title": "Different Title",
        }, strict=True)


def test_matching_alias_values_are_accepted_in_strict_mode():
    record = normalize_hunter_record({
        "ip": "192.0.2.1",
        "asn_organization": "Example Network",
        "asn_org": "Example Network",
    }, strict=True)
    assert record.asn_organization == "Example Network"


def test_asn_must_fit_32_bit_asn_space():
    with pytest.raises(ValueError, match="ASN must be between"):
        normalize_hunter_record({"ip": "192.0.2.1", "asn": 4_294_967_296})
