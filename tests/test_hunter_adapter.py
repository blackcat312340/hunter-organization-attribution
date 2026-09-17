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

