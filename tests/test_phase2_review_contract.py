from hunter_org_attribution.production_adapter import (
    MEASUREMENT212_ASN_LOOKUP_SCRIPT_BLOB,
    MEASUREMENT212_SOURCE_SCRIPT_BLOB,
    MEASUREMENT212_SOURCE_SHA,
)


def test_phase2_upstream_contract_is_pinned_to_reviewed_sources():
    assert MEASUREMENT212_SOURCE_SHA == "2ba9545f87b55d393e3e155fea75deb165b7b9ac"
    assert MEASUREMENT212_SOURCE_SCRIPT_BLOB == "89a7d1fc1e0cfce4f90b129c53c36476a5ccc7a6"
    assert MEASUREMENT212_ASN_LOOKUP_SCRIPT_BLOB == "49ae1e784de77a515d0fe75c950e1fe560a78f4b"
