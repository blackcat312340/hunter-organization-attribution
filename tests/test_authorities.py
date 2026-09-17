from pathlib import Path

import pytest

from hunter_org_attribution import AuthoritySpec, load_authority
from hunter_org_attribution.provenance import sha256_file


FIXTURES = Path(__file__).parent / "fixtures"


def test_authority_sha_mismatch_fails_closed():
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_authority(AuthoritySpec(
            path=FIXTURES / "domains.yaml",
            expected_sha256="0" * 64,
            authority_type="domains",
            source="synthetic",
        ))


def test_row_count_audit_fails_closed():
    path = FIXTURES / "domains.yaml"
    with pytest.raises(ValueError, match="Row-count mismatch"):
        load_authority(AuthoritySpec(
            path=path,
            expected_sha256=sha256_file(path),
            authority_type="domains",
            source="synthetic",
            expected_rows=999,
        ))


def test_audit_preserves_hash_schema_count_and_provenance():
    path = FIXTURES / "domains.yaml"
    loaded = load_authority(AuthoritySpec(
        path=path,
        expected_sha256=sha256_file(path),
        authority_type="domains",
        source="synthetic-domain-v1",
        expected_rows=2,
        provenance={"reviewed": True},
    ))
    assert loaded.audit["row_count"] == 2
    assert loaded.audit["schema"] == "domains"
    assert loaded.audit["provenance"] == {"reviewed": True}

