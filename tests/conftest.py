from pathlib import Path

import pytest

from hunter_org_attribution import AttributionEngine, AuthoritySpec, load_authority
from hunter_org_attribution.provenance import sha256_file


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str, authority_type: str):
    path = FIXTURES / name
    return load_authority(AuthoritySpec(
        path=path,
        expected_sha256=sha256_file(path),
        authority_type=authority_type,
        source=f"synthetic-{authority_type}-v1",
        provenance={"synthetic": True},
    ))


@pytest.fixture
def engine():
    authorities = [
        load_fixture("ranges.yaml", "ipv4_ranges"),
        load_fixture("exact_ips.yaml", "exact_ip"),
        load_fixture("domains.yaml", "domains"),
        load_fixture("asns.yaml", "asn"),
    ]
    return AttributionEngine.from_repository_defaults(authorities)

