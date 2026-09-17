from pathlib import Path

from hunter_org_attribution import AttributionEngine, AuthoritySpec, load_authority, normalize_hunter_record
from hunter_org_attribution.export import to_json


# The path is illustrative. The file is local, hash-pinned, and never committed.
spec = AuthoritySpec(
    path=Path("private/institution_domains.yaml"),
    expected_sha256="replace-with-reviewed-sha256",
    authority_type="domains",
    source="reviewed-institution-domain-authority-v1",
    expected_rows=1,
    provenance={"publisher": "example", "reviewed_by": "replace-me"},
)
authority = load_authority(spec)
engine = AttributionEngine.from_repository_defaults([authority])
record = normalize_hunter_record({
    "ip": "192.0.2.10",
    "domain": "lab.example.edu",
    "host": "https://lab.example.edu/",
    "title": "Example University Lab",
    "asn": "AS64500",
    "asn_org": "Amazon.com, Inc.",
})
print(to_json(engine.attribute(record)))

