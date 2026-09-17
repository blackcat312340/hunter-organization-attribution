from __future__ import annotations

from collections.abc import Mapping

from .models import NormalizedHunterRecord
from .normalize import clean_text, derive_root_domain, normalize_asn, normalize_domain, normalize_ip


# Only reviewed Hunter fields and explicit aliases belong here. FOFA objects are
# intentionally not accepted as a separate runtime type.
SUPPORTED_INPUT_FIELDS = frozenset(
    {
        "ip", "domain", "root_domain", "host", "web_title", "title",
        "asn", "asn_organization", "asn_org", "hunter_record_id", "observed_at",
    }
)


def normalize_hunter_record(raw: Mapping[str, object], *, strict: bool = False) -> NormalizedHunterRecord:
    if strict:
        unknown = sorted(set(raw) - SUPPORTED_INPUT_FIELDS)
        if unknown:
            raise ValueError(f"Unsupported Hunter fields: {', '.join(unknown)}")

    domain = normalize_domain(raw.get("domain"))
    root = normalize_domain(raw.get("root_domain")) or derive_root_domain(domain)
    return NormalizedHunterRecord(
        ip=normalize_ip(raw.get("ip")),
        root_domain=root,
        domain=domain,
        host=clean_text(raw.get("host")),
        web_title=clean_text(raw.get("web_title") or raw.get("title")),
        asn=normalize_asn(raw.get("asn")),
        asn_organization=clean_text(raw.get("asn_organization") or raw.get("asn_org")),
        hunter_record_id=clean_text(raw.get("hunter_record_id")),
        observed_at=clean_text(raw.get("observed_at")),
    )

