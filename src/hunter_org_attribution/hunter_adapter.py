from __future__ import annotations

from collections.abc import Mapping

from .models import NormalizedHunterRecord
from .normalize import clean_text, derive_root_domain, normalize_asn, normalize_domain, normalize_ip, normalize_port


# Only reviewed Hunter fields and explicit aliases belong here. FOFA objects are
# intentionally not accepted as a separate runtime type.
SUPPORTED_INPUT_FIELDS = frozenset(
    {
        "ip", "port", "domain", "root_domain", "host", "web_title", "title",
        "asn", "asn_organization", "asn_org", "hunter_reported_country", "country",
        "infrastructure_category", "provider_family", "hunter_record_id", "observed_at",
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
        port=normalize_port(raw.get("port")),
        asn=normalize_asn(raw.get("asn")),
        asn_organization=clean_text(raw.get("asn_organization") or raw.get("asn_org")),
        root_domain=root,
        domain=domain,
        host=clean_text(raw.get("host")),
        web_title=clean_text(raw.get("web_title") or raw.get("title")),
        hunter_reported_country=clean_text(raw.get("hunter_reported_country") or raw.get("country")),
        infrastructure_category=clean_text(raw.get("infrastructure_category")),
        provider_family=clean_text(raw.get("provider_family")),
        hunter_record_id=clean_text(raw.get("hunter_record_id")),
        observed_at=clean_text(raw.get("observed_at")),
    )
