from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def clean_text(value: object) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).strip().split())
    return text or None


def normalize_ip(value: object) -> str:
    text = clean_text(value)
    if not text:
        raise ValueError("Hunter record requires ip")
    address = ipaddress.ip_address(text)
    if address.version != 4:
        raise ValueError("Phase 1 supports IPv4 only")
    return str(address)


def normalize_domain(value: object) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    candidate = text if "://" in text else f"//{text}"
    parsed = urlsplit(candidate)
    host = parsed.hostname or parsed.path.split("/")[0]
    host = host.rstrip(".").lower()
    return host or None


def normalize_asn(value: object) -> int | None:
    text = clean_text(value)
    if not text:
        return None
    if text.upper().startswith("AS"):
        text = text[2:]
    asn = int(text)
    if asn <= 0:
        raise ValueError("ASN must be positive")
    return asn


def derive_root_domain(domain: str | None) -> str | None:
    """Conservative fallback; prefer Hunter/reviewed enrichment root_domain."""
    if not domain:
        return None
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    common_second_level = {"ac", "co", "com", "edu", "gov", "net", "org"}
    if len(labels[-2]) <= 3 and labels[-2] in common_second_level:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

