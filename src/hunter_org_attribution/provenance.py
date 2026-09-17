from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


MAX_ASN = 4_294_967_295

AUTHORITY_SCHEMAS = {
    "ipv4_ranges": {"start_ip", "end_ip", "organization"},
    "exact_ip": {"ip", "organization"},
    "domains": {"domain", "organization"},
    "asn": {"asn", "organization", "role"},
}


class AuthoritySourceError(ValueError):
    """Raised when an external authority source cannot be projected safely.

    Subclasses ``ValueError`` so existing fail-closed callers keep working.
    """


@dataclass(frozen=True)
class AuthoritySpec:
    path: Path
    expected_sha256: str
    authority_type: str
    source: str
    expected_rows: int | None = None
    provenance: dict[str, Any] | None = None


@dataclass(frozen=True)
class LoadedAuthority:
    authority_type: str
    source: str
    sha256: str
    rows: tuple[dict[str, Any], ...]
    audit: dict[str, Any]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_rows(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))
    if suffix in {".yaml", ".yml"}:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    elif suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        raise ValueError(f"Unsupported authority format: {suffix}")
    rows = payload.get("rows") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise ValueError("Authority must contain a list of row objects")
    return rows


def _validate_row(authority_type: str, row: dict[str, Any], index: int) -> None:
    required = AUTHORITY_SCHEMAS[authority_type]
    missing = sorted(key for key in required if row.get(key) in (None, ""))
    if missing:
        raise ValueError(f"Row {index} missing required fields: {', '.join(missing)}")

    if authority_type == "ipv4_ranges":
        start = ipaddress.ip_address(str(row["start_ip"]))
        end = ipaddress.ip_address(str(row["end_ip"]))
        if start.version != 4 or end.version != 4 or start > end:
            raise ValueError(f"Row {index} has invalid IPv4 range")
    elif authority_type == "exact_ip":
        address = ipaddress.ip_address(str(row["ip"]))
        if address.version != 4:
            raise ValueError(f"Row {index} must contain IPv4")
    elif authority_type == "domains":
        domain = str(row["domain"]).strip().lower().lstrip(".").rstrip(".")
        if not domain or " " in domain or "." not in domain:
            raise ValueError(f"Row {index} has invalid domain")
    elif authority_type == "asn":
        asn = int(str(row["asn"]).upper().removeprefix("AS"))
        if not 1 <= asn <= MAX_ASN:
            raise ValueError(f"Row {index} has invalid ASN")
        role = str(row["role"]).strip().lower()
        if role not in {"organization", "infrastructure", "network"}:
            raise ValueError(f"Row {index} has invalid ASN role: {role}")


def load_authority(spec: AuthoritySpec) -> LoadedAuthority:
    path = Path(spec.path)
    actual_hash = sha256_file(path)
    if actual_hash.lower() != spec.expected_sha256.lower():
        raise ValueError(f"SHA256 mismatch for {path}: expected {spec.expected_sha256}, got {actual_hash}")
    if spec.authority_type not in AUTHORITY_SCHEMAS:
        raise ValueError(f"Unknown authority type: {spec.authority_type}")
    rows = _read_rows(path)
    return load_authority_rows(
        rows,
        authority_type=spec.authority_type,
        source=spec.source,
        sha256=actual_hash,
        path=str(path),
        expected_rows=spec.expected_rows,
        provenance=spec.provenance,
    )


def load_authority_rows(
    rows: Iterable[Mapping[str, Any]],
    *,
    authority_type: str,
    source: str,
    sha256: str,
    path: str | None = None,
    expected_rows: int | None = None,
    provenance: dict[str, Any] | None = None,
) -> LoadedAuthority:
    """Validate canonical authority records and build a ``LoadedAuthority``.

    This is the single validation entry point shared by the file loader and by
    source-specific adapters. Adapters are responsible only for projecting an
    external source schema into the canonical column names; all structural
    validation still happens here.
    """
    if authority_type not in AUTHORITY_SCHEMAS:
        raise ValueError(f"Unknown authority type: {authority_type}")
    materialized = [dict(row) for row in rows]
    if expected_rows is not None and len(materialized) != expected_rows:
        raise ValueError(f"Row-count mismatch: expected {expected_rows}, got {len(materialized)}")
    for index, row in enumerate(materialized, start=1):
        _validate_row(authority_type, row, index)
    audit = {
        "path": path,
        "sha256": sha256,
        "row_count": len(materialized),
        "schema": authority_type,
        "source": source,
        "provenance": provenance or {},
        "normalization_report": {
            "rows_read": len(materialized),
            "transformations": "none; authority values are validated but preserved verbatim",
        },
    }
    return LoadedAuthority(authority_type, source, sha256, tuple(materialized), audit)
