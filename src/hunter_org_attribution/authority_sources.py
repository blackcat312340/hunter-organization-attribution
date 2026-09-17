"""Reviewed source adapters for external organization-identity authorities.

Layering (nothing below the adapter learns about a specific external schema)::

    external authority source
            -> source-specific reviewed adapter      (this module)
            -> canonical authority records           (organization / start_ip / ...)
            -> existing authority loader/index       (provenance.load_authority_rows)
            -> existing attribution engine           (engine.AttributionEngine)

Each adapter declares which external columns it consumes, which canonical
columns it produces, and a stable adapter identifier that is carried into the
authority audit and therefore into every piece of evidence provenance.

Semantics preserved deliberately:

- The China education/research IPv4 export is an institution **range** authority:
  ``observed IP is contained in a reviewed organization IPv4 range``.
- ``domain,org`` is a reviewed/derived **domain association** authority; it is
  matched with the engine's existing label-boundary domain semantics and is not
  expanded into substring matching.
- ``ip,org`` is an **exact-IP association** authority. It is never expanded into
  a subnet, CIDR block, or neighbouring-address range.

None of these adapters infer country, category, ownership, or deployment from an
organization name. The resulting attribution statement stays
``the observed IP/service is associated with organization X according to evidence Y``.
"""

from __future__ import annotations

import csv
import ipaddress
import json
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from .provenance import AuthoritySourceError, LoadedAuthority, load_authority_rows, sha256_file


CHINA_INSTITUTION_RANGE_ADAPTER = "reviewed-adapter:china-institution-ipv4-range:v1"
DOMAIN_ORG_ASSOCIATION_ADAPTER = "reviewed-adapter:domain-org-association:v1"
EXACT_IP_ORG_ASSOCIATION_ADAPTER = "reviewed-adapter:exact-ip-org-association:v1"
GOV_DOMAIN_REGISTRY_ADAPTER = "reviewed-adapter:gov-domain-registry:v1"
ROR_DOMAIN_AUTHORITY_ADAPTER = "reviewed-adapter:ror-domain-authority:v1"

CHINA_INSTITUTION_RANGE_SOURCE_COLUMNS = ("org", "start_ip", "end_ip")
DOMAIN_ORG_SOURCE_COLUMNS = ("domain", "org")
EXACT_IP_ORG_SOURCE_COLUMNS = ("ip", "org")
CISA_DOTGOV_SOURCE_COLUMNS = ("Domain name", "Organization name")
ROR_DOMAIN_SOURCE_COLUMNS = ("id", "domains", "names")

# The global .gov registrar publishes no stable organization identifier: only a
# free-text organization name. No identifier is invented from it.
CISA_DOTGOV_SOURCE_ID = "cisa_dotgov_data"

# ROR identifiers are compared only inside their own namespace.
ROR_NAMESPACE = "ror"

_ORGANIZATION_ALIASES = ("organization", "org")


def _clean(value: object) -> str:
    return " ".join(str(value).strip().split()) if value is not None else ""


def _organization_from(row: Mapping[str, Any], index: int) -> str:
    for key in _ORGANIZATION_ALIASES:
        if key in row:
            return _clean(row.get(key))
    raise AuthoritySourceError(f"Row {index} is missing an organization column (expected one of {_ORGANIZATION_ALIASES})")


def _require_columns(row: Mapping[str, Any], columns: Iterable[str], index: int) -> None:
    missing = [column for column in columns if column not in row]
    if missing:
        raise AuthoritySourceError(f"Row {index} is missing source columns: {', '.join(missing)}")


def _project_uniquely(
    rows: list[dict[str, Any]],
    *,
    key_columns: tuple[str, ...],
    kind: str,
) -> tuple[list[dict[str, Any]], int]:
    """Drop exact duplicate projections; fail closed on conflicting projections.

    Two source rows sharing a key but naming different organizations cannot be
    represented as one canonical authority record, so they fail closed rather
    than resolving by row order.
    """
    seen: dict[tuple[str, ...], dict[str, Any]] = {}
    duplicates = 0
    for row in rows:
        key = tuple(row[column] for column in key_columns)
        if key in seen:
            if seen[key]["organization"] != row["organization"]:
                raise AuthoritySourceError(
                    f"Conflicting {kind} rows for {key}: "
                    f"{seen[key]['organization']!r} vs {row['organization']!r}"
                )
            duplicates += 1
            continue
        seen[key] = row
    return list(seen.values()), duplicates


def _parse_address(value: str, index: int) -> ipaddress.IPv4Address | None:
    """Return an IPv4 address, ``None`` for an out-of-scope IPv6 address.

    The method is IPv4-only, so a well-formed IPv6 address is out of scope
    rather than malformed; callers drop and count it. Anything unparseable is a
    structural fault and fails closed.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AuthoritySourceError(f"Row {index} has an invalid IP address: {exc}") from exc
    if address.version != 4:
        return None
    return address


def _finalize(
    rows: list[dict[str, Any]],
    *,
    authority_type: str,
    source: str,
    sha256: str,
    adapter: str,
    source_columns: tuple[str, ...],
    path: str | None,
    expected_rows: int | None,
    provenance: Mapping[str, Any] | None,
    counts: Mapping[str, int],
    duplicate_rows_removed: int,
) -> LoadedAuthority:
    audit_provenance = dict(provenance or {})
    audit_provenance.update(
        {
            "adapter": adapter,
            "source_columns": list(source_columns),
            "unmapped_rows_dropped": counts.get("unmapped_rows", 0),
            "out_of_scope_rows_dropped": counts.get("out_of_scope_rows", 0),
            "out_of_scope_reason": "IPv6 addresses are out of scope for the IPv4-only method",
            "duplicate_rows_removed": duplicate_rows_removed,
            # Every adapter-specific counter (for example the ROR
            # ``ambiguous_domain_keys_dropped``) stays visible in the authority
            # audit so aggregate ingestion statistics are reproducible.
            "adapter_counts": dict(sorted(counts.items())),
            "association_semantics": (
                "reviewed/derived organization association; not an ownership, "
                "deployment, or operational-responsibility claim"
            ),
        }
    )
    return load_authority_rows(
        rows,
        authority_type=authority_type,
        source=source,
        sha256=sha256,
        path=path,
        expected_rows=expected_rows,
        provenance=audit_provenance,
    )


def adapt_china_institution_ranges(
    source_rows: Iterable[Any],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Project headerless ``org,start_ip,end_ip`` rows into canonical range rows.

    Returns ``(canonical_rows, counts)`` where ``counts`` separates rows dropped
    because they carry no association (``unmapped_rows``) from rows dropped
    because they are IPv6 and therefore out of scope (``out_of_scope_rows``).
    """
    projected: list[dict[str, Any]] = []
    unmapped = 0
    out_of_scope = 0
    for index, row in enumerate(source_rows, start=1):
        if isinstance(row, Mapping):
            _require_columns(row, ("start_ip", "end_ip"), index)
            organization = _organization_from(row, index)
            start_ip = _clean(row.get("start_ip"))
            end_ip = _clean(row.get("end_ip"))
        elif isinstance(row, Sequence) and not isinstance(row, (str, bytes)):
            if len(row) != 3:
                raise AuthoritySourceError(
                    f"Row {index} must have exactly 3 columns {CHINA_INSTITUTION_RANGE_SOURCE_COLUMNS}, got {len(row)}"
                )
            organization, start_ip, end_ip = (_clean(cell) for cell in row)
        else:
            raise AuthoritySourceError(f"Row {index} has unsupported source shape: {type(row).__name__}")

        if not organization:
            unmapped += 1
            continue
        start = _parse_address(start_ip, index)
        end = _parse_address(end_ip, index)
        if start is None or end is None:
            out_of_scope += 1
            continue
        if start > end:
            raise AuthoritySourceError(f"Row {index} has an inverted range: {start} > {end}")
        projected.append(
            {"organization": organization, "start_ip": str(start), "end_ip": str(end)}
        )
    return projected, {"unmapped_rows": unmapped, "out_of_scope_rows": out_of_scope}


def adapt_domain_org(source_rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Project ``domain,org`` rows into canonical ``domain`` authority rows."""
    projected: list[dict[str, Any]] = []
    unmapped = 0
    for index, row in enumerate(source_rows, start=1):
        _require_columns(row, ("domain",), index)
        organization = _organization_from(row, index)
        domain = _clean(row.get("domain")).lower().lstrip(".").rstrip(".")
        if not organization or not domain:
            # An absent organization carries no association; it is dropped and counted.
            unmapped += 1
            continue
        if " " in domain or "." not in domain:
            raise AuthoritySourceError(f"Row {index} has an invalid domain: {row.get('domain')!r}")
        projected.append({"domain": domain, "organization": organization})
    return projected, {"unmapped_rows": unmapped, "out_of_scope_rows": 0}


def adapt_exact_ip_org(source_rows: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Project ``ip,org`` rows into canonical ``exact_ip`` authority rows.

    The result is exact-IP only; no subnet/CIDR/neighbour expansion happens here
    or anywhere downstream. IPv6 source rows are dropped as out of scope for
    this IPv4-only method and reported separately from unmapped rows.
    """
    projected: list[dict[str, Any]] = []
    unmapped = 0
    out_of_scope = 0
    for index, row in enumerate(source_rows, start=1):
        _require_columns(row, ("ip",), index)
        organization = _organization_from(row, index)
        ip_text = _clean(row.get("ip"))
        if not organization or not ip_text:
            unmapped += 1
            continue
        address = _parse_address(ip_text, index)
        if address is None:
            out_of_scope += 1
            continue
        projected.append({"ip": str(address), "organization": organization})
    return projected, {"unmapped_rows": unmapped, "out_of_scope_rows": out_of_scope}


def _read_headerless_rows(path: Path) -> list[list[str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [row for row in csv.reader(handle) if row]


def _read_dict_rows(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _check_sha(path: Path, expected_sha256: str) -> str:
    actual = sha256_file(path)
    if expected_sha256 and actual.lower() != expected_sha256.lower():
        raise ValueError(f"SHA256 mismatch for {path}: expected {expected_sha256}, got {actual}")
    return actual


def load_china_institution_range_authority(
    path: str | Path,
    *,
    expected_sha256: str = "",
    source: str = "china-institution-ipv4-ranges",
    expected_rows: int | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> LoadedAuthority:
    """Load the headerless ``org,start_ip,end_ip`` institution range export."""
    resolved = Path(path)
    actual = _check_sha(resolved, expected_sha256)
    canonical, counts = adapt_china_institution_ranges(_read_headerless_rows(resolved))
    canonical, duplicates = _project_uniquely(
        canonical, key_columns=("start_ip", "end_ip"), kind="ipv4_ranges"
    )
    return _finalize(
        canonical,
        authority_type="ipv4_ranges",
        source=source,
        sha256=actual,
        adapter=CHINA_INSTITUTION_RANGE_ADAPTER,
        source_columns=CHINA_INSTITUTION_RANGE_SOURCE_COLUMNS,
        path=str(resolved),
        expected_rows=expected_rows,
        provenance=provenance,
        counts=counts,
        duplicate_rows_removed=duplicates,
    )


def load_domain_org_authority(
    path: str | Path,
    *,
    expected_sha256: str = "",
    source: str = "domain-org-association",
    expected_rows: int | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> LoadedAuthority:
    """Load a reviewed ``domain,org`` association export as a domain authority."""
    resolved = Path(path)
    actual = _check_sha(resolved, expected_sha256)
    canonical, counts = adapt_domain_org(_read_dict_rows(resolved))
    canonical, duplicates = _project_uniquely(
        canonical, key_columns=("domain",), kind="domains"
    )
    return _finalize(
        canonical,
        authority_type="domains",
        source=source,
        sha256=actual,
        adapter=DOMAIN_ORG_ASSOCIATION_ADAPTER,
        source_columns=DOMAIN_ORG_SOURCE_COLUMNS,
        path=str(resolved),
        expected_rows=expected_rows,
        provenance=provenance,
        counts=counts,
        duplicate_rows_removed=duplicates,
    )


def load_exact_ip_org_authority(
    path: str | Path,
    *,
    expected_sha256: str = "",
    source: str = "exact-ip-org-association",
    expected_rows: int | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> LoadedAuthority:
    """Load a reviewed ``ip,org`` association export as an exact-IP authority."""
    resolved = Path(path)
    actual = _check_sha(resolved, expected_sha256)
    canonical, counts = adapt_exact_ip_org(_read_dict_rows(resolved))
    canonical, duplicates = _project_uniquely(
        canonical, key_columns=("ip",), kind="exact_ip"
    )
    return _finalize(
        canonical,
        authority_type="exact_ip",
        source=source,
        sha256=actual,
        adapter=EXACT_IP_ORG_ASSOCIATION_ADAPTER,
        source_columns=EXACT_IP_ORG_SOURCE_COLUMNS,
        path=str(resolved),
        expected_rows=expected_rows,
        provenance=provenance,
        counts=counts,
        duplicate_rows_removed=duplicates,
    )


# --------------------------------------------------------------------------
# CISA dotgov-data (.gov registrar): direct domain identity
# --------------------------------------------------------------------------

def _canonical_authority_domain(value: object, index: int, *, drop_invalid: bool) -> str | None:
    domain = _clean(value).lower().lstrip(".").rstrip(".")
    if not domain:
        return None
    if " " in domain or "." not in domain:
        if drop_invalid:
            return None
        raise AuthoritySourceError(f"Row {index} has an invalid domain: {value!r}")
    return domain


def adapt_cisa_dotgov(
    source_rows: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Project the .gov registrar export into canonical ``domain`` authority rows.

    The registrar asserts only that a named government organization holds a
    registrable domain. It publishes no stable organization identifier, so
    ``organization_id`` stays null and the free-text organization name is the
    complete identity payload.

    This adapter does not derive a government *category* from ``.gov``: identity
    and category stay separate, and the existing category rules classify the
    organization name independently.
    """
    projected: list[dict[str, Any]] = []
    unmapped = 0
    for index, row in enumerate(source_rows, start=1):
        _require_columns(row, CISA_DOTGOV_SOURCE_COLUMNS, index)
        organization = _clean(row.get("Organization name"))
        if not organization:
            # A registered domain with no named holder carries no association.
            unmapped += 1
            continue
        domain = _canonical_authority_domain(row.get("Domain name"), index, drop_invalid=False)
        if domain is None:
            unmapped += 1
            continue
        projected.append({"domain": domain, "organization": organization})
    return projected, {"unmapped_rows": unmapped, "out_of_scope_rows": 0}


def load_cisa_dotgov_authority(
    path: str | Path,
    *,
    expected_sha256: str = "",
    source: str = CISA_DOTGOV_SOURCE_ID,
    expected_rows: int | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> LoadedAuthority:
    """Load the reviewed CISA dotgov-data export as a direct domain authority."""
    resolved = Path(path)
    actual = _check_sha(resolved, expected_sha256)
    canonical, counts = adapt_cisa_dotgov(_read_dict_rows(resolved))
    canonical, duplicates = _project_uniquely(
        canonical, key_columns=("domain",), kind="domains"
    )
    return _finalize(
        canonical,
        authority_type="domains",
        source=source,
        sha256=actual,
        adapter=GOV_DOMAIN_REGISTRY_ADAPTER,
        source_columns=CISA_DOTGOV_SOURCE_COLUMNS,
        path=str(resolved),
        expected_rows=expected_rows,
        provenance=provenance,
        counts=counts,
        duplicate_rows_removed=duplicates,
    )


# --------------------------------------------------------------------------
# ROR schema-v2 domains: direct research-organization domain identity
# --------------------------------------------------------------------------

def ror_identifier(ror_id: str) -> str:
    """Namespace a ROR identifier so it is never compared across registries."""
    return f"{ROR_NAMESPACE}:{ror_id.strip()}"


def _ror_display_name(record: Mapping[str, Any]) -> str | None:
    """Canonical ROR display name, without fuzzy or alias matching."""
    names = record.get("names")
    if not isinstance(names, Sequence) or isinstance(names, (str, bytes)):
        return None
    fallback: str | None = None
    for entry in names:
        if not isinstance(entry, Mapping):
            continue
        value = _clean(entry.get("value"))
        if not value:
            continue
        types = entry.get("types") or ()
        if isinstance(types, Sequence) and "ror_display" in types:
            return value
        fallback = fallback or value
    return fallback


def adapt_ror_domains(
    source_records: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Project schema-v2 ROR records into canonical ``domain`` authority rows.

    Only domains the ROR dump itself provides are ingested; no organization name
    is ever turned into a domain, and no alias is used for fuzzy matching.

    A canonical domain claimed by more than one distinct ROR identifier is
    ``AMBIGUOUS``: the key is dropped rather than resolved by record order, and
    the drop is counted per key as ``ambiguous_domain_keys_dropped``.
    """
    counts = {
        "organizations_read": 0,
        "organizations_without_domains": 0,
        "domain_entries": 0,
        "invalid_domains": 0,
        "blank_organization_names": 0,
        "duplicate_domain_entries": 0,
        "ambiguous_domain_keys_dropped": 0,
    }
    claims: dict[str, dict[str, Any]] = {}
    ambiguous: set[str] = set()

    for index, record in enumerate(source_records, start=1):
        counts["organizations_read"] += 1
        ror_id = _clean(record.get("id"))
        if not ror_id:
            raise AuthoritySourceError(f"Record {index} is missing a ROR id")
        domains = record.get("domains")
        if not isinstance(domains, Sequence) or isinstance(domains, (str, bytes)):
            domains = ()
        if not domains:
            counts["organizations_without_domains"] += 1
            continue
        organization = _ror_display_name(record)
        if not organization:
            counts["blank_organization_names"] += 1
            continue
        organization_id = ror_identifier(ror_id)

        for entry in domains:
            counts["domain_entries"] += 1
            domain = _canonical_authority_domain(entry, index, drop_invalid=True)
            if domain is None:
                counts["invalid_domains"] += 1
                continue
            if domain in ambiguous:
                continue
            existing = claims.get(domain)
            if existing is None:
                claims[domain] = {
                    "domain": domain,
                    "organization": organization,
                    "organization_id": organization_id,
                }
            elif existing["organization_id"] == organization_id:
                counts["duplicate_domain_entries"] += 1
            else:
                # Same canonical domain, two distinct ROR identifiers: no
                # deterministic choice exists, so the key is excluded.
                claims.pop(domain, None)
                ambiguous.add(domain)
                counts["ambiguous_domain_keys_dropped"] += 1

    projected = [claims[domain] for domain in sorted(claims)]
    counts["usable_unique_domains"] = len(projected)
    return projected, counts


def _iter_json_objects(stream: Any, chunk_size: int = 1 << 20) -> Iterator[Any]:
    """Yield top-level JSON values from a byte stream incrementally.

    Handles both a top-level JSON array and a JSONL stream without materializing
    the document: the published ROR dump is a ~300 MB pretty-printed array, so an
    eager ``json.load`` would dominate the process's memory.
    """
    decoder = json.JSONDecoder()
    buffer = ""
    eof = False
    while True:
        index = 0
        while index < len(buffer):
            char = buffer[index]
            if char in " \t\r\n,[":
                index += 1
                continue
            if char == "]":
                index += 1
                continue
            try:
                value, end = decoder.raw_decode(buffer, index)
            except ValueError:
                break
            index = end
            yield value
        buffer = buffer[index:]
        if eof:
            break
        chunk = stream.read(chunk_size)
        if chunk:
            buffer += chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else chunk
        else:
            eof = True
    if buffer.strip() not in ("", "]"):
        raise AuthoritySourceError("unparsed trailing ROR JSON data")


def _iter_ror_records(path: Path) -> Iterator[dict[str, Any]]:
    """Iterate a ROR schema-v2 dump (zip, JSON array, or JSONL), read-only.

    The published archive is read in memory member-by-member; nothing is written
    to disk and the source is never modified.
    """
    suffix = path.suffix.lower()
    if suffix == ".zip":
        import zipfile

        with zipfile.ZipFile(path) as archive:
            members = sorted(name for name in archive.namelist() if name.endswith(".json"))
            if not members:
                raise AuthoritySourceError(f"{path} contains no ROR .json member")
            with archive.open(members[0]) as stream:
                yield from _normalize_ror_stream(_iter_json_objects(stream))
        return
    with path.open("rb") as stream:
        yield from _normalize_ror_stream(_iter_json_objects(stream))


def _normalize_ror_stream(values: Iterable[Any]) -> Iterator[dict[str, Any]]:
    for value in values:
        if not isinstance(value, Mapping):
            continue
        if "id" not in value and isinstance(value.get("items"), list):
            # A container payload rather than a bare record list.
            for item in value["items"]:
                if isinstance(item, Mapping):
                    yield dict(item)
            continue
        yield dict(value)


def load_ror_domain_authority(
    path: str | Path,
    *,
    expected_sha256: str = "",
    source: str = "ror_domains",
    expected_rows: int | None = None,
    provenance: Mapping[str, Any] | None = None,
) -> LoadedAuthority:
    """Load a reviewed ROR schema-v2 dump as a direct domain identity authority."""
    resolved = Path(path)
    actual = _check_sha(resolved, expected_sha256)
    canonical, counts = adapt_ror_domains(_iter_ror_records(resolved))
    if expected_rows is not None and len(canonical) != expected_rows:
        raise ValueError(f"Row-count mismatch: expected {expected_rows}, got {len(canonical)}")
    return _finalize(
        canonical,
        authority_type="domains",
        source=source,
        sha256=actual,
        adapter=ROR_DOMAIN_AUTHORITY_ADAPTER,
        source_columns=ROR_DOMAIN_SOURCE_COLUMNS,
        path=str(resolved),
        expected_rows=None,
        provenance=provenance,
        counts=counts,
        duplicate_rows_removed=0,
    )