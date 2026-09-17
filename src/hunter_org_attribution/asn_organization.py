"""Reviewed CAIDA AS Organizations (as2org) adapter.

Runtime role — ASN -> ``asn_organization`` **network-registration text**.

This module deliberately does **not** produce organization identity. CAIDA
describes the method as mapping ASes "to the organizational entities that
operate them", where the entity is the *resource holder* recorded by the
originating RIR. A holder is frequently a transit provider, a hosting company, a
downstream customer, or a holding entity, so the registration text is network
context, never the hosted-service organization of an observation.

Consequences enforced here and downstream:

- CAIDA evidence may populate ``asn_organization`` only.
- CAIDA never sets ``organization_id``, never sets ``resolved_organization`` and
  never participates in identity reconciliation.
- The CAIDA source-local organization handle is preserved under the
  ``caida-as2org`` namespace as ``network_organization_id``. It is a *different
  namespace* from every other registry handle and must never be compared with,
  or written to, ``organization_id``.

Layering (nothing below the adapter learns about the CAIDA file format)::

    CAIDA as2org dated dump
            -> this reviewed adapter
            -> canonical ``asn -> asn_organization`` records
            -> engine ASN-organization enrichment
            -> existing field-local ``asn_org_regex`` rules
"""

from __future__ import annotations

import gzip
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .normalize import normalize_asn
from .provenance import AuthoritySourceError, sha256_file
from .resolution import canonical_organization_name


CAIDA_AS2ORG_ADAPTER = "reviewed-adapter:asn-organization-text:v1"
CAIDA_AS2ORG_SOURCE_ID = "caida_as2org"
CAIDA_AS2ORG_NAMESPACE = "caida-as2org"

# The two record types the dated ``.as-org2info.txt`` build emits, in file order.
ORGANIZATION_FORMAT = "# format:org_id|changed|org_name|country|source"
ASN_FORMAT = "# format:aut|changed|aut_name|org_id|opaque_id|source"

_ORGANIZATION_COLUMNS = ("org_id", "changed", "org_name", "country", "source")
_ASN_COLUMNS = ("aut", "changed", "aut_name", "org_id", "opaque_id", "source")


class AsnOrganizationEnrichmentConflict(ValueError):
    """Raised when a Hunter record value and reviewed enrichment disagree.

    A raw ``asn_organization`` and a CAIDA value are never fuzzy-reconciled: an
    exact disagreement fails closed rather than silently preferring one side.
    """


@dataclass(frozen=True)
class AsnOrganizationRecord:
    """One canonical ``asn -> asn_organization`` network-registration record."""

    asn: int
    asn_organization: str
    network_organization_id: str | None
    network_organization_id_namespace: str
    network_organization_source: str | None

    def provenance(self) -> dict[str, Any]:
        return {
            "asn": self.asn,
            "network_organization_id": self.network_organization_id,
            "network_organization_id_namespace": self.network_organization_id_namespace,
            "network_organization_source": self.network_organization_source,
        }


class AsnOrganizationAuthority:
    """An indexed, hash-pinned CAIDA as2org projection.

    The authority is read-only and answers a single question: given an ASN, what
    network-registration organization text did the dated CAIDA build record?
    """

    __slots__ = ("source", "adapter", "sha256", "version", "audit", "_index", "_rows")

    def __init__(
        self,
        *,
        source: str,
        adapter: str,
        sha256: str,
        version: str | None,
        rows: Iterable[AsnOrganizationRecord],
        audit: dict[str, Any],
    ) -> None:
        self.source = source
        self.adapter = adapter
        self.sha256 = sha256
        self.version = version
        self._rows = tuple(sorted(rows, key=lambda row: row.asn))
        self.audit = dict(audit)
        self._index = {row.asn: row for row in self._rows}

    @property
    def records(self) -> tuple[AsnOrganizationRecord, ...]:
        return self._rows

    @property
    def asn_count(self) -> int:
        return len(self._index)

    def lookup(self, asn: int | None) -> AsnOrganizationRecord | None:
        if asn is None:
            return None
        return self._index.get(asn)

    def enrichment_provenance(self, row: AsnOrganizationRecord) -> dict[str, Any]:
        """Field-level provenance for a rule hit driven by this enrichment."""
        return {
            "adapter": self.adapter,
            "source": self.source,
            "authority_sha256": self.sha256,
            "authority_version": self.version,
            **row.provenance(),
        }


def parse_as2org_text(text: str) -> tuple[dict[str, dict[str, str]], list[dict[str, str]]]:
    """Parse the dated ``.as-org2info.txt`` body into orgs and ``aut`` rows.

    The build emits two pipe-delimited record types, each introduced by its own
    ``# format:`` header. The association ASN -> organization is
    ``aut -> org_id -> organization``; the ``aut_name`` field is a *network*
    name and is never used as the organization text.
    """
    organizations: dict[str, dict[str, str]] = {}
    asns: list[dict[str, str]] = []
    section: str | None = None

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip("\r\n")
        if line.startswith("#"):
            if line.startswith(ORGANIZATION_FORMAT):
                section = "organization"
            elif line.startswith(ASN_FORMAT):
                section = "asn"
            continue
        if not line.strip():
            continue
        parts = line.split("|")
        if section == "organization":
            if len(parts) != len(_ORGANIZATION_COLUMNS):
                raise AuthoritySourceError(
                    f"Line {lineno}: organization record must have {len(_ORGANIZATION_COLUMNS)} fields"
                )
            org_id, _changed, org_name, country, source = parts
            if org_id in organizations:
                raise AuthoritySourceError(f"Line {lineno}: duplicate organization id {org_id!r}")
            organizations[org_id] = {
                "org_name": org_name,
                "country": country,
                "source": source,
            }
        elif section == "asn":
            if len(parts) != len(_ASN_COLUMNS):
                raise AuthoritySourceError(
                    f"Line {lineno}: ASN record must have {len(_ASN_COLUMNS)} fields"
                )
            asn, _changed, aut_name, org_id, opaque_id, source = parts
            asns.append(
                {
                    "asn": asn,
                    "aut_name": aut_name,
                    "org_id": org_id,
                    "opaque_id": opaque_id,
                    "source": source,
                }
            )
        else:
            raise AuthoritySourceError(f"Line {lineno}: data row before any '# format:' header")
    return organizations, asns


def adapt_caida_as2org(text: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Project as2org text into canonical ``asn -> asn_organization`` rows.

    Fail-closed policy, decided from the real format semantics (the ``aut`` record
    states its ``org_id`` explicitly, so an internally inconsistent key admits no
    deterministic choice):

    - ``aut`` row whose ``org_id`` is absent from the organization section:
      dropped and counted as ``unresolved_organization_reference``.
    - repeated ``aut`` rows for the same ASN naming the same organization:
      deduplicated and counted as ``duplicate_asn_rows``.
    - repeated ``aut`` rows for the same ASN naming different organizations:
      the *key* is excluded (no mapping is emitted for that ASN) and counted as
      ``asn_mapping_conflicts``. This is ``CAIDA_ASN_MAPPING_CONFLICT`` at
      key granularity, so one inconsistent ASN cannot poison the whole source.
    - blank organization name: dropped and counted as ``blank_organization``.
    - invalid ASN syntax: structural fault, raised.
    """
    organizations, asn_rows = parse_as2org_text(text)

    by_asn: dict[int, dict[str, Any]] = {}
    conflicts: set[int] = set()
    counts = {
        "asn_rows_read": len(asn_rows),
        "organization_records": len(organizations),
        "unresolved_organization_reference": 0,
        "blank_organization": 0,
        "duplicate_asn_rows": 0,
        "asn_mapping_conflicts": 0,
        "invalid_asn_rows": 0,
    }

    for row in asn_rows:
        organization = organizations.get(row["org_id"])
        if organization is None:
            counts["unresolved_organization_reference"] += 1
            continue
        org_name = " ".join(organization["org_name"].split())
        if not org_name:
            counts["blank_organization"] += 1
            continue
        try:
            asn = normalize_asn(row["asn"])
        except (TypeError, ValueError):
            counts["invalid_asn_rows"] += 1
            continue
        if asn is None:
            counts["invalid_asn_rows"] += 1
            continue

        candidate = {
            "asn": asn,
            "asn_organization": org_name,
            "network_organization_id": row["org_id"] or None,
            "network_organization_source": organization["source"] or None,
        }
        existing = by_asn.get(asn)
        if existing is None:
            if asn in conflicts:
                # A previously seen conflict keeps the key excluded.
                continue
            by_asn[asn] = candidate
        elif existing["asn_organization"] == candidate["asn_organization"]:
            counts["duplicate_asn_rows"] += 1
        else:
            # Conflicting registrations for one ASN: exclude the key entirely.
            by_asn.pop(asn, None)
            conflicts.add(asn)
            counts["asn_mapping_conflicts"] += 1

    projected = [by_asn[asn] for asn in sorted(by_asn)]
    counts["conflicting_keys_excluded"] = len(conflicts)
    counts["usable_asn_mappings"] = len(projected)
    return projected, counts


def _open_text(path: Path) -> str:
    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return path.read_text(encoding="utf-8", errors="replace")


def load_caida_as2org_authority(
    path: str | Path,
    *,
    expected_sha256: str = "",
    source: str = CAIDA_AS2ORG_SOURCE_ID,
    version: str | None = None,
    expected_asns: int | None = None,
    provenance: dict[str, Any] | None = None,
) -> AsnOrganizationAuthority:
    """Load a reviewed CAIDA as2org dump read-only into an ASN enrich index.

    The source file is never modified. ``expected_sha256``, when supplied, is
    verified before parsing; the verified digest is always carried forward into
    every derived evidence provenance entry.
    """
    resolved = Path(path)
    actual = sha256_file(resolved)
    if expected_sha256 and actual.lower() != expected_sha256.lower():
        raise ValueError(f"SHA256 mismatch for {resolved}: expected {expected_sha256}, got {actual}")

    projected, counts = adapt_caida_as2org(_open_text(resolved))
    if expected_asns is not None and len(projected) != expected_asns:
        raise ValueError(f"ASN-count mismatch: expected {expected_asns}, got {len(projected)}")

    rows = tuple(
        AsnOrganizationRecord(
            asn=row["asn"],
            asn_organization=row["asn_organization"],
            network_organization_id=row["network_organization_id"],
            network_organization_id_namespace=CAIDA_AS2ORG_NAMESPACE,
            network_organization_source=row["network_organization_source"],
        )
        for row in projected
    )
    audit = {
        "path": str(resolved),
        "sha256": actual,
        "schema": "asn_organization",
        "source": source,
        "version": version,
        "adapter": CAIDA_AS2ORG_ADAPTER,
        "row_count": len(rows),
        "counts": dict(sorted(counts.items())),
        "provenance": dict(provenance or {}),
        "semantics": (
            "ASN -> network-registration organization TEXT. Never organization "
            "identity; the source-local handle stays in the caida-as2org namespace."
        ),
    }
    return AsnOrganizationAuthority(
        source=source,
        adapter=CAIDA_AS2ORG_ADAPTER,
        sha256=actual,
        version=version,
        rows=rows,
        audit=audit,
    )


def load_caida_as2org_authority_from_text(
    text: str,
    *,
    source: str = CAIDA_AS2ORG_SOURCE_ID,
    sha256: str = "",
    version: str | None = None,
    provenance: dict[str, Any] | None = None,
) -> AsnOrganizationAuthority:
    """Build a CAIDA authority from in-memory text (fixtures, embedded exports)."""
    projected, counts = adapt_caida_as2org(text)
    rows = tuple(
        AsnOrganizationRecord(
            asn=row["asn"],
            asn_organization=row["asn_organization"],
            network_organization_id=row["network_organization_id"],
            network_organization_id_namespace=CAIDA_AS2ORG_NAMESPACE,
            network_organization_source=row["network_organization_source"],
        )
        for row in projected
    )
    audit = {
        "path": None,
        "sha256": sha256,
        "schema": "asn_organization",
        "source": source,
        "version": version,
        "adapter": CAIDA_AS2ORG_ADAPTER,
        "row_count": len(rows),
        "counts": dict(sorted(counts.items())),
        "provenance": dict(provenance or {}),
    }
    return AsnOrganizationAuthority(
        source=source,
        adapter=CAIDA_AS2ORG_ADAPTER,
        sha256=sha256,
        version=version,
        rows=rows,
        audit=audit,
    )


def agreement_ok(record_value: str | None, enrichment_value: str) -> bool:
    """Normalized exact agreement between a record value and enrichment text."""
    return canonical_organization_name(record_value) == canonical_organization_name(enrichment_value)
