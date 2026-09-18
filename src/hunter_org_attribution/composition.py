"""Reviewed canonical authority composition.

Production callers hold reviewed authority artifacts as local files. This module
composes them into one deterministic runtime configuration so that callers never
have to merge real CSVs by hand and never have to know which adapter each source
needs.

Composition is explicit about *role*::

    China institution IPv4 ranges   -> ipv4_ranges     (direct identity)
    submission / reviewed domains   -> domains         (direct identity)
    submission / reviewed exact IPs -> exact_ip        (direct identity)
    CISA dotgov-data                -> domains         (direct identity)
    ROR schema-v2 domains           -> domains         (direct identity)
    CAIDA AS Organizations          -> asn_organization (network text enrichment)

The Measurement 212 ASN infrastructure lookup is deliberately *not* an engine
authority: it is applied at the Hunter projection layer as record enrichment
(``infrastructure_category`` / ``provider_family``) and is passed to
``project_measurement212_hunter_record``. It never populates ``asn_organization``.

Every source remains read-only. Missing artifacts are simply absent from the
composition; no placeholder or inferred authority is ever synthesized.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .asn_organization import AsnOrganizationAuthority, load_caida_as2org_authority
from .authority_sources import (
    load_china_institution_range_authority,
    load_cisa_dotgov_authority,
    load_domain_org_authority,
    load_exact_ip_org_authority,
    load_ror_domain_authority,
)
from .engine import AttributionEngine
from .provenance import LoadedAuthority


@dataclass(frozen=True)
class AuthorityArtifact:
    """A reviewed local authority file with its frozen identity."""

    path: Path
    expected_sha256: str = ""
    source: str | None = None
    version: str | None = None
    expected_rows: int | None = None
    provenance: Mapping[str, Any] | None = None
    # Phase 5.2 ROR public-suffix quality gate: frozen PSL snapshot identity.
    psl_path: Path | None = None
    psl_sha256: str = ""
    psl_source: str | None = None
    psl_retrieved_at: str | None = None


@dataclass(frozen=True)
class ComposedAuthorities:
    """The loaded runtime configuration plus an aggregate load audit."""

    authorities: tuple[LoadedAuthority, ...]
    asn_organization_authorities: tuple[AsnOrganizationAuthority, ...]
    audit: dict[str, Any]
    engine: AttributionEngine = field(repr=False)


@dataclass(frozen=True)
class AuthorityComposition:
    """Declarative composition of the reviewed global and local authorities."""

    china_ipv4_ranges: AuthorityArtifact | None = None
    submission_domains: AuthorityArtifact | None = None
    submission_exact_ips: AuthorityArtifact | None = None
    cisa_dotgov: AuthorityArtifact | None = None
    ror_domains: AuthorityArtifact | None = None
    caida_as2org: AuthorityArtifact | None = None
    # Pre-loaded authorities, used by tests and by callers that already hold
    # validated objects. These are merged in, never replaced.
    extra_authorities: tuple[LoadedAuthority, ...] = ()
    extra_asn_organization_authorities: tuple[AsnOrganizationAuthority, ...] = ()
    rules: Iterable[dict[str, Any]] | None = None

    def load(self) -> ComposedAuthorities:
        authorities: list[LoadedAuthority] = list(self.extra_authorities)
        asn_organization: list[AsnOrganizationAuthority] = list(
            self.extra_asn_organization_authorities
        )

        if self.china_ipv4_ranges is not None:
            artifact = self.china_ipv4_ranges
            authorities.append(load_china_institution_range_authority(
                artifact.path,
                expected_sha256=artifact.expected_sha256,
                source=artifact.source or "china-institution-ipv4-ranges",
                expected_rows=artifact.expected_rows,
                provenance=artifact.provenance,
            ))
        if self.submission_domains is not None:
            artifact = self.submission_domains
            authorities.append(load_domain_org_authority(
                artifact.path,
                expected_sha256=artifact.expected_sha256,
                source=artifact.source or "domain-org-association",
                expected_rows=artifact.expected_rows,
                provenance=artifact.provenance,
            ))
        if self.submission_exact_ips is not None:
            artifact = self.submission_exact_ips
            authorities.append(load_exact_ip_org_authority(
                artifact.path,
                expected_sha256=artifact.expected_sha256,
                source=artifact.source or "exact-ip-org-association",
                expected_rows=artifact.expected_rows,
                provenance=artifact.provenance,
            ))
        if self.cisa_dotgov is not None:
            artifact = self.cisa_dotgov
            authorities.append(load_cisa_dotgov_authority(
                artifact.path,
                expected_sha256=artifact.expected_sha256,
                source=artifact.source or "cisa_dotgov_data",
                expected_rows=artifact.expected_rows,
                provenance=artifact.provenance,
            ))
        if self.ror_domains is not None:
            artifact = self.ror_domains
            authorities.append(load_ror_domain_authority(
                artifact.path,
                expected_sha256=artifact.expected_sha256,
                source=artifact.source or "ror_domains",
                expected_rows=artifact.expected_rows,
                provenance=artifact.provenance,
                psl_path=artifact.psl_path,
                psl_sha256=artifact.psl_sha256 or "",
                psl_source=artifact.psl_source or "",
                psl_retrieved_at=artifact.psl_retrieved_at or "",
            ))
        if self.caida_as2org is not None:
            artifact = self.caida_as2org
            asn_organization.append(load_caida_as2org_authority(
                artifact.path,
                expected_sha256=artifact.expected_sha256,
                source=artifact.source or "caida_as2org",
                version=artifact.version,
                expected_asns=artifact.expected_rows,
                provenance=artifact.provenance,
            ))

        if self.rules is not None:
            engine = AttributionEngine(self.rules, authorities, asn_organization)
        else:
            engine = AttributionEngine.from_repository_defaults(authorities, asn_organization)

        audit = {
            "schema": "authority_composition_v1",
            "authority_count": len(authorities),
            "asn_organization_authority_count": len(asn_organization),
            "authorities": [
                {
                    "source": authority.source,
                    "authority_type": authority.authority_type,
                    "sha256": authority.sha256,
                    "row_count": authority.audit.get("row_count"),
                    "adapter": authority.audit.get("provenance", {}).get("adapter"),
                }
                for authority in sorted(authorities, key=lambda a: (a.authority_type, a.source))
            ],
            "asn_organization_authorities": [
                {
                    "source": authority.source,
                    "sha256": authority.sha256,
                    "version": authority.version,
                    "asn_count": authority.asn_count,
                    "adapter": authority.adapter,
                }
                for authority in asn_organization
            ],
        }
        return ComposedAuthorities(
            authorities=tuple(authorities),
            asn_organization_authorities=tuple(asn_organization),
            audit=audit,
            engine=engine,
        )


def compose_engine(
    *,
    authorities: Iterable[LoadedAuthority] = (),
    asn_organization_authorities: Iterable[AsnOrganizationAuthority] = (),
    rules: Iterable[dict[str, Any]] | None = None,
) -> AttributionEngine:
    """Compose already-loaded reviewed authorities into a runtime engine."""
    if rules is None:
        return AttributionEngine.from_repository_defaults(authorities, asn_organization_authorities)
    return AttributionEngine(rules, authorities, asn_organization_authorities)
