"""Deterministic cross-source identity alias crosswalk (Phase 6).

A cross-source identity alias asserts that a source-native organization *name*
(no stable identifier) is a deterministic alias of an already-stable
organization identifier, based only on *shared reviewed canonical domains*.

Construction rule: ``shared_canonical_domain_unique_target``.

The crosswalk is **not** entity resolution and **not** a fuzzy matcher:

- no name similarity / fuzzy matching anywhere;
- no translation or bilingual equivalence;
- no acronym similarity;
- no observation co-occurrence (a Hunter observation carrying range evidence
  plus ROR evidence is itself never an alias authority);
- no country / ASN / same-observed-IP / same-web-title inference.

It is built exclusively from reviewed direct-identity *domain* authorities:

    ROR (stable id + name)     d -> ror:X / display name
    submission domain          d -> no-ID / Chinese name
    CISA dotgov                d -> no-ID / .gov holder name

A canonical domain ``d`` present in the ROR authority and in one of the no-ID
domain authorities is a *bridge*. Each bridge asserts
``normalized(no-ID name) -> ror:X``. A normalized name becomes a
``GLOBAL_DETERMINISTIC_ALIAS`` only when every bridge for that name targets the
same single stable ROR id; a name with bridges to two different ROR ids is an
``ALIAS_CROSSWALK_CONFLICT`` and is excluded (fail closed). One ROR id may have
many aliases (an alias set, not a conflict).

Range and exact-IP authorities never participate in crosswalk construction:
they carry no domain key, so there is no circular reconciliation (range/exact-IP
evidence can only *use* an independently built alias, never create one).

Evidence is never rewritten. The alias only affects reconciliation identity
grouping: a no-ID name whose crosswalk entry exists may be attributed to the
stable id, but every original evidence row keeps its source-native
``organization_id`` and ``organization`` values.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Mapping

from .provenance import LoadedAuthority
from .resolution import canonical_organization_name

# Reviewed source families eligible to *create* a bridge. A bridge needs the
# stable-id side (ROR) and one no-ID domain side (submission domain or CISA).
SUBMISSION_DOMAIN_SOURCE = "domain-org-association"
CISA_SOURCE = "cisa_dotgov_data"
ROR_SOURCE = "ror_domains"

CONSTRUCTION_RULE = "shared_canonical_domain_unique_target"

# A normalized no-ID name whose bridges point at two different stable ids is an
# alias crosswalk conflict: the name is excluded from the crosswalk (fail closed).
ALIAS_CROSSWALK_CONFLICT = "alias_crosswalk_conflict"


def _canonical_domain(value: object) -> str:
    return str(value).strip().lower().lstrip(".").rstrip(".")


@dataclass(frozen=True)
class CrosswalkAlias:
    """One global deterministic alias: normalized no-ID name -> stable id.

    Provenance is kept non-numeric: every alias records the reviewed bridge
    domains and sources that produced it, the source organization names, and the
    authority digests, together with the construction rule. No confidence score
    is stored.
    """

    alias_normalized_name: str
    canonical_stable_id: str
    canonical_display_name: str
    bridge_domains: tuple[str, ...]
    bridge_sources: tuple[str, ...]
    source_organization_names: tuple[str, ...]
    source_authority_hashes: tuple[str, ...]
    construction_rule: str = CONSTRUCTION_RULE


@dataclass(frozen=True)
class AliasCrosswalk:
    """A deterministic normalized-name -> stable-id map with full provenance."""

    aliases: Mapping[str, CrosswalkAlias]
    audit: dict[str, Any] = field(default_factory=dict)

    def lookup(self, name: object) -> CrosswalkAlias | None:
        """Return the deterministic alias for ``name`` (canonicalized), or None."""
        return self.aliases.get(canonical_organization_name(name))

    def __contains__(self, name: object) -> bool:
        return canonical_organization_name(name) in self.aliases

    def __len__(self) -> int:
        return len(self.aliases)

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------
    @classmethod
    def build(
        cls,
        *,
        ror_authority: LoadedAuthority,
        submission_domain_authority: LoadedAuthority | None = None,
        cisa_authority: LoadedAuthority | None = None,
    ) -> "AliasCrosswalk":
        """Build the crosswalk from reviewed direct-identity domain authorities.

        Only ROR provides the stable-id side. Only submission-domain and CISA
        provide no-ID names, and each side is used only when its canonical
        domain also appears in ROR. Everything else (range, exact-IP) is never a
        bridge source.
        """
        # ---- stable-id side: ROR domain -> (stable id, display name) ----
        ror_map: dict[str, tuple[str, str]] = {}
        for row in ror_authority.rows:
            domain = _canonical_domain(row.get("domain"))
            if not domain:
                continue
            organization_id = row.get("organization_id")
            organization = row.get("organization")
            if not organization_id or not organization:
                continue
            existing = ror_map.get(domain)
            if existing is not None and existing[0] != organization_id:
                raise ValueError(
                    f"AliasCrosswalk: ROR authority maps domain {domain!r} to "
                    f"two stable ids ({existing[0]}, {organization_id}); "
                    "ambiguous ROR domain keys must be excluded at ingestion."
                )
            ror_map[domain] = (str(organization_id), str(organization))

        # ---- no-ID domain sides: domain -> organization name ----
        def _no_id_map(authority: LoadedAuthority | None) -> dict[str, str]:
            mapping: dict[str, str] = {}
            if authority is None:
                return mapping
            for row in authority.rows:
                domain = _canonical_domain(row.get("domain"))
                organization = row.get("organization")
                if not domain or not organization:
                    continue
                existing = mapping.get(domain)
                if existing is not None and existing != str(organization):
                    raise ValueError(
                        f"AliasCrosswalk: {authority.source} maps domain {domain!r} "
                        f"to two names ({existing!r}, {organization!r}); "
                        "conflicting domain projections must be excluded at ingestion."
                    )
                mapping[domain] = str(organization)
            return mapping

        submission_map = _no_id_map(submission_domain_authority)
        cisa_map = _no_id_map(cisa_authority)

        # ---- assertions: (name, stable id, display, domain, source, org name, sha) ----
        assertions: list[tuple[str, str, str, str, str, str, str]] = []
        no_id_sides: list[tuple[str, dict[str, str], str, str]] = [
            (SUBMISSION_DOMAIN_SOURCE, submission_map,
             submission_domain_authority.sha256 if submission_domain_authority else "",
             submission_domain_authority.source if submission_domain_authority else ""),
            (CISA_SOURCE, cisa_map,
             cisa_authority.sha256 if cisa_authority else "",
             cisa_authority.source if cisa_authority else ""),
        ]
        for side_key, mapping, sha, source_name in no_id_sides:
            for domain, (stable_id, display_name) in ror_map.items():
                org_name = mapping.get(domain)
                if org_name is None:
                    continue
                normalized = canonical_organization_name(org_name)
                if not normalized:
                    continue
                assertions.append(
                    (normalized, stable_id, display_name, domain, side_key, org_name, sha)
                )

        # ---- global uniqueness gate: one normalized name -> exactly one stable id ----
        by_name: dict[str, list[tuple[str, str, str, str, str, str, str]]] = defaultdict(list)
        for assertion in assertions:
            by_name[assertion[0]].append(assertion)

        aliases: dict[str, CrosswalkAlias] = {}
        ambiguous: dict[str, list[str]] = {}
        for normalized, group in by_name.items():
            targets = {a[1] for a in group}
            if len(targets) != 1:
                ambiguous[normalized] = sorted(targets)
                continue
            stable_id = next(iter(targets))
            display_names = {a[2] for a in group}
            aliases[normalized] = CrosswalkAlias(
                alias_normalized_name=normalized,
                canonical_stable_id=stable_id,
                canonical_display_name=sorted(display_names)[0],
                bridge_domains=tuple(sorted({a[3] for a in group})),
                bridge_sources=tuple(sorted({a[4] for a in group})),
                source_organization_names=tuple(sorted({a[5] for a in group})),
                source_authority_hashes=tuple(sorted({a[6] for a in group if a[6]})),
            )

        shared_ror_submission = sorted(
            set(ror_map) & set(submission_map)
        ) if submission_domain_authority is not None else []
        shared_ror_cisa = sorted(
            set(ror_map) & set(cisa_map)
        ) if cisa_authority is not None else []

        audit = {
            "construction_rule": CONSTRUCTION_RULE,
            "ror_domains": len(ror_map),
            "submission_domains": len(submission_map),
            "cisa_domains": len(cisa_map),
            "shared_ror_submission_domains": len(shared_ror_submission),
            "shared_ror_cisa_domains": len(shared_ror_cisa),
            "bridge_assertions": len(assertions),
            "candidate_names": len(by_name),
            "accepted_aliases": len(aliases),
            "ambiguous_aliases_dropped": len(ambiguous),
            "stable_ror_ids_with_aliases": len({
                a.canonical_stable_id for a in aliases.values()
            }),
            "aliases_by_source": dict(sorted(
                Counter(s for a in aliases.values() for s in a.bridge_sources).items()
            )),
            "ambiguous_alias_targets": {k: v for k, v in sorted(ambiguous.items())},
        }
        return cls(aliases=aliases, audit=audit)

    # ------------------------------------------------------------------
    # export helpers
    # ------------------------------------------------------------------
    def audit_dict(self) -> dict[str, Any]:
        return dict(self.audit)

    def csv_rows(self) -> list[dict[str, Any]]:
        """Sanitized CSV rows (normalized name, display name, ROR id, bridge
        domain, source family). No Hunter IP or observation data is ever here."""
        rows: list[dict[str, Any]] = []
        for alias in self.aliases.values():
            for domain in alias.bridge_domains:
                rows.append({
                    "alias_normalized_name": alias.alias_normalized_name,
                    "display_name": alias.canonical_display_name,
                    "ror_id": alias.canonical_stable_id,
                    "bridge_domain": domain,
                    "source_family": "|".join(alias.bridge_sources),
                })
        rows.sort(key=lambda r: (r["alias_normalized_name"], r["bridge_domain"]))
        return rows


def build_alias_crosswalk_from_authorities(
    authorities: Iterable[LoadedAuthority],
) -> AliasCrosswalk:
    """Locate the reviewed domain authorities among ``authorities`` and build.

    Convenience for callers that already hold the full composed authority set.
    Range / exact-IP / ASN authorities are ignored: they have no domain key and
    cannot create bridges.
    """
    ror = next((a for a in authorities if a.source == ROR_SOURCE), None)
    if ror is None:
        raise ValueError(
            "build_alias_crosswalk_from_authorities: no ROR domain authority "
            f"(source={ROR_SOURCE!r}) found among {sorted({a.source for a in authorities})}"
        )
    submission = next((a for a in authorities if a.source == SUBMISSION_DOMAIN_SOURCE), None)
    cisa = next((a for a in authorities if a.source == CISA_SOURCE), None)
    return AliasCrosswalk.build(
        ror_authority=ror,
        submission_domain_authority=submission,
        cisa_authority=cisa,
    )
