from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import Evidence, NormalizedHunterRecord, Resolution


IDENTITY_PRIORITY = {
    "direct_range": 0,
    "exact_ip_mapping": 1,
    "official_domain": 2,
    "organization_asn": 3,
}


def _identity_evidence(evidence: Iterable[Evidence]) -> list[Evidence]:
    return [item for item in evidence if item.resolved_organization]


def canonical_organization_name(value: object) -> str:
    """Canonical comparison form for an organization name.

    Collapses internal whitespace and case-folds. This is deliberately a normal
    form, not a similarity metric: no fuzzy matching is performed anywhere in
    identity reconciliation.
    """
    return " ".join(str(value).strip().split()).casefold()


def _crosswalk_stable_id(item: Evidence, alias_crosswalk) -> str | None:
    """Stable id a name-only evidence row is deterministically associated with.

    Returns None when no crosswalk is supplied or the name has no alias entry.
    Range/exact-IP evidence never *creates* the alias; it may only use a
    crosswalk that was built from independent shared-domain bridges.
    """
    if alias_crosswalk is None or not item.resolved_organization:
        return None
    alias = alias_crosswalk.lookup(item.resolved_organization)
    return alias.canonical_stable_id if alias is not None else None


def _cluster_identities(
    identity_evidence: list[Evidence],
    alias_crosswalk=None,
) -> list[list[Evidence]]:
    """Group identity-bearing evidence into reconciled identity clusters.

    Explicit reconciliation rules (see ``docs/METHOD.md`` section 10):

    1. same non-null ``organization_id``      -> same identity (names may differ)
    2. one non-null ID, other null, canonical names equal -> same identity
    3. both IDs null, canonical names equal   -> same identity
    4. two different non-null IDs             -> identity conflict, even if names match
    5. ID present vs absent with differing names -> distinct identities (conflict)

    Phase 6 cross-source alias crosswalk (section 10.2): a name-only item whose
    normalized name has a deterministic crosswalk entry to a stable id joins the
    id group with that exact stable id, and two name-only items whose names both
    resolve to the same crosswalk id join the same identity. Two *explicit*
    different ids are never merged by the crosswalk.
    """
    id_groups: dict[str, list[Evidence]] = {}
    name_only: list[Evidence] = []
    for item in identity_evidence:
        if item.resolved_organization_id:
            id_groups.setdefault(item.resolved_organization_id, []).append(item)
        else:
            name_only.append(item)

    group_names = {
        group_id: {canonical_organization_name(item.resolved_organization) for item in group}
        for group_id, group in id_groups.items()
    }

    unmatched: list[Evidence] = []
    for item in name_only:
        name = canonical_organization_name(item.resolved_organization)
        crosswalk_id = _crosswalk_stable_id(item, alias_crosswalk)
        name_matches = [group_id for group_id, names in group_names.items() if name in names]
        id_matches = [group_id for group_id in id_groups if crosswalk_id is not None and group_id == crosswalk_id]
        matches = sorted(set(name_matches) | set(id_matches))
        if len(matches) == 1:
            group_id = matches[0]
            id_groups[group_id].append(item)
            group_names[group_id].add(name)
        elif not matches:
            unmatched.append(item)
        # len(matches) > 1: the name/crosswalk agrees with several distinct ID
        # groups. Those ID groups already conflict with each other, so no new
        # cluster is created.

    # Remaining name-only items group by their identity key: the deterministic
    # crosswalk stable id when one exists (so bilingual/no-ID aliases of the same
    # stable id reconcile), otherwise the canonical name (existing rule 3).
    name_groups: dict[str, list[Evidence]] = {}
    for item in unmatched:
        key = _crosswalk_stable_id(item, alias_crosswalk) or canonical_organization_name(
            item.resolved_organization
        )
        name_groups.setdefault(key, []).append(item)

    return list(id_groups.values()) + list(name_groups.values())


def _cluster_organization_id(cluster: list[Evidence], alias_crosswalk=None) -> str | None:
    identifiers = sorted({item.resolved_organization_id for item in cluster if item.resolved_organization_id})
    if identifiers:
        return identifiers[0]
    if alias_crosswalk is not None:
        derived = sorted({
            alias.canonical_stable_id
            for item in cluster
            if item.resolved_organization
            for alias in (alias_crosswalk.lookup(item.resolved_organization),)
            if alias is not None
        })
        # A cluster groups by a single identity key, so at most one derived id
        # is expected; anything else fails closed (no derived id).
        if len(derived) == 1:
            return derived[0]
    return None


def _cluster_organization_name(cluster: list[Evidence], alias_crosswalk=None) -> str | None:
    """Deterministic display name for a cluster.

    Names carried alongside an explicit identifier take precedence; the
    remaining candidates are ordered deterministically. Differing names inside
    one cluster are a display-name discrepancy, and every individual name stays
    visible on its own evidence row.

    Phase 6: a cluster whose identity is fully crosswalk-derived uses the stable
    id's canonical display name, so Chinese no-ID names and English ROR names of
    one institution unify on one display name instead of splitting.
    """
    with_id = sorted({item.resolved_organization for item in cluster if item.resolved_organization_id and item.resolved_organization})
    if with_id:
        return with_id[0]
    if alias_crosswalk is not None:
        derived = sorted({
            alias.canonical_display_name
            for item in cluster
            if item.resolved_organization
            for alias in (alias_crosswalk.lookup(item.resolved_organization),)
            if alias is not None
        })
        if len(derived) == 1:
            return derived[0]
    without_id = sorted({item.resolved_organization for item in cluster if item.resolved_organization})
    return without_id[0] if without_id else None


def _association_types(evidence: tuple[Evidence, ...], *, add_multi_rule: bool) -> tuple[str, ...]:
    base_types = {e.rule_family for e in evidence}
    if add_multi_rule:
        base_types.add("multi_rule")
    return tuple(sorted(base_types))


def resolve(
    evidence: tuple[Evidence, ...],
    record: NormalizedHunterRecord,
    alias_crosswalk=None,
) -> Resolution:
    identity_evidence = _identity_evidence(evidence)

    organization_categories = tuple(sorted({
        e.resolved_category
        for e in evidence
        if e.resolved_category and e.target in {"organization_identity", "organization_category"}
    }))
    infrastructure = tuple(sorted({
        e.infrastructure_organization
        for e in evidence
        if e.infrastructure_organization
    }))
    infrastructure_category_values = {
        e.resolved_category
        for e in evidence
        if e.resolved_category and e.target == "infrastructure"
    }
    if record.infrastructure_category:
        infrastructure_category_values.add(record.infrastructure_category)
    infrastructure_categories = tuple(sorted(infrastructure_category_values))

    clusters = _cluster_identities(identity_evidence, alias_crosswalk)

    if not clusters:
        status = "category_only" if organization_categories else "unresolved"
        return Resolution(
            organization_id=None,
            organization_name=None,
            categories=organization_categories,
            association_types=_association_types(evidence, add_multi_rule=False),
            infrastructure_organizations=infrastructure,
            infrastructure_categories=infrastructure_categories,
            infrastructure_category=record.infrastructure_category,
            provider_family=record.provider_family,
            ambiguity_status="no_identity",
            agreement_status="not_applicable",
            status=status,
        )

    if len(clusters) > 1:
        conflict_names = tuple(sorted({
            name for name in (_cluster_organization_name(cluster, alias_crosswalk) for cluster in clusters) if name
        }))
        return Resolution(
            organization_id=None,
            organization_name=None,
            categories=organization_categories,
            association_types=_association_types(evidence, add_multi_rule=False),
            infrastructure_organizations=infrastructure,
            infrastructure_categories=infrastructure_categories,
            infrastructure_category=record.infrastructure_category,
            provider_family=record.provider_family,
            ambiguity_status="ambiguous_conflict",
            agreement_status="conflict",
            status="conflict",
            conflicting_organizations=conflict_names,
        )

    cluster = clusters[0]
    agreement = "multi_rule_agreement" if len(cluster) > 1 else "single_identity_evidence"
    return Resolution(
        organization_id=_cluster_organization_id(cluster, alias_crosswalk),
        organization_name=_cluster_organization_name(cluster, alias_crosswalk),
        categories=organization_categories,
        association_types=_association_types(evidence, add_multi_rule=len(cluster) > 1),
        infrastructure_organizations=infrastructure,
        infrastructure_categories=infrastructure_categories,
        infrastructure_category=record.infrastructure_category,
        provider_family=record.provider_family,
        ambiguity_status="unambiguous",
        agreement_status=agreement,
        status="resolved",
    )