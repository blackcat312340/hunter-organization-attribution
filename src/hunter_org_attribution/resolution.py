from __future__ import annotations

from collections import defaultdict

from .models import Evidence, NormalizedHunterRecord, Resolution


IDENTITY_PRIORITY = {
    "direct_range": 0,
    "exact_ip_mapping": 1,
    "official_domain": 2,
    "organization_asn": 3,
}


def _identity_key(item: Evidence) -> tuple[str | None, str] | None:
    if not item.resolved_organization:
        return None
    return (item.resolved_organization_id, item.resolved_organization)


def _association_types(evidence: tuple[Evidence, ...], *, add_multi_rule: bool) -> tuple[str, ...]:
    base_types = {e.rule_family for e in evidence}
    if add_multi_rule:
        base_types.add("multi_rule")
    return tuple(sorted(base_types))


def resolve(evidence: tuple[Evidence, ...], record: NormalizedHunterRecord) -> Resolution:
    identities: dict[tuple[str | None, str], list[Evidence]] = defaultdict(list)
    identity_evidence: list[Evidence] = []
    for item in evidence:
        key = _identity_key(item)
        if key is not None:
            identities[key].append(item)
            identity_evidence.append(item)

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

    if not identities:
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

    identity_keys = tuple(sorted(identities, key=lambda k: ((k[0] or ""), k[1])))
    if len(identity_keys) > 1:
        conflict_names = tuple(sorted({name for _, name in identity_keys}))
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

    organization_id, organization_name = identity_keys[0]
    agreeing_identity_rules = len(identity_evidence)
    agreement = "multi_rule_agreement" if agreeing_identity_rules > 1 else "single_identity_evidence"
    return Resolution(
        organization_id=organization_id,
        organization_name=organization_name,
        categories=organization_categories,
        association_types=_association_types(evidence, add_multi_rule=agreeing_identity_rules > 1),
        infrastructure_organizations=infrastructure,
        infrastructure_categories=infrastructure_categories,
        infrastructure_category=record.infrastructure_category,
        provider_family=record.provider_family,
        ambiguity_status="unambiguous",
        agreement_status=agreement,
        status="resolved",
    )
