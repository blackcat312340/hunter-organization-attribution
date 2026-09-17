from __future__ import annotations

from collections import defaultdict

from .models import Evidence, NormalizedHunterRecord, Resolution


IDENTITY_PRIORITY = {
    "direct_range": 0,
    "exact_ip_mapping": 1,
    "official_domain": 2,
    "organization_asn": 3,
}


def resolve(evidence: tuple[Evidence, ...], record: NormalizedHunterRecord) -> Resolution:
    identities: dict[tuple[str | None, str], list[Evidence]] = defaultdict(list)
    identity_evidence: list[Evidence] = []
    for item in evidence:
        if item.resolved_organization:
            key = (item.resolved_organization_id, item.resolved_organization)
            identities[key].append(item)
            identity_evidence.append(item)

    categories = tuple(sorted({e.resolved_category for e in evidence if e.resolved_category}))
    infrastructure = tuple(sorted({e.infrastructure_organization for e in evidence if e.infrastructure_organization}))
    base_types = {e.rule_family for e in evidence}
    association_types = tuple(sorted(base_types | ({"multi_rule"} if len(evidence) > 1 else set())))

    if not identities:
        status = "category_only" if categories else "unresolved"
        return Resolution(
            organization_id=None,
            organization_name=None,
            categories=categories,
            association_types=association_types,
            infrastructure_organizations=infrastructure,
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
            categories=categories,
            association_types=association_types,
            infrastructure_organizations=infrastructure,
            infrastructure_category=record.infrastructure_category,
            provider_family=record.provider_family,
            ambiguity_status="ambiguous_conflict",
            agreement_status="conflict",
            status="conflict",
            conflicting_organizations=conflict_names,
        )

    organization_id, organization_name = identity_keys[0]
    agreement = "multi_rule_agreement" if len(identity_evidence) > 1 else "single_identity_evidence"
    return Resolution(
        organization_id=organization_id,
        organization_name=organization_name,
        categories=categories,
        association_types=association_types,
        infrastructure_organizations=infrastructure,
        infrastructure_category=record.infrastructure_category,
        provider_family=record.provider_family,
        ambiguity_status="unambiguous",
        agreement_status=agreement,
        status="resolved",
    )
