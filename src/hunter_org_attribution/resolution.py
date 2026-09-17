from __future__ import annotations

from collections import defaultdict

from .models import Evidence, Resolution


IDENTITY_PRIORITY = {
    "direct_range": 0,
    "exact_ip_mapping": 1,
    "official_domain": 2,
    "organization_asn": 3,
}


def resolve(evidence: tuple[Evidence, ...]) -> Resolution:
    identities: dict[str, list[Evidence]] = defaultdict(list)
    for item in evidence:
        if item.resolved_organization:
            identities[item.resolved_organization].append(item)

    categories = tuple(sorted({e.resolved_category for e in evidence if e.resolved_category}))
    infrastructure = tuple(sorted({e.infrastructure_organization for e in evidence if e.infrastructure_organization}))
    base_types = {e.rule_type for e in evidence}
    evidence_types = tuple(sorted(base_types | ({"multi_rule"} if len(evidence) > 1 else set())))

    if not identities:
        status = "category_only" if categories else "unresolved"
        return Resolution(None, categories, infrastructure, status, evidence_types)

    organizations = tuple(sorted(identities))
    if len(organizations) > 1:
        return Resolution(None, categories, infrastructure, "conflict", evidence_types, organizations)

    # There is exactly one identity. Priority governs presentation order only;
    # no evidence is discarded and no numeric confidence is synthesized.
    organization = organizations[0]
    return Resolution(organization, categories, infrastructure, "resolved", evidence_types)

