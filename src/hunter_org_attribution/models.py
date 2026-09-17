from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


RuleFamily = Literal[
    "direct_range",
    "exact_ip_mapping",
    "official_domain",
    "organization_asn",
    "asn_org_regex",
    "domain_regex",
    "host_regex",
    "title_regex",
]


@dataclass(frozen=True)
class NormalizedHunterRecord:
    """The complete and exclusive runtime input contract for Phase 1."""

    ip: str
    port: int | None = None
    asn: int | None = None
    asn_organization: str | None = None
    root_domain: str | None = None
    domain: str | None = None
    host: str | None = None
    web_title: str | None = None
    hunter_reported_country: str | None = None
    infrastructure_category: str | None = None
    provider_family: str | None = None
    hunter_record_id: str | None = None
    observed_at: str | None = None


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    rule_family: RuleFamily
    target: Literal["organization_identity", "organization_category", "infrastructure"]
    matched_field: str
    observed_value: str
    operator: str
    pattern: str
    source: str
    authority: str
    resolved_organization_id: str | None = None
    resolved_organization: str | None = None
    resolved_category: str | None = None
    infrastructure_organization: str | None = None
    notes: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def rule_type(self) -> RuleFamily:
        """Backward-compatible alias for pre-review callers."""
        return self.rule_family

    @property
    def matched_pattern(self) -> str:
        """Backward-compatible alias for pre-review callers."""
        return self.pattern


@dataclass(frozen=True)
class Resolution:
    organization_id: str | None
    organization_name: str | None
    categories: tuple[str, ...]
    association_types: tuple[str, ...]
    infrastructure_organizations: tuple[str, ...]
    infrastructure_categories: tuple[str, ...]
    infrastructure_category: str | None
    provider_family: str | None
    ambiguity_status: Literal["no_identity", "unambiguous", "ambiguous_conflict"]
    agreement_status: Literal[
        "not_applicable",
        "single_identity_evidence",
        "multi_rule_agreement",
        "conflict",
    ]
    status: Literal["resolved", "category_only", "unresolved", "conflict"]
    conflicting_organizations: tuple[str, ...] = ()

    @property
    def organization(self) -> str | None:
        """Backward-compatible alias for organization_name."""
        return self.organization_name

    @property
    def evidence_types(self) -> tuple[str, ...]:
        """Backward-compatible alias for association_types."""
        return self.association_types


@dataclass(frozen=True)
class AttributionResult:
    schema_version: str
    record: NormalizedHunterRecord
    evidence: tuple[Evidence, ...]
    resolution: Resolution

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
