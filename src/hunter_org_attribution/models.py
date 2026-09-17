from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


RuleType = Literal[
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
    """The complete and exclusive runtime input contract."""

    ip: str
    root_domain: str | None = None
    domain: str | None = None
    host: str | None = None
    web_title: str | None = None
    asn: int | None = None
    asn_organization: str | None = None
    hunter_record_id: str | None = None
    observed_at: str | None = None


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    rule_type: RuleType
    matched_field: str
    observed_value: str
    matched_pattern: str
    authority: str
    resolved_organization: str | None = None
    resolved_category: str | None = None
    infrastructure_organization: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Resolution:
    organization: str | None
    categories: tuple[str, ...]
    infrastructure_organizations: tuple[str, ...]
    status: Literal["resolved", "category_only", "unresolved", "conflict"]
    evidence_types: tuple[str, ...]
    conflicting_organizations: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttributionResult:
    schema_version: str
    record: NormalizedHunterRecord
    evidence: tuple[Evidence, ...]
    resolution: Resolution

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

