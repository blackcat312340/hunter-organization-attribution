"""Deterministic organization attribution for normalized Hunter records."""

from .authority_sources import (
    CHINA_INSTITUTION_RANGE_ADAPTER,
    DOMAIN_ORG_ASSOCIATION_ADAPTER,
    EXACT_IP_ORG_ASSOCIATION_ADAPTER,
    adapt_china_institution_ranges,
    adapt_domain_org,
    adapt_exact_ip_org,
    load_china_institution_range_authority,
    load_domain_org_authority,
    load_exact_ip_org_authority,
)
from .engine import AttributionEngine
from .hunter_adapter import normalize_hunter_record
from .models import AttributionResult, NormalizedHunterRecord
from .production_adapter import Measurement212Projection, project_measurement212_hunter_record
from .provenance import AuthoritySourceError, AuthoritySpec, load_authority, load_authority_rows

__all__ = [
    "AttributionEngine",
    "AttributionResult",
    "AuthoritySourceError",
    "AuthoritySpec",
    "CHINA_INSTITUTION_RANGE_ADAPTER",
    "DOMAIN_ORG_ASSOCIATION_ADAPTER",
    "EXACT_IP_ORG_ASSOCIATION_ADAPTER",
    "Measurement212Projection",
    "NormalizedHunterRecord",
    "adapt_china_institution_ranges",
    "adapt_domain_org",
    "adapt_exact_ip_org",
    "load_authority",
    "load_authority_rows",
    "load_china_institution_range_authority",
    "load_domain_org_authority",
    "load_exact_ip_org_authority",
    "normalize_hunter_record",
    "project_measurement212_hunter_record",
]
