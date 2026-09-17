"""Deterministic organization attribution for normalized Hunter records."""

from .engine import AttributionEngine
from .hunter_adapter import normalize_hunter_record
from .models import AttributionResult, NormalizedHunterRecord
from .production_adapter import Measurement212Projection, project_measurement212_hunter_record
from .provenance import AuthoritySpec, load_authority

__all__ = [
    "AttributionEngine",
    "AttributionResult",
    "AuthoritySpec",
    "Measurement212Projection",
    "NormalizedHunterRecord",
    "load_authority",
    "normalize_hunter_record",
    "project_measurement212_hunter_record",
]
