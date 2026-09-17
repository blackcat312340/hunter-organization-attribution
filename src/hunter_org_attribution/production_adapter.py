from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .hunter_adapter import normalize_hunter_record
from .models import NormalizedHunterRecord
from .normalize import clean_text, normalize_asn


MEASUREMENT212_SOURCE_REPO = "blackcat312340/findings-graph"
MEASUREMENT212_SOURCE_BRANCH = "agent/m212-institution-ip-export-20260916"
MEASUREMENT212_SOURCE_SHA = "2ba9545f87b55d393e3e155fea75deb165b7b9ac"
MEASUREMENT212_SOURCE_SCRIPT = "scripts/build_measurement_212_institution_ip_export.py"
MEASUREMENT212_SOURCE_SCRIPT_BLOB = "89a7d1fc1e0cfce4f90b129c53c36476a5ccc7a6"
MEASUREMENT212_ASN_LOOKUP_SCRIPT = "scripts/build_measurement_212_asn_v2_lookup.py"
MEASUREMENT212_ASN_LOOKUP_SCRIPT_BLOB = "49ae1e784de77a515d0fe75c950e1fe560a78f4b"

# Fields directly consumed by the organization-attribution runtime. These names
# are verified against the production Measurement 212 reader at the source SHA
# above. They are intentionally narrower than the complete Hunter snapshot.
MEASUREMENT212_ATTRIBUTION_FIELDS = frozenset(
    {
        "ip",
        "port",
        "asn",
        "root_domain",
        "domain",
        "host",
        "web_title",
        "country",
    }
)

# Production fields verified in the same reader but deliberately excluded from
# organization attribution. They belong to service/fingerprint/transport logic.
MEASUREMENT212_KNOWN_NONATTRIBUTION_FIELDS = frozenset(
    {
        "full_name",
        "http_head",
        "protocol_type",
        "favicon",
    }
)

# The frozen ASN lookup exports aggregate network context, not ASN organization
# registration text. In particular, it does not provide asn_organization.
MEASUREMENT212_ASN_ENRICHMENT_FIELDS = frozenset(
    {
        "asn",
        "asn_category",
        "provider_family",
        "is_cloud_provider",
        "is_cloud_or_hosting_infra",
        "classification_confidence",
        "classification_rule",
    }
)


@dataclass(frozen=True)
class Measurement212Projection:
    record: NormalizedHunterRecord
    consumed_fields: tuple[str, ...]
    ignored_known_fields: tuple[str, ...]
    unknown_fields: tuple[str, ...]
    enrichment_fields: tuple[str, ...]
    source_sha: str = MEASUREMENT212_SOURCE_SHA


def _nonempty_keys(raw: Mapping[str, object], allowed: frozenset[str]) -> tuple[str, ...]:
    return tuple(sorted(k for k in allowed if k in raw and raw[k] not in (None, "")))


def _validate_enrichment_asn(raw: Mapping[str, object], enrichment: Mapping[str, object]) -> None:
    if raw.get("asn") in (None, "") or enrichment.get("asn") in (None, ""):
        return
    raw_asn = normalize_asn(raw.get("asn"))
    enrichment_asn = normalize_asn(enrichment.get("asn"))
    if raw_asn != enrichment_asn:
        raise ValueError(
            f"ASN enrichment mismatch: Hunter record ASN {raw_asn} != enrichment ASN {enrichment_asn}"
        )


def project_measurement212_hunter_record(
    raw: Mapping[str, object],
    *,
    asn_enrichment: Mapping[str, object] | None = None,
    observed_at: object | None = None,
    hunter_record_id: object | None = None,
    strict_contract: bool = True,
) -> Measurement212Projection:
    """Project one production Measurement 212 Hunter row into the frozen method input.

    The function is deliberately a projection, not a permissive alias layer. Known
    service-identification fields are explicitly ignored and never become attribution
    evidence. Unknown production fields fail closed when ``strict_contract=True``.
    """

    known = MEASUREMENT212_ATTRIBUTION_FIELDS | MEASUREMENT212_KNOWN_NONATTRIBUTION_FIELDS
    unknown = tuple(sorted(set(raw) - known))
    if strict_contract and unknown:
        raise ValueError(f"Unreviewed Measurement 212 Hunter fields: {', '.join(unknown)}")

    projected: dict[str, object] = {
        key: raw[key]
        for key in MEASUREMENT212_ATTRIBUTION_FIELDS
        if key in raw
    }

    enrichment_fields: tuple[str, ...] = ()
    if asn_enrichment is not None:
        enrichment_unknown = tuple(sorted(set(asn_enrichment) - MEASUREMENT212_ASN_ENRICHMENT_FIELDS))
        if strict_contract and enrichment_unknown:
            raise ValueError(
                "Unreviewed Measurement 212 ASN enrichment fields: "
                + ", ".join(enrichment_unknown)
            )
        _validate_enrichment_asn(raw, asn_enrichment)
        if asn_enrichment.get("asn_category") not in (None, ""):
            projected["infrastructure_category"] = asn_enrichment["asn_category"]
        if asn_enrichment.get("provider_family") not in (None, ""):
            projected["provider_family"] = asn_enrichment["provider_family"]
        enrichment_fields = _nonempty_keys(asn_enrichment, MEASUREMENT212_ASN_ENRICHMENT_FIELDS)

    if observed_at not in (None, ""):
        projected["observed_at"] = clean_text(observed_at)
    if hunter_record_id not in (None, ""):
        projected["hunter_record_id"] = clean_text(hunter_record_id)

    record = normalize_hunter_record(projected, strict=True)
    return Measurement212Projection(
        record=record,
        consumed_fields=_nonempty_keys(raw, MEASUREMENT212_ATTRIBUTION_FIELDS),
        ignored_known_fields=_nonempty_keys(raw, MEASUREMENT212_KNOWN_NONATTRIBUTION_FIELDS),
        unknown_fields=unknown,
        enrichment_fields=enrichment_fields,
    )
