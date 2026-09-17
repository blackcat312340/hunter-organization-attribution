#!/usr/bin/env python3
"""Read-only small-sample validator for the Measurement 212 Hunter interface.

The validator deliberately emits aggregate schema/status counts only. It never
prints raw IPs, hostnames, titles, service labels, or other observation values.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import sys
from typing import Any

from hunter_org_attribution import AttributionEngine, project_measurement212_hunter_record
from hunter_org_attribution.production_adapter import (
    MEASUREMENT212_ASN_ENRICHMENT_FIELDS,
    MEASUREMENT212_ATTRIBUTION_FIELDS,
    MEASUREMENT212_KNOWN_NONATTRIBUTION_FIELDS,
    MEASUREMENT212_SOURCE_SHA,
)


def asn_key(value: object) -> str | None:
    text = str(value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    if not text:
        return None
    try:
        number = int(text)
    except ValueError:
        return None
    return str(number) if number > 0 else None


def load_asn_lookup(path: Path | None) -> tuple[dict[str, dict[str, str]], tuple[str, ...]]:
    if path is None:
        return {}, ()
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = tuple(reader.fieldnames or ())
        unknown = tuple(sorted(set(fields) - MEASUREMENT212_ASN_ENRICHMENT_FIELDS))
        rows: dict[str, dict[str, str]] = {}
        for row in reader:
            key = asn_key(row.get("asn"))
            if key is not None:
                rows[key] = dict(row)
    return rows, unknown


def validate(path: Path, *, limit: int, allow_unreviewed: bool, asn_lookup_path: Path | None) -> dict[str, Any]:
    if limit < 1:
        raise ValueError("limit must be >= 1")

    asn_lookup, lookup_unknown_columns = load_asn_lookup(asn_lookup_path)
    engine = AttributionEngine.from_repository_defaults()

    consumed = Counter()
    ignored = Counter()
    unknown = Counter()
    enrichment = Counter()
    statuses = Counter()
    errors = Counter()
    checked = projected = 0

    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if checked >= limit:
                break
            if not line.strip():
                continue
            checked += 1
            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise TypeError("JSON record is not an object")
            except (json.JSONDecodeError, TypeError):
                errors["invalid_json_object"] += 1
                continue

            # Inventory schema drift before projection so strict failures still
            # contribute field-name counts without exposing field values.
            known_raw = MEASUREMENT212_ATTRIBUTION_FIELDS | MEASUREMENT212_KNOWN_NONATTRIBUTION_FIELDS
            unknown.update(set(raw) - known_raw)

            key = asn_key(raw.get("asn"))
            asn_enrichment = asn_lookup.get(key) if key is not None else None
            try:
                projection = project_measurement212_hunter_record(
                    raw,
                    asn_enrichment=asn_enrichment,
                    strict_contract=not allow_unreviewed,
                )
                result = engine.attribute(projection.record)
            except (TypeError, ValueError):
                errors["projection_or_normalization"] += 1
                continue

            projected += 1
            consumed.update(projection.consumed_fields)
            ignored.update(projection.ignored_known_fields)
            enrichment.update(projection.enrichment_fields)
            statuses[result.resolution.status] += 1

    return {
        "schema": "measurement212_hunter_interface_smoke_v1",
        "production_source_sha": MEASUREMENT212_SOURCE_SHA,
        "mode": "audit_allow_unreviewed" if allow_unreviewed else "strict_contract",
        "limit": limit,
        "records_checked": checked,
        "records_projected": projected,
        "records_failed": sum(errors.values()),
        "resolution_status_counts": dict(sorted(statuses.items())),
        "consumed_field_counts": dict(sorted(consumed.items())),
        "ignored_known_field_counts": dict(sorted(ignored.items())),
        "unknown_raw_field_counts": dict(sorted(unknown.items())),
        "asn_enrichment_field_counts": dict(sorted(enrichment.items())),
        "asn_lookup_unknown_columns": list(lookup_unknown_columns),
        "error_class_counts": dict(sorted(errors.items())),
        "raw_values_emitted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path, help="one line-delimited Hunter JSON snapshot file")
    parser.add_argument("--limit", type=int, default=100, help="maximum nonblank records to inspect (default: 100)")
    parser.add_argument("--asn-lookup", type=Path, default=None, help="optional reviewed ASN lookup CSV")
    parser.add_argument(
        "--allow-unreviewed",
        action="store_true",
        help="inventory unknown production fields without admitting their values to attribution rules",
    )
    args = parser.parse_args()

    try:
        summary = validate(
            args.snapshot,
            limit=args.limit,
            allow_unreviewed=args.allow_unreviewed,
            asn_lookup_path=args.asn_lookup,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "validator_error", "error_type": type(exc).__name__}, sort_keys=True))
        return 2

    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["records_checked"] == 0:
        return 2
    if not args.allow_unreviewed and (
        summary["records_failed"] > 0
        or summary["unknown_raw_field_counts"]
        or summary["asn_lookup_unknown_columns"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
