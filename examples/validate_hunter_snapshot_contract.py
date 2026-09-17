#!/usr/bin/env python3
"""Read-only small-sample validator for the Measurement 212 Hunter interface.

The validator deliberately emits aggregate schema/status counts only. It never
prints raw IPs, hostnames, titles, service labels, or other observation values.

Reviewed authorities are supplied by explicit, semantically named flags so the
composition is auditable and nothing is guessed from a file name::

    --china-ranges    ...   institution IPv4 range authority
    --domain-org      ...   reviewed domain association authority
    --exact-ip-org    ...   reviewed exact-IP association authority
    --cisa-dotgov     ...   CISA .gov registrar direct domain identity
    --ror-dump        ...   ROR schema-v2 direct research-domain identity
    --caida-as2org    ...   CAIDA AS->asn_organization network text enrichment

Every flag accepts a matching ``--<name>-sha256`` so a frozen artifact is pinned
before parsing. ``--strict-authority`` requires that pin.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import sys
from typing import Any

from hunter_org_attribution import AuthorityComposition, AuthorityArtifact, project_measurement212_hunter_record
from hunter_org_attribution.asn_organization import AsnOrganizationEnrichmentConflict
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


def _artifact(path: Path | None, sha256: str) -> AuthorityArtifact | None:
    if path is None:
        return None
    return AuthorityArtifact(path=path, expected_sha256=sha256, provenance={"supplied_via": "cli"})


def build_composition(args: argparse.Namespace):
    composition = AuthorityComposition(
        china_ipv4_ranges=_artifact(args.china_ranges, args.china_ranges_sha256),
        submission_domains=_artifact(args.domain_org, args.domain_org_sha256),
        submission_exact_ips=_artifact(args.exact_ip_org, args.exact_ip_org_sha256),
        cisa_dotgov=_artifact(args.cisa_dotgov, args.cisa_dotgov_sha256),
        ror_domains=_artifact(args.ror_dump, args.ror_dump_sha256),
        caida_as2org=(
            AuthorityArtifact(
                path=args.caida_as2org,
                expected_sha256=args.caida_as2org_sha256,
                version=args.caida_as2org_version,
                provenance={"supplied_via": "cli"},
            )
            if args.caida_as2org is not None
            else None
        ),
    )
    frozen = {
        "china-ranges": (args.china_ranges, args.china_ranges_sha256),
        "domain-org": (args.domain_org, args.domain_org_sha256),
        "exact-ip-org": (args.exact_ip_org, args.exact_ip_org_sha256),
        "cisa-dotgov": (args.cisa_dotgov, args.cisa_dotgov_sha256),
        "ror-dump": (args.ror_dump, args.ror_dump_sha256),
        "caida-as2org": (args.caida_as2org, args.caida_as2org_sha256),
    }
    unpinned = sorted(name for name, (path, sha) in frozen.items() if path is not None and not sha)
    if args.strict_authority and unpinned:
        raise ValueError(
            "strict authority validation requires a --<authority>-sha256 for: " + ", ".join(unpinned)
        )
    return composition


def validate(args: argparse.Namespace) -> dict[str, Any]:
    if args.limit < 1:
        raise ValueError("limit must be >= 1")

    composition = build_composition(args)
    composed = composition.load()
    engine = composed.engine
    asn_lookup, lookup_unknown_columns = load_asn_lookup(args.asn_lookup)

    consumed = Counter()
    ignored = Counter()
    unknown = Counter()
    enrichment = Counter()
    statuses = Counter()
    association_types = Counter()
    identity_sources = Counter()
    category_counts = Counter()
    infrastructure_category_counts = Counter()
    caida_enrichment = Counter()
    errors = Counter()
    checked = projected = 0

    with args.snapshot.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if checked >= args.limit:
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
                    strict_contract=not args.allow_unreviewed,
                )
                result = engine.attribute(projection.record)
            except AsnOrganizationEnrichmentConflict:
                errors["asn_organization_enrichment_conflict"] += 1
                continue
            except (TypeError, ValueError):
                errors["projection_or_normalization"] += 1
                continue

            projected += 1
            consumed.update(projection.consumed_fields)
            ignored.update(projection.ignored_known_fields)
            enrichment.update(projection.enrichment_fields)
            statuses[result.resolution.status] += 1
            association_types.update(result.resolution.association_types)
            category_counts.update(result.resolution.categories)
            infrastructure_category_counts.update(result.resolution.infrastructure_categories)
            for evidence in result.evidence:
                if evidence.resolved_organization:
                    identity_sources[evidence.source] += 1
                block = evidence.provenance.get("asn_organization_enrichment")
                if isinstance(block, dict):
                    caida_enrichment[f"origin:{block.get('origin')}"] += 1

    summary = {
        "schema": "measurement212_hunter_interface_smoke_v2",
        "production_source_sha": MEASUREMENT212_SOURCE_SHA,
        "mode": "audit_allow_unreviewed" if args.allow_unreviewed else "strict_contract",
        "limit": args.limit,
        "records_checked": checked,
        "records_projected": projected,
        "records_failed": sum(errors.values()),
        "resolution_status_counts": dict(sorted(statuses.items())),
        "association_type_counts": dict(sorted(association_types.items())),
        "identity_evidence_source_counts": dict(sorted(identity_sources.items())),
        "organization_category_counts": dict(sorted(category_counts.items())),
        "infrastructure_category_counts": dict(sorted(infrastructure_category_counts.items())),
        "asn_organization_enrichment_counts": dict(sorted(caida_enrichment.items())),
        "consumed_field_counts": dict(sorted(consumed.items())),
        "ignored_known_field_counts": dict(sorted(ignored.items())),
        "unknown_raw_field_counts": dict(sorted(unknown.items())),
        "asn_enrichment_field_counts": dict(sorted(enrichment.items())),
        "asn_lookup_unknown_columns": list(lookup_unknown_columns),
        "error_class_counts": dict(sorted(errors.items())),
        "raw_values_emitted": False,
    }
    if args.authority_report:
        summary["authority_composition"] = composed.audit
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("snapshot", type=Path, help="one line-delimited Hunter JSON snapshot file")
    parser.add_argument("--limit", type=int, default=100, help="maximum nonblank records to inspect (default: 100)")
    parser.add_argument("--asn-lookup", type=Path, default=None, help="optional reviewed ASN infrastructure lookup CSV")
    parser.add_argument("--china-ranges", type=Path, default=None, help="reviewed institution IPv4 range authority")
    parser.add_argument("--china-ranges-sha256", default="", help="frozen SHA-256 of --china-ranges")
    parser.add_argument("--domain-org", type=Path, default=None, help="reviewed domain association authority")
    parser.add_argument("--domain-org-sha256", default="", help="frozen SHA-256 of --domain-org")
    parser.add_argument("--exact-ip-org", type=Path, default=None, help="reviewed exact-IP association authority")
    parser.add_argument("--exact-ip-org-sha256", default="", help="frozen SHA-256 of --exact-ip-org")
    parser.add_argument("--cisa-dotgov", type=Path, default=None, help="CISA dotgov-data registrar export")
    parser.add_argument("--cisa-dotgov-sha256", default="", help="frozen SHA-256 of --cisa-dotgov")
    parser.add_argument("--ror-dump", type=Path, default=None, help="ROR schema-v2 data dump (zip, json or jsonl)")
    parser.add_argument("--ror-dump-sha256", default="", help="frozen SHA-256 of --ror-dump")
    parser.add_argument("--caida-as2org", type=Path, default=None, help="CAIDA as2org dated dump (.txt.gz or .txt)")
    parser.add_argument("--caida-as2org-sha256", default="", help="frozen SHA-256 of --caida-as2org")
    parser.add_argument("--caida-as2org-version", default=None, help="CAIDA build version, e.g. 20260901")
    parser.add_argument(
        "--strict-authority",
        action="store_true",
        help="require a frozen SHA-256 for every supplied authority and verify it before parsing",
    )
    parser.add_argument(
        "--authority-report",
        action="store_true",
        help="include the aggregate authority composition audit in the output",
    )
    parser.add_argument(
        "--allow-unreviewed",
        action="store_true",
        help="inventory unknown production fields without admitting their values to attribution rules",
    )
    args = parser.parse_args()

    try:
        summary = validate(args)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "validator_error", "error_type": type(exc).__name__, "detail": str(exc)}, sort_keys=True))
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
