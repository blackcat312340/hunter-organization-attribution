from __future__ import annotations

from bisect import bisect_right
import ipaddress
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .models import AttributionResult, Evidence, NormalizedHunterRecord
from .provenance import LoadedAuthority
from .resolution import resolve
from .rules.loader import load_rules


RULE_FAMILY_BY_FIELD = {
    "asn_organization": "asn_org_regex",
    "root_domain": "domain_regex",
    "domain": "domain_regex",
    "host": "host_regex",
    "web_title": "title_regex",
}


class AttributionEngine:
    def __init__(self, rules: Iterable[dict[str, Any]] = (), authorities: Iterable[LoadedAuthority] = ()):
        self.rules = tuple(sorted((r for r in rules if r.get("executable", True)), key=lambda r: r["rule_id"]))
        self.authorities = tuple(sorted(authorities, key=lambda a: (a.authority_type, a.source, a.sha256)))
        self._compiled = {
            rule["rule_id"]: re.compile(rule["pattern"], re.IGNORECASE)
            for rule in self.rules if rule["operator"] == "regex"
        }

        self._range_entries: list[tuple[int, int, LoadedAuthority, dict[str, Any], int]] = []
        self._range_starts: list[int] = []
        self._range_prefix_max_end: list[int] = []
        self._exact_ip_index: dict[str, list[tuple[LoadedAuthority, dict[str, Any], int]]] = defaultdict(list)
        self._domain_index: dict[str, list[tuple[LoadedAuthority, dict[str, Any], int]]] = defaultdict(list)
        self._asn_index: dict[int, list[tuple[LoadedAuthority, dict[str, Any], int]]] = defaultdict(list)
        self._build_authority_indexes()

    @classmethod
    def from_repository_defaults(cls, authorities: Iterable[LoadedAuthority] = ()) -> "AttributionEngine":
        root = Path(__file__).resolve().parents[2]
        rule_root = root / "rules"
        paths = [rule_root / name for name in ("categories.yaml", "organization_patterns.yaml", "domain_patterns.yaml")]
        return cls(load_rules(paths), authorities)

    @staticmethod
    def _canonical_domain(value: object) -> str:
        return str(value).strip().lower().lstrip(".").rstrip(".")

    def _build_authority_indexes(self) -> None:
        for authority in self.authorities:
            for index, row in enumerate(authority.rows, start=1):
                if authority.authority_type == "ipv4_ranges":
                    start = int(ipaddress.ip_address(str(row["start_ip"])))
                    end = int(ipaddress.ip_address(str(row["end_ip"])))
                    self._range_entries.append((start, end, authority, row, index))
                elif authority.authority_type == "exact_ip":
                    ip = str(ipaddress.ip_address(str(row["ip"])))
                    self._exact_ip_index[ip].append((authority, row, index))
                elif authority.authority_type == "domains":
                    domain = self._canonical_domain(row["domain"])
                    self._domain_index[domain].append((authority, row, index))
                elif authority.authority_type == "asn":
                    asn = int(str(row["asn"]).upper().removeprefix("AS"))
                    self._asn_index[asn].append((authority, row, index))

        self._range_entries.sort(
            key=lambda item: (
                item[0], item[1], item[2].source, item[2].sha256, item[4]
            )
        )
        self._range_starts = [entry[0] for entry in self._range_entries]
        max_end = -1
        for _, end, _, _, _ in self._range_entries:
            max_end = max(max_end, end)
            self._range_prefix_max_end.append(max_end)

    @staticmethod
    def _match(operator: str, pattern: str, value: str, compiled: re.Pattern[str] | None) -> bool:
        folded = value.casefold()
        if operator == "regex":
            return bool(compiled and compiled.search(value))
        if operator == "equals":
            return folded == pattern.casefold()
        if operator == "suffix":
            suffix = pattern.casefold().lstrip(".")
            return folded == suffix or folded.endswith("." + suffix)
        return False

    @staticmethod
    def _structured_evidence(
        *,
        rule_id: str,
        rule_family: str,
        matched_field: str,
        observed_value: str,
        operator: str,
        pattern: str,
        authority: LoadedAuthority,
        row: dict[str, Any],
        target: str = "organization_identity",
        infrastructure_organization: str | None = None,
    ) -> Evidence:
        return Evidence(
            rule_id=rule_id,
            rule_family=rule_family,
            target=target,
            matched_field=matched_field,
            observed_value=observed_value,
            operator=operator,
            pattern=pattern,
            source=authority.source,
            authority=authority.authority_type,
            resolved_organization_id=(str(row["organization_id"]) if row.get("organization_id") else None),
            resolved_organization=(str(row["organization"]) if target == "organization_identity" else None),
            resolved_category=(str(row["category"]) if row.get("category") else None),
            infrastructure_organization=infrastructure_organization,
            notes=(str(row["notes"]) if row.get("notes") else None),
            provenance={**authority.audit, "authority_sha256": authority.sha256},
        )

    @staticmethod
    def _rule_id(authority: LoadedAuthority, row: dict[str, Any], index: int) -> str:
        return str(row.get("rule_id") or f"{authority.source}:{authority.authority_type}:{index}")

    def _range_matches(self, ip_value: int) -> list[tuple[LoadedAuthority, dict[str, Any], int, int, int]]:
        if not self._range_entries:
            return []
        position = bisect_right(self._range_starts, ip_value) - 1
        matches: list[tuple[LoadedAuthority, dict[str, Any], int, int, int]] = []
        i = position
        while i >= 0 and self._range_prefix_max_end[i] >= ip_value:
            start, end, authority, row, index = self._range_entries[i]
            if start <= ip_value <= end:
                matches.append((authority, row, index, start, end))
            i -= 1
        return matches

    @staticmethod
    def _domain_suffixes(value: str) -> tuple[str, ...]:
        labels = value.split(".")
        return tuple(".".join(labels[i:]) for i in range(len(labels)))

    def _authority_evidence(self, record: NormalizedHunterRecord) -> list[Evidence]:
        found: list[Evidence] = []
        ip_value = int(ipaddress.ip_address(record.ip))

        for authority, row, index, start, end in self._range_matches(ip_value):
            found.append(self._structured_evidence(
                rule_id=self._rule_id(authority, row, index),
                rule_family="direct_range",
                matched_field="ip",
                observed_value=record.ip,
                operator="contains",
                pattern=f"{ipaddress.ip_address(start)}-{ipaddress.ip_address(end)}",
                authority=authority,
                row=row,
            ))

        for authority, row, index in self._exact_ip_index.get(record.ip, ()):
            found.append(self._structured_evidence(
                rule_id=self._rule_id(authority, row, index),
                rule_family="exact_ip_mapping",
                matched_field="ip",
                observed_value=record.ip,
                operator="equals",
                pattern=str(ipaddress.ip_address(str(row["ip"]))),
                authority=authority,
                row=row,
            ))

        seen_domain_rows: set[tuple[str, str, int]] = set()
        for matched_field, observed in (("domain", record.domain), ("root_domain", record.root_domain)):
            if not observed:
                continue
            for suffix in self._domain_suffixes(observed):
                for authority, row, index in self._domain_index.get(suffix, ()):
                    row_key = (authority.source, authority.sha256, index)
                    if row_key in seen_domain_rows:
                        continue
                    seen_domain_rows.add(row_key)
                    found.append(self._structured_evidence(
                        rule_id=self._rule_id(authority, row, index),
                        rule_family="official_domain",
                        matched_field=matched_field,
                        observed_value=observed,
                        operator="suffix",
                        pattern=suffix,
                        authority=authority,
                        row=row,
                    ))

        if record.asn is not None:
            for authority, row, index in self._asn_index.get(record.asn, ()):
                rule_id = self._rule_id(authority, row, index)
                role = str(row["role"]).strip().lower()
                if role == "organization":
                    found.append(self._structured_evidence(
                        rule_id=rule_id,
                        rule_family="organization_asn",
                        matched_field="asn",
                        observed_value=str(record.asn),
                        operator="equals",
                        pattern=str(row["asn"]),
                        authority=authority,
                        row=row,
                    ))
                elif role in {"infrastructure", "network"}:
                    found.append(self._structured_evidence(
                        rule_id=rule_id,
                        rule_family="organization_asn",
                        matched_field="asn",
                        observed_value=str(record.asn),
                        operator="equals",
                        pattern=str(row["asn"]),
                        authority=authority,
                        row=row,
                        target="infrastructure",
                        infrastructure_organization=str(row["organization"]),
                    ))
                else:
                    raise ValueError(f"Invalid ASN role in {rule_id}: {role}")
        return found

    @staticmethod
    def _rule_provenance(rule: dict[str, Any]) -> dict[str, Any]:
        provenance = {"rule_source": rule["source"]}
        for key in (
            "source_path",
            "source_symbol",
            "source_sha256",
            "archive_sha256",
            "source_reference",
            "adaptation",
        ):
            if rule.get(key) is not None:
                provenance[key] = rule[key]
        return provenance

    def _rule_evidence(self, record: NormalizedHunterRecord) -> list[Evidence]:
        found: list[Evidence] = []
        for rule in self.rules:
            value = getattr(record, rule["field"])
            if value is None:
                continue
            observed = str(value)
            if not self._match(rule["operator"], rule["pattern"], observed, self._compiled.get(rule["rule_id"])):
                continue
            target = rule["target"]
            organization = rule.get("organization") if target == "organization_identity" else None
            infrastructure = rule.get("organization") if target == "infrastructure" else None
            found.append(Evidence(
                rule_id=rule["rule_id"],
                rule_family=RULE_FAMILY_BY_FIELD[rule["field"]],
                target=target,
                matched_field=rule["field"],
                observed_value=observed,
                operator=rule["operator"],
                pattern=rule["pattern"],
                source=rule["source"],
                authority=rule.get("authority", "repository_rule_catalog"),
                resolved_organization_id=rule.get("organization_id"),
                resolved_organization=organization,
                resolved_category=rule.get("resolved_category"),
                infrastructure_organization=infrastructure,
                notes=rule["notes"],
                provenance=self._rule_provenance(rule),
            ))
        return found

    def attribute(self, record: NormalizedHunterRecord) -> AttributionResult:
        evidence = self._authority_evidence(record) + self._rule_evidence(record)
        ordered = tuple(sorted(evidence, key=lambda e: (e.rule_id, e.rule_family, e.matched_field, e.observed_value)))
        return AttributionResult("1.2.0", record, ordered, resolve(ordered, record))
