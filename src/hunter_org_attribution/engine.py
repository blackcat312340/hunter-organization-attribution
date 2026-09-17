from __future__ import annotations

import ipaddress
import re
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

    @classmethod
    def from_repository_defaults(cls, authorities: Iterable[LoadedAuthority] = ()) -> "AttributionEngine":
        root = Path(__file__).resolve().parents[2]
        rule_root = root / "rules"
        paths = [rule_root / name for name in ("categories.yaml", "organization_patterns.yaml", "domain_patterns.yaml")]
        return cls(load_rules(paths), authorities)

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

    def _authority_evidence(self, record: NormalizedHunterRecord) -> list[Evidence]:
        found: list[Evidence] = []
        address = ipaddress.ip_address(record.ip)
        for authority in self.authorities:
            for index, row in enumerate(authority.rows, start=1):
                rule_id = str(row.get("rule_id") or f"{authority.source}:{authority.authority_type}:{index}")
                if authority.authority_type == "ipv4_ranges":
                    start, end = ipaddress.ip_address(row["start_ip"]), ipaddress.ip_address(row["end_ip"])
                    if start <= address <= end:
                        found.append(self._structured_evidence(
                            rule_id=rule_id, rule_family="direct_range", matched_field="ip",
                            observed_value=record.ip, operator="contains", pattern=f"{start}-{end}",
                            authority=authority, row=row,
                        ))
                elif authority.authority_type == "exact_ip" and record.ip == str(row["ip"]):
                    found.append(self._structured_evidence(
                        rule_id=rule_id, rule_family="exact_ip_mapping", matched_field="ip",
                        observed_value=record.ip, operator="equals", pattern=str(row["ip"]),
                        authority=authority, row=row,
                    ))
                elif authority.authority_type == "domains":
                    observed = record.root_domain or record.domain
                    expected = str(row["domain"]).lower().lstrip(".")
                    if observed and (observed == expected or observed.endswith("." + expected)):
                        found.append(self._structured_evidence(
                            rule_id=rule_id, rule_family="official_domain", matched_field="root_domain",
                            observed_value=observed, operator="suffix", pattern=expected,
                            authority=authority, row=row,
                        ))
                elif authority.authority_type == "asn" and record.asn == int(str(row["asn"]).upper().removeprefix("AS")):
                    role = str(row["role"]).lower()
                    if role == "organization":
                        found.append(self._structured_evidence(
                            rule_id=rule_id, rule_family="organization_asn", matched_field="asn",
                            observed_value=str(record.asn), operator="equals", pattern=str(row["asn"]),
                            authority=authority, row=row,
                        ))
                    elif role in {"infrastructure", "network"}:
                        found.append(self._structured_evidence(
                            rule_id=rule_id, rule_family="organization_asn", matched_field="asn",
                            observed_value=str(record.asn), operator="equals", pattern=str(row["asn"]),
                            authority=authority, row=row, target="infrastructure",
                            infrastructure_organization=str(row["organization"]),
                        ))
                    else:
                        raise ValueError(f"Invalid ASN role in {rule_id}: {role}")
        return found

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
                provenance={"rule_source": rule["source"]},
            ))
        return found

    def attribute(self, record: NormalizedHunterRecord) -> AttributionResult:
        evidence = self._authority_evidence(record) + self._rule_evidence(record)
        ordered = tuple(sorted(evidence, key=lambda e: (e.rule_id, e.rule_family, e.matched_field, e.observed_value)))
        return AttributionResult("1.1.0", record, ordered, resolve(ordered, record))
