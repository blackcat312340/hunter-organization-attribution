from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Iterable

from .models import AttributionResult, Evidence, NormalizedHunterRecord
from .provenance import LoadedAuthority
from .resolution import resolve
from .rules.loader import load_rules


RULE_TYPE_BY_FIELD = {
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

    def _authority_evidence(self, record: NormalizedHunterRecord) -> list[Evidence]:
        found: list[Evidence] = []
        address = ipaddress.ip_address(record.ip)
        for authority in self.authorities:
            provenance = {**authority.audit, "authority_sha256": authority.sha256}
            for index, row in enumerate(authority.rows, start=1):
                rule_id = str(row.get("rule_id") or f"{authority.source}:{authority.authority_type}:{index}")
                category = row.get("category") or None
                if authority.authority_type == "ipv4_ranges":
                    start, end = ipaddress.ip_address(row["start_ip"]), ipaddress.ip_address(row["end_ip"])
                    if start <= address <= end:
                        found.append(Evidence(rule_id, "direct_range", "ip", record.ip, f"{start}-{end}", authority.source, str(row["organization"]), category, provenance=provenance))
                elif authority.authority_type == "exact_ip" and record.ip == str(row["ip"]):
                    found.append(Evidence(rule_id, "exact_ip_mapping", "ip", record.ip, str(row["ip"]), authority.source, str(row["organization"]), category, provenance=provenance))
                elif authority.authority_type == "domains":
                    observed = record.root_domain or record.domain
                    expected = str(row["domain"]).lower().lstrip(".")
                    if observed and (observed == expected or observed.endswith("." + expected)):
                        found.append(Evidence(rule_id, "official_domain", "root_domain", observed, expected, authority.source, str(row["organization"]), category, provenance=provenance))
                elif authority.authority_type == "asn" and record.asn == int(str(row["asn"]).upper().removeprefix("AS")):
                    role = str(row["role"]).lower()
                    if role == "organization":
                        found.append(Evidence(rule_id, "organization_asn", "asn", str(record.asn), str(row["asn"]), authority.source, str(row["organization"]), category, provenance=provenance))
                    elif role in {"infrastructure", "network"}:
                        found.append(Evidence(rule_id, "organization_asn", "asn", str(record.asn), str(row["asn"]), authority.source, resolved_category=category, infrastructure_organization=str(row["organization"]), provenance=provenance))
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
                rule_type=RULE_TYPE_BY_FIELD[rule["field"]],
                matched_field=rule["field"],
                observed_value=observed,
                matched_pattern=rule["pattern"],
                authority=rule["source"],
                resolved_organization=organization,
                resolved_category=rule.get("resolved_category"),
                infrastructure_organization=infrastructure,
                provenance={"notes": rule["notes"]},
            ))
        return found

    def attribute(self, record: NormalizedHunterRecord) -> AttributionResult:
        evidence = self._authority_evidence(record) + self._rule_evidence(record)
        ordered = tuple(sorted(evidence, key=lambda e: (e.rule_id, e.rule_type, e.matched_field, e.observed_value)))
        return AttributionResult("1.0.0", record, ordered, resolve(ordered))
