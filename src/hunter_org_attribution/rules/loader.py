from __future__ import annotations

from pathlib import Path
import re
from typing import Any

import yaml


EXECUTABLE_FIELDS = {"asn_organization", "root_domain", "domain", "host", "web_title"}
OPERATORS = {"regex", "equals", "suffix"}
TARGETS = {"organization_identity", "organization_category", "infrastructure"}
LENS_PROVENANCE_FIELDS = {"source_path", "source_symbol", "source_sha256", "archive_sha256"}


def load_rules(paths: list[Path]) -> tuple[dict[str, Any], ...]:
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in payload.get("rules", []):
            rule = dict(raw)
            missing = [key for key in ("rule_id", "target", "field", "operator", "pattern", "source", "notes") if key not in rule]
            if missing:
                raise ValueError(f"{path}: rule missing {missing}")
            if rule["rule_id"] in seen:
                raise ValueError(f"Duplicate rule_id: {rule['rule_id']}")
            seen.add(rule["rule_id"])
            executable = bool(rule.get("executable", True))
            if rule["target"] not in TARGETS:
                raise ValueError(f"Unsupported target in {rule['rule_id']}: {rule['target']}")
            if executable and rule["field"] not in EXECUTABLE_FIELDS:
                raise ValueError(f"Executable rule {rule['rule_id']} uses unsupported field {rule['field']}")
            if executable and rule["operator"] not in OPERATORS:
                raise ValueError(f"Unsupported operator in {rule['rule_id']}")
            if executable and rule["operator"] == "regex":
                try:
                    re.compile(rule["pattern"], re.IGNORECASE)
                except re.error as exc:
                    raise ValueError(f"Invalid regex in {rule['rule_id']}: {exc}") from exc
            if rule["source"] == "LENS-20260602":
                provenance_missing = sorted(LENS_PROVENANCE_FIELDS - set(rule))
                if provenance_missing:
                    raise ValueError(f"{rule['rule_id']} missing LENS provenance: {provenance_missing}")
            rules.append(rule)
    return tuple(sorted(rules, key=lambda item: item["rule_id"]))
