from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


EXECUTABLE_FIELDS = {"asn_organization", "root_domain", "domain", "host", "web_title"}
OPERATORS = {"regex", "equals", "suffix"}


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
            if executable and rule["field"] not in EXECUTABLE_FIELDS:
                raise ValueError(f"Executable rule {rule['rule_id']} uses unsupported field {rule['field']}")
            if executable and rule["operator"] not in OPERATORS:
                raise ValueError(f"Unsupported operator in {rule['rule_id']}")
            rules.append(rule)
    return tuple(sorted(rules, key=lambda item: item["rule_id"]))

