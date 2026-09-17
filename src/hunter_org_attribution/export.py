from __future__ import annotations

import json

from .models import AttributionResult


def to_json(result: AttributionResult, *, indent: int | None = 2) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, indent=indent)

