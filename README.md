# Hunter Organization Attribution

Frozen, deterministic organization-attribution method whose only operational input is a normalized Hunter observation. FOFA and LENS are not runtime dependencies; `LENS-20260602` is a source-verified methodology/rule reference only.

Phase 1 freezes the method, schemas, rules, provenance controls, and synthetic tests. It does **not** process Measurement 212 or create paper findings.

The verified LENS archive/source provenance, executable classifier migration, and reference-only sensitive-rule inventory are documented in [`docs/LENS_RULE_MIGRATION.md`](docs/LENS_RULE_MIGRATION.md). The normative method contract is [`docs/METHOD.md`](docs/METHOD.md).

## Quick start

```bash
python -m pip install -e ".[dev]"
pytest
```

```python
from hunter_org_attribution import AttributionEngine, normalize_hunter_record

record = normalize_hunter_record({
    "ip": "192.0.2.10",
    "domain": "lab.example.edu",
    "host": "https://lab.example.edu",
    "web_title": "Example University Lab",
    "asn": 64500,
    "asn_organization": "Amazon.com, Inc.",
})
result = AttributionEngine.from_repository_defaults().attribute(record)
```

External authorities are supplied at runtime with an expected SHA-256 and are never bundled. See [`examples/attribute_record.py`](examples/attribute_record.py).
