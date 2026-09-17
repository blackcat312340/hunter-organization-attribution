# Hunter Organization Attribution

Frozen, deterministic organization-attribution method whose only operational input is a normalized Hunter observation. FOFA and LENS are not runtime dependencies; `LENS-20260602` is a source-verified methodology/rule reference only.

Phase 1 freezes the method, schemas, rules, provenance controls, and synthetic tests. Phase 2 adds a reviewed production projection layer for the current Measurement 212 Hunter reader without changing the frozen attribution semantics. Neither phase, by itself, runs the full Measurement 212 corpus or creates paper findings.

The normative method contract is [`docs/METHOD.md`](docs/METHOD.md). Verified LENS provenance and rule migration are documented in [`docs/LENS_RULE_MIGRATION.md`](docs/LENS_RULE_MIGRATION.md). The production Hunter interface and small-sample gate are documented in [`docs/HUNTER_INTEGRATION.md`](docs/HUNTER_INTEGRATION.md).

Package version `1.3.0` adds the production-integration API; the serialized attribution-result schema remains `1.2.0` because its evidence/resolution contract is unchanged.

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

For the reviewed Measurement 212 production boundary, use `project_measurement212_hunter_record()` rather than passing complete raw Hunter objects directly to the generic normalizer. The projection explicitly audits consumed, ignored, and unreviewed production fields.

A local read-only smoke check is available as:

```bash
python examples/validate_hunter_snapshot_contract.py /path/to/one-snapshot.json --limit 100
```

Add `--asn-lookup /path/to/measurement_212_asn_v2_lookup.csv` to test the reviewed ASN category/provider join. The validator emits aggregate schema/status counts only and does not print raw asset values.

External authorities are supplied at runtime with an expected SHA-256 and are never bundled. See [`examples/attribute_record.py`](examples/attribute_record.py).
