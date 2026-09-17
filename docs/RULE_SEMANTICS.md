# Rule Semantics

`docs/METHOD.md` is the normative method authority. This file specifies executable rule behavior. LENS-specific provenance and source-parity details are frozen separately in `docs/LENS_RULE_MIGRATION.md`.

## Rule record

Every executable YAML rule contains:

- `rule_id`
- `target`: `organization_identity`, `organization_category`, or `infrastructure`
- `field`
- `operator`
- `pattern`
- `source`
- `notes`
- optional `resolved_category`
- optional `organization` / `organization_id`
- optional `authority`
- optional `executable` (default true)

Source-verified LENS rules additionally carry `source_path`, `source_symbol`, `source_sha256`, and `archive_sha256`. Adapted rules may also carry `source_reference` and `adaptation`.

Reference-only source inventories, such as `rules/sensitive_reference.yaml`, are not loaded by the default attribution engine.

## Operators

- `regex`: case-insensitive regular-expression search within exactly one normalized field.
- `equals`: case-insensitive exact textual equality.
- `suffix`: label-boundary-aware domain suffix match; `example.edu` matches itself and `lab.example.edu`, but not `notexample.edu`.
- Structured authorities additionally emit `contains` for IPv4 ranges and `equals`/`suffix` for their corresponding match semantics.

Rule loading validates target, executable field, operator, regex syntax, duplicate IDs, and mandatory source provenance for `source: LENS-20260602` rules.

## Field locality

Executable regex rules may target only reviewed normalized fields:

- `asn_organization`
- `root_domain`
- `domain`
- `host`
- `web_title`

The engine does not concatenate fields. When a source rule originally used a combined field string, migration splits it into field-local rules and records the adaptation explicitly.

## Identity rules

A rule with `target: organization_identity` may emit a concrete organization only when the rule itself explicitly names that organization and has reviewed provenance. Generic category text must not be converted into identity.

Structured authority families that may emit identity are `direct_range`, `exact_ip_mapping`, `official_domain`, and `organization_asn` only for authority rows with role `organization`.

## Organization-category rules

A rule with `target: organization_category` emits only an organization category. Category evidence never creates an organization name or organization ID. Multiple categories may coexist and are retained deterministically.

The source LENS first-match category precedence is intentionally not used by this method; all independent rule hits remain evidence.

## Infrastructure rules

A rule with `target: infrastructure` emits network/hosting context. It cannot become the hosted organization identity. Cloud/CDN/ISP and education-network patterns therefore remain orthogonal to organization identity.

If an infrastructure rule emits `resolved_category`, that value belongs to `resolution.infrastructure_categories`, not `resolution.categories`. Generic infrastructure signals may omit an `organization` entirely rather than fabricate names such as “generic cloud provider”. Named provider/network context requires a separately reviewed rule or authority.

## Reference-only source rules

Some source logic is preserved for provenance without execution. In Phase 1, the verified LENS `detect_sensitive` rule family is reference-only because its output target differs from general organization attribution and its result depends on cross-field guard logic. Preserving a source expression does not imply it should execute under a different semantic target.

## Evidence preservation

Every hit emits the full evidence contract:

`rule_id`, `rule_family`, `target`, `matched_field`, `observed_value`, `operator`, `pattern`, `source`, `authority`, optional resolved identity/category/infrastructure values, notes, and provenance.

No rule is discarded merely because another rule is more specific. Conflicting identity evidence is surfaced by resolution rather than overwritten.

`multi_rule` is added only for multiple agreeing identity-bearing hits, never merely because several category or infrastructure rules matched.

## Determinism

Rules are sorted by stable `rule_id`; evidence is sorted by stable semantic keys. Repeated runs over the same normalized record, rule version, and authority digests must produce byte-equivalent JSON output.
