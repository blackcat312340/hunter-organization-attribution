# Rule Semantics

`docs/METHOD.md` is the normative method authority. This file specifies executable rule behavior. LENS-specific provenance and counts are frozen separately in `docs/LENS_RULE_MIGRATION.md`.

## Rule record

Every YAML rule contains:

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

Rules marked `executable: false` remain in the inventory for provenance/review but never execute.

## Operators

- `regex`: case-insensitive regular-expression search within exactly one normalized field.
- `equals`: case-insensitive exact textual equality.
- `suffix`: label-boundary-aware domain suffix match; `example.edu` matches itself and `lab.example.edu`, but not `notexample.edu`.
- Structured authorities additionally emit `contains` for IPv4 ranges and `equals`/`suffix` for their corresponding match semantics.

## Field locality

Executable regex rules may target only reviewed normalized fields:

- `asn_organization`
- `root_domain`
- `domain`
- `host`
- `web_title`

The engine does not concatenate fields. This preserves which observation triggered a rule and prevents an unsupported source field from being reconstructed implicitly.

## Identity rules

A rule with `target: organization_identity` may emit a concrete organization only when the rule itself explicitly names that organization and has reviewed provenance. Generic category text must not be converted into identity.

Structured authority families that may emit identity are:

- `direct_range`
- `exact_ip_mapping`
- `official_domain`
- `organization_asn` only for authority rows with role `organization`

## Category rules

A rule with `target: organization_category` emits only a category. Category evidence never creates an organization name or organization ID. Multiple categories may coexist and are retained deterministically.

## Infrastructure rules

A rule with `target: infrastructure` emits network/hosting context. It cannot become the hosted organization identity. Cloud/CDN/ISP and education-network patterns therefore remain orthogonal to organization identity.

## Evidence preservation

Every hit emits the full evidence contract:

`rule_id`, `rule_family`, `target`, `matched_field`, `observed_value`, `operator`, `pattern`, `source`, `authority`, optional resolved identity/category/infrastructure values, notes, and provenance.

No rule is discarded merely because another rule is more specific. Conflicting identity evidence is surfaced by resolution rather than overwritten.

## Determinism

Rules are sorted by stable `rule_id`; evidence is sorted by stable semantic keys. Repeated runs over the same normalized record, rule version, and authority digests must produce byte-equivalent JSON output.
