# Input and Output Schemas

## NormalizedHunterRecord 1.2.0

`NormalizedHunterRecord` is the exclusive runtime input contract. It is populated only from Hunter observations or reviewed Hunter enrichment; FOFA/LENS objects are not accepted runtime records.

| field | type | required | semantics |
|---|---|---:|---|
| `ip` | IPv4 string | yes | canonical observed address |
| `port` | integer/null | no | observed TCP/UDP service port, 1..65535 |
| `asn` | positive integer/null | no | observed/enriched ASN |
| `asn_organization` | string/null | no | ASN registration text; network/infrastructure context by default |
| `root_domain` | string/null | no | reviewed root/registrable domain |
| `domain` | string/null | no | normalized Hunter domain/hostname |
| `host` | string/null | no | Hunter host/URL observation |
| `web_title` | string/null | no | reviewed Hunter web title |
| `hunter_reported_country` | string/null | no | Hunter-reported country/region value |
| `infrastructure_category` | string/null | no | reviewed infrastructure enrichment |
| `provider_family` | string/null | no | reviewed provider-family enrichment |
| `hunter_record_id` | string/null | no | source record correlation identifier |
| `observed_at` | string/null | no | preserved observation timestamp |

Explicit aliases are limited to `title -> web_title`, `asn_org -> asn_organization`, and `country -> hunter_reported_country`. Unknown fields are ignored by default for adapter compatibility and rejected when `strict=True`; ignored fields are never available to rules. Conflicting canonical/alias values fail closed in strict mode.

## Evidence row 1.2.0

Every rule hit is retained as a separate evidence record. Mandatory semantic fields are:

- `rule_id`
- `rule_family`
- `target`: `organization_identity`, `organization_category`, or `infrastructure`
- `matched_field`
- `observed_value`
- `operator`
- `pattern`
- `source`
- `authority`
- `resolved_organization_id` (nullable)
- `resolved_organization` (nullable)
- `resolved_category` (nullable; interpreted according to `target`)
- `infrastructure_organization` (nullable)
- `notes` (nullable)
- `provenance`

For LENS-derived rules, `provenance` includes source-file/symbol and archive/file SHA-256 metadata. This table is the explanation surface for “why was this IP associated with this organization/category/network?”. Evidence is never deleted merely because another rule has higher specificity.

## AttributionResult 1.2.0

- `schema_version`: `1.2.0`
- `record`: normalized Hunter input
- `evidence[]`: complete, deterministically sorted evidence rows
- `resolution`:
  - `organization_id`: agreed organization identifier or null
  - `organization_name`: agreed organization display name or null
  - `categories[]`: organization categories only; infrastructure rule categories are excluded
  - `association_types[]`: all evidence families plus `multi_rule` only for multiple agreeing identity hits
  - `infrastructure_organizations[]`: named network/hosting organizations retained separately from identity
  - `infrastructure_categories[]`: union of infrastructure-rule categories and reviewed input `infrastructure_category`
  - `infrastructure_category`: reviewed input enrichment or null; retained for compatibility and source fidelity
  - `provider_family`: reviewed input enrichment or null
  - `ambiguity_status`: `no_identity`, `unambiguous`, or `ambiguous_conflict`
  - `agreement_status`: `not_applicable`, `single_identity_evidence`, `multi_rule_agreement`, or `conflict`
  - `status`: `resolved`, `category_only`, `unresolved`, or `conflict`
  - `conflicting_organizations[]`: explicit sorted conflict set

Infrastructure-only evidence does not produce `category_only`; it produces `unresolved` plus explicit infrastructure context.

`organization_id` and `organization_name` describe the single reconciled identity. Reconciliation follows `docs/METHOD.md` section 10.1: evidence agreeing on a non-null identifier, or on a canonical name where at most one side carries an identifier, forms one identity; two distinct non-null identifiers always conflict. When identity evidence agrees but names differ, the cluster keeps one deterministic primary name while every individual name remains visible on its own evidence row.

Compatibility properties `resolution.organization`, `resolution.evidence_types`, `evidence.rule_type`, and `evidence.matched_pattern` remain available for initial Phase 1 callers, but serialized output uses the explicit 1.2.0 fields above.
