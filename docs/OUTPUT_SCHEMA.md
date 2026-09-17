# Input and Output Schemas

## NormalizedHunterRecord 1.0.0

| field | type | required | semantics |
|---|---|---:|---|
| `ip` | IPv4 string | yes | canonical observed address |
| `root_domain` | string/null | no | reviewed root/registrable domain |
| `domain` | string/null | no | normalized Hunter domain/hostname |
| `host` | string/null | no | Hunter host/URL observation |
| `web_title` | string/null | no | reviewed Hunter web title |
| `asn` | positive integer/null | no | observed/enriched ASN |
| `asn_organization` | string/null | no | ASN registration text; context by default |
| `hunter_record_id` | string/null | no | source record correlation identifier |
| `observed_at` | string/null | no | preserved observation timestamp |

Unknown fields are ignored by default for adapter compatibility and rejected
when `strict=True`. In either mode they are never available to rules. The
adapter accepts only explicit aliases `title -> web_title` and
`asn_org -> asn_organization`.

## AttributionResult

- `schema_version`: `1.0.0`
- `record`: normalized input
- `evidence[]`: complete, deterministically sorted matches
- `resolution`:
  - `organization`: one agreed identity or null
  - `categories[]`: all categories
  - `infrastructure_organizations[]`: all network/hosting contexts
  - `status`: `resolved`, `category_only`, `unresolved`, or `conflict`
  - `evidence_types[]`: typed evidence plus `multi_rule` where applicable
  - `conflicting_organizations[]`: explicit sorted conflict set

Each evidence item includes all mandatory preservation fields and provenance.
JSON export uses sorted keys and stable evidence ordering.

