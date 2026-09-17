# External Data Authorities

No external measurement or authority data are committed. Runtime users provide local files to `load_authority(AuthoritySpec(...))`; every load is hash-pinned and fails closed on validation errors.

## Supported authority schemas

| type | required columns | identity semantics |
|---|---|---|
| `ipv4_ranges` | `start_ip`, `end_ip`, `organization` | direct organization identity association |
| `exact_ip` | `ip`, `organization` | exact-IP identity association |
| `domains` | `domain`, `organization` | official-domain identity association |
| `asn` | `asn`, `organization`, `role` | identity only when `role=organization`; `network`/`infrastructure` stay contextual |

Optional columns include `rule_id`, `organization_id`, `category`, and `notes`. CSV, JSON, and YAML are accepted. JSON/YAML may be a row list or an object with a `rows` list.

Loaders verify expected SHA-256, supported authority type, required fields, optional expected row count, IPv4/range validity, ASN syntax/range and role semantics, basic domain syntax, and provenance/audit metadata. The audit record includes a normalization report. Phase 1 validates but does not silently rewrite authority values.

## China education/research IPv4 range authority

The real CSV is private runtime input and is not committed.

- source file name used in the measurement environment: `edu-ipv4-utf8(1).csv`
- SHA-256: `5ebc091a0a76ad3f11039e169d8456a19db930f52977cf004ad7bd96a9c4dd68`
- source rows: `4,968`
- institutions: `3,086`
- exact CIDR decompositions: `5,306`
- listed IPv4 addresses: `12,769,746`
- previously validated invalid ranges: `0`
- previously validated duplicate rows: `0`
- previously validated overlap pairs: `0`

Only this metadata belongs in Git. The actual CSV must remain external.

## LENS methodology archive

The Phase 1 source-completeness gate was closed on `2026-09-17` using the re-supplied original archive.

- filename: `LENS-20260602.zip`
- independently verified SHA-256: `0e76e38b27859339f952ae34d49302c8fdd358458a4d5c3b29fbfccc1221f10c`
- embedded Git remote: `https://github.com/Cristliu/LENS`
- embedded `main` commit: `19a155697284c58d895b47a1506472a23b338594`
- reviewed source file: `utils/cn_org_ip_stats.py`
- reviewed source-file SHA-256: `b4faa14c6a6fe0b0ef6e62c6e3d339d547a5f1cf6348788a85224856426f7e29`
- use: methodology/rule migration reference only
- runtime role: none
- repository status: excluded by `*.zip`
- migration inventory: `docs/LENS_RULE_MIGRATION.md`

The verified source confirms the general classifier families `EDU_RESEARCH_PAT`, `GOV_PAT`, `FINANCE_PAT`, `HEALTH_PAT`, `SOE_PAT`, `CLOUD_PAT`, and `ISP_PAT`. It also confirms a separate ten-rule `SENSITIVE_RULES` classifier plus two guard regexes; those are preserved as reference-only because their target and cross-field guard semantics differ from general organization attribution.

LENS field mapping is documented in `rules/field_mapping.yaml`. FOFA/LENS observations and outputs are not accepted as runtime attribution truth.

## Exact-IP/domain association authorities

Historical packages may contain exact-IP or domain-derived organization associations. Such data may be loaded through `exact_ip` or `domains` authority interfaces after independent provenance and SHA review. A domain-derived exact-IP association must not be reinterpreted as a CIDR/institutional-range authority.

## Reviewed source adapters

External exports whose column names do not match the canonical authority schema are projected by reviewed, source-specific adapters before validation. The engine and the canonical loader never learn about a particular external file format; an adapter declares the external columns it consumes, the canonical columns it produces, and a stable adapter identifier that is carried into the authority audit and therefore into evidence provenance.

| adapter | external columns | canonical type | produced columns |
|---|---|---|---|
| `reviewed-adapter:china-institution-ipv4-range:v1` | `org,start_ip,end_ip` (headerless) | `ipv4_ranges` | `organization,start_ip,end_ip` |
| `reviewed-adapter:domain-org-association:v1` | `domain,org` | `domains` | `domain,organization` |
| `reviewed-adapter:exact-ip-org-association:v1` | `ip,org` | `exact_ip` | `ip,organization` |

```python
from hunter_org_attribution import (
    load_china_institution_range_authority,
    load_domain_org_authority,
    load_exact_ip_org_authority,
)
```

Adapter behavior is fixed and fail-closed:

- The source file is never modified; the adapter reads it read-only and the SHA is verified before parsing.
- A row whose organization column is blank carries no association: it is dropped and counted as `unmapped_rows_dropped` in the authority audit. It is not treated as an error and never invents a name.
- A well-formed IPv6 address or range row is out of scope for this IPv4-only method: it is dropped and counted separately as `out_of_scope_rows_dropped`, never coerced or truncated into IPv4.
- Exact duplicate projections are deduplicated and counted as `duplicate_rows_removed`.
- Two source rows sharing a key but naming different organizations fail closed, because they cannot be represented as one canonical record and must not resolve by row order.
- Structural faults fail closed: wrong column count, a missing organization column, an unparseable IP address, an inverted range, or an invalid domain.
- `organization_id` is not synthesized. The canonical schema treats it as optional, so rows carry `organization_id = null` and identity reconciliation falls back to canonical-name agreement (see `docs/METHOD.md` section 10.1). No identifier is invented from an organization name.
- No country, category, ownership, or deployment attribute is inferred from an organization name.

Integration scope: the adapters project bytes the caller has already obtained. When an export lives inside an archive, the caller stages the exact member and supplies the archive path, member path, and member SHA-256 through `provenance` so they reach the authority audit and evidence. The China institution range export currently integrated this way is `edu-ipv4-utf8(1).csv` (SHA-256 `5ebc091a…c4dd68`, 4,968 rows); the derived association exports are `results/domain_org.csv` and `results/ip_org.csv` inside `submission_package_2026-08-13.zip`.

Semantics are unchanged by adaptation: a `domains` authority still means "reviewed/derived domain-to-organization association", and an `exact_ip` authority still means "reviewed/derived exact-IP-to-organization association". Neither is an ownership, deployment, or operational-responsibility authority, and the exact-IP authority is never expanded into a subnet, CIDR block, or neighbouring-address range.

## Operational hygiene

Authority files should be mounted read-only where practical. Record publisher/source, version, retrieval time, license/usage constraints, and transformation history in `AuthoritySpec.provenance`. Real authority data, Hunter snapshots, Measurement 212 exports, and real IP lists are prohibited from this repository.
