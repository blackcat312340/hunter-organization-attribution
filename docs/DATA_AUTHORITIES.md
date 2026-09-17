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

## Operational hygiene

Authority files should be mounted read-only where practical. Record publisher/source, version, retrieval time, license/usage constraints, and transformation history in `AuthoritySpec.provenance`. Real authority data, Hunter snapshots, Measurement 212 exports, and real IP lists are prohibited from this repository.
