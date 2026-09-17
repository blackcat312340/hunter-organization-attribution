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

Loaders verify:

- expected SHA-256;
- supported authority type;
- required fields;
- optional expected row count;
- IPv4/range validity;
- ASN syntax/range and role semantics;
- basic domain syntax;
- provenance/audit metadata.

The audit record also includes a normalization report. Phase 1 validates but does not silently rewrite authority values.

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

- filename: `LENS-20260602.zip`
- recorded SHA-256: `0e76e38b27859339f952ae34d49302c8fdd358458a4d5c3b29fbfccc1221f10c`
- use: methodology/rule migration reference only
- migration review date: `2026-09-17`
- runtime role: none
- repository status: excluded by `*.zip`
- migrated runtime fields: `org -> asn_organization` (semantic narrowing), `domain -> domain/root_domain`, `hosts -> host`, `titles -> web_title`
- unsupported runtime fields: `body`, `server`, `app`
- migration inventory: `docs/LENS_RULE_MIGRATION.md`
- known source-verification gap: preserved task notes identify an `SOE` category family whose exact source rule is not available in the current review environment

The archive bytes were not available in this review environment for an independent re-hash. The recorded digest therefore remains inherited provenance rather than a newly verified digest. If the archive is reintroduced, its digest must be verified before source-complete migration is claimed, and the original classifier must be compared rule by rule with the repository inventory. No missing executable rule should be reconstructed from a category name or summary alone.

## Exact-IP/domain association authorities

Historical packages may contain exact-IP or domain-derived organization associations. Such data may be loaded through `exact_ip` or `domains` authority interfaces after independent provenance and SHA review. A domain-derived exact-IP association must not be reinterpreted as a CIDR/institutional-range authority.

## Operational hygiene

Authority files should be mounted read-only where practical. Record publisher/source, version, retrieval time, license/usage constraints, and transformation history in `AuthoritySpec.provenance`. Real authority data, Hunter snapshots, Measurement 212 exports, and real IP lists are prohibited from this repository.
