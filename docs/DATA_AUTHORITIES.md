# External Data Authorities

No external measurement or authority data are committed. Runtime users provide
local files to `load_authority(AuthoritySpec(...))`.

## Supported schemas

| type | required columns | identity semantics |
|---|---|---|
| `ipv4_ranges` | `start_ip`, `end_ip`, `organization` | direct identity |
| `exact_ip` | `ip`, `organization` | direct identity |
| `domains` | `domain`, `organization` | official-domain identity |
| `asn` | `asn`, `organization`, `role` | identity only when role is `organization`; otherwise infrastructure/network context |

Optional columns include `rule_id` and `category`. CSV, JSON, and YAML are
accepted. JSON/YAML may be a row list or an object with a `rows` list. Loaders
verify the file SHA-256 before parsing, validate required fields row by row,
optionally enforce an expected row count, and return an audit/provenance record.

## Known authority metadata (data not included)

China education/research IPv4 range authority:

- SHA-256: `5ebc091a0a76ad3f11039e169d8456a19db930f52977cf004ad7bd96a9c4dd68`
- rows: `4968`
- institutions: `3086`
- local file: intentionally unspecified and uncommitted

LENS methodology archive:

- name: `LENS-20260602.zip`
- SHA-256: `0e76e38b27859339f952ae34d49302c8fdd358458a4d5c3b29fbfccc1221f10c`
- runtime role: none
- repository status: excluded by `*.zip`

Authority files should be mounted read-only. Record their publisher, version,
retrieval time, license, and transformation history in `provenance`.

