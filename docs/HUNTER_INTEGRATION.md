# Hunter Production Integration Contract

This document defines the Phase 2 boundary between the frozen organization-attribution method and the current Measurement 212 Hunter-processing code. It does not redefine the Phase 1 attribution semantics in `docs/METHOD.md` and it does not authorize a full Measurement 212 run.

## Reviewed production source

The integration contract was derived from the production reader already used by the Measurement 212 institutional-IP export:

- repository: `blackcat312340/findings-graph`
- branch: `agent/m212-institution-ip-export-20260916`
- exact commit: `2ba9545f87b55d393e3e155fea75deb165b7b9ac`
- reader: `scripts/build_measurement_212_institution_ip_export.py`
- reader blob: `89a7d1fc1e0cfce4f90b129c53c36476a5ccc7a6`

The ASN context interface was reviewed from:

- script: `scripts/build_measurement_212_asn_v2_lookup.py`
- script blob: `49ae1e784de77a515d0fe75c950e1fe560a78f4b`
- frozen lookup: `artifacts/measurement_212_asn_v2_lookup.csv`
- frozen lookup SHA-256: `1709d5be6478bf5add9566b5b1d843aa1eb5a79d4e9962fd07fc19d093105390`

The lookup summary records 11,488 ASN rows and confirms that it is an aggregate-only `ASN -> category/provider` replay product. These identifiers are frozen in `production_adapter.py`. A future production-source or lookup change must be reviewed before the corresponding contract constants are advanced.

The existing 796-IP institutional export at the same source commit is supporting compatibility evidence, not an input to this repository. Its master table uses numeric `primary_asn` together with `primary_infrastructure_category` and `primary_provider_family`; the reviewed example rows have no ASN organization text. This is consistent with the narrower lookup contract below and does not justify synthesizing `asn_organization`.

A separately archived Hunter/Spark construction script was also reviewed during the Phase 2 compatibility audit. Its fixed stored-output projection contains `is_web`, `city`, `updated_at`, and `banner_info` in addition to fields already consumed by the Measurement 212 reader. That archived script is not a versioned repository authority, so these four names are admitted only as **known ignored compatibility fields**. They are not promoted to attribution inputs and they do not advance any source-pinned authority constant.

## Raw Hunter projection

The reviewed production reader directly accesses these fields that are relevant to organization attribution:

| production field | normalized field | role |
|---|---|---|
| `ip` | `ip` | required observed IPv4 address |
| `port` | `port` | observed service port |
| `asn` | `asn` | observed/enriched numeric ASN |
| `root_domain` | `root_domain` | domain context |
| `domain` | `domain` | domain context |
| `host` | `host` | host/URL context |
| `web_title` | `web_title` | title classification signal |
| `country` | `hunter_reported_country` | Hunter-reported country value; not independent geolocation |

The integration layer uses `project_measurement212_hunter_record()` to copy only these reviewed fields into `NormalizedHunterRecord` and then invokes the strict Phase 1 normalizer.

## Explicit non-attribution fields

Reviewed production or stored-output fields that may be present but must not become organization-attribution evidence are:

- `full_name`
- `http_head`
- `protocol_type`
- `favicon`
- `is_web`
- `city`
- `updated_at`
- `banner_info`

They are recognized by the production projection but never copied into `NormalizedHunterRecord`. In particular:

- `full_name` is a service/repository label in Measurement 212, not organization identity;
- `favicon` and `web_title` may participate in the separate service-fingerprint workflow, but only `web_title` is a reviewed organization-category textual signal in this method;
- `http_head`, `protocol_type`, `is_web`, `city`, and `banner_info` do not become organization evidence;
- upstream `updated_at` is not automatically mapped to `observed_at`: the former is asset metadata, while the latter is explicit observation/snapshot provenance supplied by the caller.

The archived construction script also reads `web_body` for upstream fingerprint matching but explicitly omits it from the fixed stored output. Therefore `web_body` remains outside this production contract and still fails closed if it appears in strict projection input.

The projection result records the names of known fields it consumed and explicitly ignored. It never copies ignored field values into attribution evidence.

## Production schema drift

Reading source code establishes the fields consumed by the reviewed production path; it does not prove that raw Hunter objects contain no additional keys. Therefore the production projection fails closed on any unreviewed key when `strict_contract=True`.

This is intentional. Before a new raw field may be admitted, review its Hunter semantics and decide whether it is:

1. attribution input;
2. known non-attribution context; or
3. unsupported/unneeded.

For an audit-only smoke check, `strict_contract=False` may be used. Unknown field names are returned in `Measurement212Projection.unknown_fields`, but their values are still not exposed to rules.

## ASN enrichment boundary

The reviewed frozen Measurement 212 ASN lookup contains exactly:

- `asn`
- `asn_category`
- `provider_family`
- `is_cloud_provider`
- `is_cloud_or_hosting_infra`
- `classification_confidence`
- `classification_rule`

It is an aggregate network/infrastructure classification. It does **not** contain ASN registration organization text and therefore does not populate `asn_organization`.

The production adapter maps only:

- `asn_category -> infrastructure_category`
- `provider_family -> provider_family`

and checks that the lookup ASN agrees with the Hunter-record ASN. The remaining lookup fields are accepted as reviewed audit context but do not become attribution-rule inputs.

Consequently, LENS-derived rules whose declared field is `asn_organization` are not executable for a record merely because the Measurement 212 ASN lookup is available. They require a separate reviewed source that actually supplies ASN organization registration text.

## ROR authority status and temporal boundary

The composed ROR direct-identity authority is the frozen `v2.12-2026-08-25` dump (retrieved `2026-09-18`). Integration applies it conservatively to historical Hunter observations (`2025-01-01` through `2026-04-30`):

- **ROR `active`**: eligible direct identity.
- **ROR `inactive`**: excluded from current direct identity. Lacking a reliable per-record status-effective timestamp, the record is **not** assumed to have been active at observation time.
- **ROR `withdrawn`**: excluded from direct identity; ROR defines withdrawn records as erroneous/duplicate/out-of-scope.
- **`successor` relationship**: never automatically substituted. A predecessor record's domain is not redirected to the successor organization.
- The `2026-08` authority snapshot is **not** observation-time ground truth for `2025-01`–`2026-04` Hunter records; the exclusion is a conservative false-negative tradeoff.

This boundary does not change the production projection contract or the serialized attribution schema (still `1.2.0`); the ROR status gate lives entirely in the ROR source adapter.

## Read-only small-sample validation

`examples/validate_hunter_snapshot_contract.py` validates a local Hunter JSONL snapshot without writing measurement outputs. It:

- reads at most the requested number of records;
- optionally joins a local ASN lookup CSV by ASN;
- projects each record through the production adapter;
- runs the default attribution engine as an interface smoke test;
- emits aggregate counts only: projection status, resolution-status counts, consumed/ignored/unknown field-name frequencies, and error-class counts;
- never prints IPs, hostnames, titles, service labels, or other raw record values.

Use `--allow-unreviewed` only to inventory schema drift. Strict mode is the gate for a reviewed production contract.

## Phase boundary

Phase 2 integration work may validate a small local sample against the projection contract. It must not, by itself:

- run all 13,616,115 Measurement 212 records;
- copy Hunter snapshots or Measurement exports into this repository;
- modify `findings-graph`;
- create or promote a paper finding.

A full run is a separate execution gate after the production interface and external authority configuration have been reviewed on a small real sample.
