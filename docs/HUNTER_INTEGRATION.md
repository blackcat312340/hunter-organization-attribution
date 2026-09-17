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

The same production reader also uses fields for service identification, fingerprint replay, or transport metadata:

- `full_name`
- `http_head`
- `protocol_type`
- `favicon`

They are deliberately recognized as production fields but are never projected into `NormalizedHunterRecord`. In particular:

- `full_name` is a service/repository label in Measurement 212, not organization identity;
- `favicon` and `web_title` may participate in the separate service-fingerprint workflow, but only `web_title` is a reviewed organization-category textual signal in this method;
- `http_head` and `protocol_type` do not become organization evidence.

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
