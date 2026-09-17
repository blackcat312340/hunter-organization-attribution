# Phase 2 Production Interface Review

## Scope

Phase 2 validates the boundary between the frozen Phase 1 attribution method and the current Measurement 212 Hunter reader. It does not run the full measurement corpus and does not modify `findings-graph`.

## Frozen upstream interface evidence

- `blackcat312340/findings-graph`
- branch `agent/m212-institution-ip-export-20260916`
- commit `2ba9545f87b55d393e3e155fea75deb165b7b9ac`
- production reader blob `89a7d1fc1e0cfce4f90b129c53c36476a5ccc7a6`
- ASN lookup builder blob `49ae1e784de77a515d0fe75c950e1fe560a78f4b`
- frozen ASN lookup SHA-256 `1709d5be6478bf5add9566b5b1d843aa1eb5a79d4e9962fd07fc19d093105390`

Additional compatibility review found an archived Hunter/Spark construction path whose fixed stored-output projection can include `is_web`, `city`, `updated_at`, and `banner_info`. Because that archived script is not a source-pinned repository authority, those fields are admitted only as known ignored compatibility metadata. `web_body` is matching-only in that construction path and remains outside the strict stored-output contract.

## Review gates

1. Raw production fields are explicitly projected rather than permissively passed to the generic adapter. **PASS**
2. Organization-attribution inputs remain limited to the reviewed projection fields. **PASS**
3. `full_name`, `http_head`, `protocol_type`, `favicon`, `is_web`, `city`, `updated_at`, and `banner_info` are explicitly non-attribution fields. **PASS**
4. Upstream `updated_at` does not silently become observation provenance; only explicit caller-supplied `observed_at` may populate that field. **PASS**
5. `web_body` remains outside the stored-output contract and fails closed in strict mode. **PASS**
6. Unknown raw production fields fail closed in strict mode and are schema-auditable without exposing their values. **PASS**
7. Current ASN lookup maps only `asn_category` and `provider_family` into infrastructure context. **PASS**
8. Current ASN lookup does not fabricate `asn_organization`. **PASS**
9. ASN enrichment requires a matching ASN key on both the Hunter record and lookup row. **PASS**
10. Small-sample validator emits aggregate field/status counts only and never raw asset values. **PASS by synthetic regression test**
11. No real snapshot/export is committed, including in Git history. **PASS**
12. Full Measurement 212 execution remains gated. **PASS**

## Merged implementation history

### PR #2 — reviewed Hunter production interface

- final PR head: `256cb60def2ba35ba49b90b3a84dced8bcaece95`
- merge commit: `7c7064299b95dc0b5027827974b9475a7349a5cf`
- package version introduced: `1.3.0`
- CI before merge: 49 tests passed; data hygiene passed

### PR #3 — stored-output metadata contract fix

- final PR head: `17c4709d4944c1f3263fa9709dfa2f07bc4cad67`
- merge commit / reviewed Phase 2 implementation baseline: `2befcd5d0380bcffa36ca932903203a7bb79d632`
- package version: `1.3.1`
- CI before merge: 51 tests passed; data hygiene passed
- post-merge CI on `main @ 2befcd5d0380bcffa36ca932903203a7bb79d632`: 51 tests passed; data hygiene passed

The serialized attribution-result schema remains `1.2.0`; Phase 2 changed the production integration API/contract, not evidence or resolution semantics.

## Remaining execution gate

A real small-sample smoke against the actual local Measurement 212 Hunter snapshots is still required before authorizing the full 13,616,115-record B-universe run.

The production measurement code resolves the raw snapshot root to `D:/selfhost_zip`, but those local snapshot bytes are not present in this repository and were not available to the review environment. Repository artifacts and the 796-IP institutional export are derived evidence and must not be substituted for raw Hunter records.

Therefore the current state is:

- method/schema/rules: **frozen**
- production projection contract: **reviewed and merged**
- synthetic/interface regression suite: **PASS (51 tests)**
- repository data hygiene: **PASS**
- actual raw Hunter small-sample smoke: **PENDING — external local-data access gate**
- full Measurement 212 organization-attribution run: **NOT AUTHORIZED YET**
- `findings-graph` modification: **NOT PERFORMED**
- paper finding creation: **NOT PERFORMED**

The real small-sample gate must use `examples/validate_hunter_snapshot_contract.py` (or an equivalent read-only invocation of the same production projection), record only aggregate contract/status output, and resolve any unknown-field drift before the full run is allowed.
