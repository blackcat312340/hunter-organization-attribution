# Phase 2 Production Interface Review

## Scope

Phase 2 validates the boundary between the frozen Phase 1 attribution method and the current Measurement 212 Hunter reader. It does not run the full measurement corpus and does not modify `findings-graph`.

## Frozen upstream interface evidence

- `blackcat312340/findings-graph`
- branch `agent/m212-institution-ip-export-20260916`
- commit `2ba9545f87b55d393e3e155fea75deb165b7b9ac`
- production reader blob `89a7d1fc1e0cfce4f90b129c53c36476a5ccc7a6`
- ASN lookup builder blob `49ae1e784de77a515d0fe75c950e1fe560a78f4b`

## Review gates

1. Raw production fields are explicitly projected rather than permissively passed to the generic adapter.
2. `full_name`, `http_head`, `protocol_type`, and `favicon` are explicitly non-attribution fields.
3. Unknown raw production fields fail closed in strict mode and are schema-auditable without exposing their values.
4. Current ASN lookup maps only `asn_category` and `provider_family` into infrastructure context.
5. Current ASN lookup does not fabricate `asn_organization`.
6. ASN enrichment requires a matching ASN key on both the Hunter record and lookup row.
7. Small-sample validation emits aggregate field/status counts only and never raw asset values.
8. No real snapshot/export is committed.
9. Full Measurement 212 execution remains out of scope.

## Validation status

The repository CI remains the executable gate. Final review must record the exact Phase 2 head and passing test count before merge.
