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
| `reviewed-adapter:gov-domain-registry:v1` | `Domain name,Organization name` | `domains` | `domain,organization` |
| `reviewed-adapter:ror-domain-authority:v1` | schema-v2 `id,domains[],names[]` | `domains` | `domain,organization,organization_id` |
| `reviewed-adapter:asn-organization-text:v1` | CAIDA `org_id\|changed\|org_name\|country\|source` and `aut\|changed\|aut_name\|org_id\|opaque_id\|source` | ASN-organization enrichment (not an evidence authority) | `asn,asn_organization` (+ namespaced network organization handle) |

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

## Global authority stack

Three reviewed global sources may be composed into the runtime. Metadata only is recorded here; no authority content is committed.

### CAIDA AS Organizations (`as2org`) — network-registration text, never identity

- source: `https://data.caida.org/datasets/as-organizations/<YYYYMMDD>.as-org2info.txt.gz`
- documented format: `org_id|changed|org_name|country|source` and `aut|changed|aut_name|org_id|opaque_id|source`
- association: `aut.org_id -> organization.org_id -> org_name`. `aut_name` is a *network* name and is never used as the organization text.
- runtime role: `ASN -> asn_organization` **network-registration text only**
- loader: `load_caida_as2org_authority(...)`; composed through `AttributionEngine(..., asn_organization_authorities=[...])`

CAIDA maps ASes "to the organizational entities that operate them", where the entity is the *resource holder* recorded by the originating RIR. A holder is frequently a transit provider, a hosting company, a downstream customer, or a holding entity, so this is network context, not the hosted-service organization of an observation.

**CAIDA never creates organization identity.** It never sets `organization_id`, never sets `resolved_organization`, and never joins an identity cluster. Its source-local handle is preserved under the `caida-as2org` namespace as `network_organization_id` and must never be compared with, or written to, `organization_id`.

Fail-closed policy: an `aut` row whose `org_id` is absent from the organization section is dropped and counted; a repeated `aut` row for one ASN naming the same organization is deduplicated and counted; a repeated `aut` row for one ASN naming *different* organizations excludes that key (`CAIDA_ASN_MAPPING_CONFLICT` at key granularity) and is counted, so one inconsistent ASN cannot poison the source. A blank `org_name` carries no registration text and is dropped and counted.

### CISA dotgov-data — direct domain identity authority

- source: `https://github.com/cisagov/dotgov-data` (`current-full.csv`)
- licence: CC0 1.0; updated daily
- scope: United States government only; registrable `.gov` domain -> government organization
- loader: `load_cisa_dotgov_authority(...)`

The registrar publishes **no stable organization identifier**, only a free-text organization name, so `organization_id` stays null and no internal "official ID" is invented. The adapter does not derive a government *category* from the `.gov` suffix: identity and category stay separate, and the existing category rules classify the organization name independently.

### ROR schema-v2 domains — direct research-domain identity authority

- source: ROR data dump, schema v2 JSON (`https://ror.readme.io/docs/data-dump`)
- licence: CC0 1.0
- scope: global research organizations, **coverage limited to records that publish `domains`**
- loader: `load_ror_domain_authority(...)`

Only domains the dump itself provides are ingested; no organization name is ever turned into a domain, and no alias is used for fuzzy matching. Identifiers are namespaced as `ror:<canonical-ror-id>` and compared only inside the `ror` namespace. A canonical domain claimed by two distinct ROR identifiers is `AMBIGUOUS`: the key is dropped rather than resolved by record order and counted as `ambiguous_domain_keys_dropped`. Organizations with empty `domains` create nothing.

**Phase 5.1 status policy.** ROR production status is a source-level gate, applied **before** domain canonicalization and ambiguity detection:

- **`status = active`** → eligible for direct domain identity. This is the only eligible status.
- **`status = inactive`** → excluded from current direct identity. The record is counted (`inactive_records`, `inactive_records_with_domains`) and its domain entries are counted and dropped (`inactive_domain_entries_dropped`). It is **not** assumed to have been active at observation time.
- **`status = withdrawn`** → excluded from direct identity. The record is counted (`withdrawn_records`, `withdrawn_records_with_domains`) and its domain entries are counted and dropped (`withdrawn_domain_entries_dropped`). ROR defines withdrawn records as erroneous/duplicate/out-of-scope.
- A blank or unknown status is conservatively not eligible (`other_status_records`).
- **No automatic successor remap.** An `inactive`/`withdrawn` record carrying a `successor` relationship is counted (`inactive_records_with_successor` / `withdrawn_records_with_successor`) but its domain is **never** redirected to the successor organization. A successor relationship is not proof that the predecessor's historical/current domain now belongs to the successor.
- **Ambiguity is computed only among eligible active records.** A domain claimed by one active and one inactive/withdrawn record is **not** ambiguous; the active claim survives. Only a domain claimed by two distinct eligible active identifiers is dropped as ambiguous.
- Every canonical row produced by the adapter carries `ror_status = "active"`, and every ROR identity evidence row confirms it in its `provenance`.
- The adapter audit records the full per-status inventory under `adapter_counts` (see `docs/METHOD.md` section 16.3).

**Temporal limitation.** The authority snapshot is `v2.12-2026-08-25` (retrieved `2026-09-18`). It is a later reviewed snapshot applied conservatively to historical Hunter observations (`2025-01-01` through `2026-04-30`). Because ROR publishes no reliable per-record status-effective timestamp, `inactive` records are excluded rather than assumed to have been active at observation time. This is a conservative false-negative tradeoff and is **not** a time-aligned ground-truth claim. `withdrawn` records are excluded because ROR defines them as erroneous/duplicate/out-of-scope.

**Phase 5.2 public-suffix domain quality gate.** Direct identity is further gated by the Public Suffix List (PSL), applied in the frozen order: parse record → status filter (`active` only) → canonicalize source domains → PSL quality gate → drop invalid/public-suffix domains → deduplicate → detect ambiguity among remaining eligible mappings → build the authority. For each canonical source-provided domain `d`, the gate computes `public_suffix(d)` using the PSL reference algorithm (normal, wildcard `*.foo`, exception `!bar.foo` rules, longest-match) over both the ICANN and PRIVATE sections, and **rejects** `d` when `canonical_domain == public_suffix(canonical_domain)` — i.e. the ROR authority key must have a registrable portion and can never itself be a shared public suffix. This prevents a generic key such as `edu.cn` from propagating identity to every subdomain under it (for example `tsinghua.edu.cn`). The gate runs **before** ambiguity detection, so a dropped public-suffix key cannot poison a real registrable domain into an artificial ROR-ROR conflict. The frozen PSL snapshot identity (`psl_source`, `psl_sha256`, `psl_retrieved_at`) is recorded in the ROR authority audit, and the gate counters (`public_suffix_domain_entries_dropped`, `public_suffix_unique_keys_dropped`, `public_suffix_icann_dropped`, `public_suffix_private_dropped`, `public_suffix_unique_icann_keys_dropped`, `public_suffix_unique_private_keys_dropped`) are reported under `adapter_counts`. The downstream domain suffix matcher is unchanged; only the authority ingestion quality gate is corrected.

### Identifier namespaces

Source-local identifiers use **disjoint namespaces** and are never compared, joined, or deduplicated on raw value: `caida-as2org` (`network_organization_id`), `ror`, and the RIR-scoped handles (`ARIN` `LPL-141`, `RIPE` `ORG-IS136-RIPE`, APNIC/AFRINIC equivalents, LACNIC ownerids). Reconciliation happens only through ASN or an explicit map, never through identifier text.

### Not available

A **global institution IP-range authority does not exist**; IPv4 institutional ranges remain country- or submission-specific. **IPv6 remains out of scope** for this IPv4-only method. ASN registration is **not** promoted to organization identity.

## Operational hygiene

Authority files should be mounted read-only where practical. Record publisher/source, version, retrieval time, license/usage constraints, and transformation history in `AuthoritySpec.provenance`. Real authority data, Hunter snapshots, Measurement 212 exports, and real IP lists are prohibited from this repository.
