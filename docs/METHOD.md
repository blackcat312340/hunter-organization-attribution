# Method Freeze: Hunter Organization Attribution v1.2.0

This document is the normative method authority for future reuse. Code or rules that conflict with it are defects. Phase 1 freezes the method only; it does **not** run Measurement 212 or create paper findings.

## 1. Research question

Given one Hunter-observed Internet asset, what organization or network association is deterministically supported by reviewed structured authorities and explicit rules, what organization category is supported, and what hosting/routing infrastructure is contextual?

The method intentionally answers **association**, not operational responsibility. An attributed IP must not automatically be described as a service deployed by, operated by, owned by, or intentionally exposed by the associated organization.

## 2. Runtime input: Hunter only

The sole operational record type is `NormalizedHunterRecord` schema 1.2.0. Hunter observations and reviewed Hunter enrichment may populate its fields. FOFA records, FOFA field names, LENS output rows, and guessed values for missing Hunter fields are forbidden runtime inputs.

The reviewed Phase 1 fields are:

`ip`, `port`, `asn`, `asn_organization`, `root_domain`, `domain`, `host`, `web_title`, `hunter_reported_country`, `infrastructure_category`, `provider_family`, `hunter_record_id`, and `observed_at`.

IPv6 is out of scope for this freeze.

## 3. Why external authorities exist

Hunter observations alone do not provide a globally complete organization identity. The method therefore accepts reviewed external authorities at runtime, including IPv4 institutional ranges, exact-IP mappings, official-domain mappings, and ASN metadata. Authorities are supplied as local files, hash-pinned, schema-validated, and never bundled in the repository.

External authority evidence and Hunter text-rule evidence are complementary rule families in one deterministic engine; neither is hidden behind a numeric confidence score.

## 4. Organization identity vs. organization category

These are different questions.

- **Organization identity**: a named entity such as `Massachusetts Institute of Technology` supported by identity-bearing evidence.
- **Organization category**: a class such as `education_research` supported by a textual/category rule.

A generic expression such as `university`, `college`, `大学`, or `学院` may support the category `education_research`. It does not identify a particular university. Category-only evidence can never synthesize an organization name.

## 5. Rule families

Structured identity/context families:

1. `direct_range` — inclusive IPv4 range containment.
2. `exact_ip_mapping` — exact IPv4 mapping.
3. `official_domain` — exact or label-boundary domain suffix mapping.
4. `organization_asn` — ASN mapping; identity is permitted only when the authority row explicitly has role `organization`. Roles `network` and `infrastructure` remain context.

Field-local deterministic rule families:

5. `asn_org_regex`
6. `domain_regex`
7. `host_regex`
8. `title_regex`

Rules run only on their declared normalized field. Concatenating unrelated fields at runtime is forbidden because it obscures provenance and changes false-positive semantics.

## 6. Structured matching

A structured authority match may resolve a concrete organization when the authority semantics permit it. Every hit records the exact matched value and operator.

- IPv4 range: `contains`
- exact IP: `equals`
- official domain: label-aware `suffix`
- ASN: `equals`

Optional authority columns may include `organization_id`, `category`, `rule_id`, and notes. Absence of `organization_id` does not block a name-based result; it remains null.

Structured authorities are indexed at engine construction time. Exact-IP and ASN lookups use keyed indexes; official domains use suffix lookup; IPv4 ranges use a sorted interval search that preserves overlapping-range evidence.

## 7. Regex and classification rules

Regex/rule classification is a first-class deterministic method, not lower-grade evidence. Method quality is controlled through rule provenance, field semantics, false-positive review, reproducibility, and ambiguity handling.

A rule explicitly declares `rule_id`, `target`, `field`, `operator`, `pattern`, `source`, `notes`, resolved outputs where applicable, and source provenance.

### Verified LENS migration

The Phase 1 LENS source is independently verified as:

- archive: `LENS-20260602.zip`
- archive SHA-256: `0e76e38b27859339f952ae34d49302c8fdd358458a4d5c3b29fbfccc1221f10c`
- source repository recorded inside the archive: `https://github.com/Cristliu/LENS`
- source repository commit: `19a155697284c58d895b47a1506472a23b338594`
- reviewed file: `utils/cn_org_ip_stats.py`
- reviewed file SHA-256: `b4faa14c6a6fe0b0ef6e62c6e3d339d547a5f1cf6348788a85224856426f7e29`

The general LENS `classify_org(org, domain)` signals `EDU_RESEARCH_PAT`, `GOV_PAT`, `FINANCE_PAT`, `HEALTH_PAT`, `SOE_PAT`, `CLOUD_PAT`, and `ISP_PAT` are accounted for in the executable rule catalog. Because LENS combines `org + domain`, each applicable source regex is split into field-local Hunter rules while preserving the exact source regex. `ISP_PAT` remains ASN-organization-only because the source applies it only to `org`.

LENS returns the first matching category. This winner-takes-first precedence is **not** inherited: the attribution method retains all independently matching evidence so ambiguity and overlap remain auditable.

`CLOUD_PAT` and `ISP_PAT` are retyped as infrastructure signals rather than hosted-organization identity/category. Named AWS and CERNET rules are explicit method adaptations and are marked separately from verbatim LENS-source rules.

The separate LENS `detect_sensitive` classifier is preserved verbatim in `rules/sensitive_reference.yaml`, including all ten sensitive patterns and its two guard regexes. It is reference-only in Phase 1 because it answers a different sensitive-asset question and its final semantics depend on a cross-field cloud/ISP guard. It is not silently reinterpreted as general organization attribution.

FOFA/LENS is never a runtime dependency and LENS per-IP output labels are never imported as attribution truth.

## 8. Multi-field evidence

One asset may match multiple independent rules. Every hit is preserved. Resolution operates over typed evidence rather than overwriting earlier matches.

Examples:

- range -> University A; official domain -> University A: multi-rule agreement.
- range -> University A; ASN/network -> CERNET: University A identity plus CERNET network context.
- official domain -> University A; ASN/infrastructure -> AWS: University A association plus AWS infrastructure context.

## 9. Organization and infrastructure are orthogonal

`organization attribution != network infrastructure attribution`.

A university domain hosted on AWS may support a university association while AWS remains infrastructure. An institutional range announced through CERNET may support an institution association while CERNET remains network context. A generic cloud/CDN/ISP signal must never become the hosted organization merely because it supplies connectivity or hosting.

Organization categories and infrastructure categories are also separate output namespaces. Infrastructure evidence such as `cloud_vendor`, `isp_carrier`, or `education_research_network` is reported through `infrastructure_categories`; it must not leak into `categories`.

## 10. Conflict preservation

Conflicting identity evidence is never silently overwritten. If two identity-bearing rules resolve different organizations, the output sets `status = conflict`, `ambiguity_status = ambiguous_conflict`, `agreement_status = conflict`, `organization_name = null`, and preserves an explicit conflict set. All underlying evidence remains present.

### 10.1 Identity reconciliation

Identity-bearing evidence is reconciled into identities by explicit rules rather than by naive `(organization_id, organization_name)` tuple equality. `organization_id` is nullable, and a missing identifier must not by itself turn an agreeing name pair into a conflict.

Let *canonical name* mean the organization name with collapsed whitespace and case folding. It is a normal form, not a similarity metric — no fuzzy string matching is used anywhere in reconciliation.

1. **Same non-null `organization_id`** → same identity, even when the display names differ. Differing names are a display-name discrepancy: each name stays visible on its own evidence row and the cluster keeps one deterministic primary name.
2. **One non-null `organization_id`, the other null, canonical names equal** → same identity.
3. **Both `organization_id` values null, canonical names equal** → same identity.
4. **Two different non-null `organization_id` values** → identity conflict, even when the names are identical. Two distinct explicit identifiers are never merged by name.
5. **One `organization_id` present and the other null, with differing canonical names** → distinct identities, reported as a conflict.

If more than one identity remains after reconciliation, the result is `conflict`; if exactly one remains, the result is `resolved`.

## 11. Deterministic resolution

Resolution does not calculate an opaque confidence score. Identity-bearing evidence is reconciled into identities by the rules in section 10.1. If exactly one identity remains, the result is resolved; if multiple identities remain, the result is conflict. Organization-category-only evidence yields `category_only`; infrastructure-only evidence yields `unresolved` with infrastructure context; no identity/category evidence also yields `unresolved`.

`multi_rule` is emitted only when multiple identity-bearing hits reconcile to **one** identity. Multiple category or infrastructure hits alone do not create identity agreement, and a category or infrastructure hit never counts toward identity agreement even when an identity hit is also present.

The conceptual specificity order is direct range, exact IP, official domain, then organization-role ASN. It is used for deterministic presentation and review, not for deleting contrary evidence.

## 12. Evidence and provenance

Every rule hit preserves:

`rule_id`, `rule_family`, `target`, `matched_field`, `observed_value`, `operator`, `pattern`, `source`, `authority`, optional organization/category/infrastructure outputs, notes, and provenance.

Structured authority provenance includes the authority digest, schema/type, row count, configured source, file path, and supplied provenance metadata. Versioned LENS-derived rules additionally preserve source path, source symbol, source-file SHA-256, archive SHA-256, and adaptation metadata where relevant.

## 13. External authority validation

Each external authority load requires local `path`, `expected_sha256`, authority type/schema, source name, optional expected row count, and provenance metadata.

The loader fails closed on SHA mismatch, row-count mismatch, schema failure, invalid IPv4/range/ASN/domain syntax, or invalid ASN role. The audit record includes a normalization report. Authority data are validated but preserved verbatim in Phase 1.

Known China education/research IPv4 authority metadata are recorded in `docs/DATA_AUTHORITIES.md`; its actual CSV is not committed.

## 14. Output semantics

The result has two layers:

1. **Asset attribution** — resolved organization identity/category, association types, infrastructure context, ambiguity, and agreement state.
2. **Evidence table** — every individual rule/authority hit with exact provenance.

This design makes attribution explainable and auditable without conflating category, identity, and infrastructure.

## 15. Scientific boundary

The correct scientific statement is of the form:

> an observed IP is associated with an organization/network according to the specified evidence.

The method does **not** by itself establish that the organization deployed the service, operates the server, owns the host, authorized the deployment, or intentionally exposed the service.

## 16. Limitations

- IPv4 only; no IPv6 range attribution in Phase 1.
- Root-domain fallback is conservative and is not a public-suffix-list replacement; reviewed enrichment should supply `root_domain` when precision matters.
- Regexes classify textual signals and can produce false positives; they do not establish identity unless explicitly defined as identity rules.
- Hunter `asn_organization` is narrower in semantics than FOFA/LENS `org`; migrated rules retain this narrowing explicitly.
- ASN data primarily identify routing/network context; only explicitly organization-role authority rows may resolve identity.
- Historical ownership, shared hosting, compromised hosts, reverse proxies, CDN origins, legal ownership, and operational control may diverge from association evidence.
- The method does not claim global completeness and performs no network queries.
