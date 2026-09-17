# Method Freeze: Hunter Organization Attribution v1.1.0

This document is the normative method authority for future reuse. Code or rules that conflict with it are defects. Phase 1 freezes the method only; it does **not** run Measurement 212 or create paper findings.

## 1. Research question

Given one Hunter-observed Internet asset, what organization or network association is deterministically supported by reviewed structured authorities and explicit rules, what organization category is supported, and what hosting/routing infrastructure is contextual?

The method intentionally answers **association**, not operational responsibility. An attributed IP must not automatically be described as a service deployed by, operated by, owned by, or intentionally exposed by the associated organization.

## 2. Runtime input: Hunter only

The sole operational record type is `NormalizedHunterRecord` schema 1.1.0. Hunter observations and reviewed Hunter enrichment may populate its fields. FOFA records, FOFA field names, LENS output rows, and guessed values for missing Hunter fields are forbidden runtime inputs.

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

Rules run only on their declared normalized field. Concatenating unrelated fields is forbidden because it obscures provenance and changes false-positive semantics.

## 6. Structured matching

A structured authority match may resolve a concrete organization when the authority semantics permit it. Every hit records the exact matched value and operator.

- IPv4 range: `contains`
- exact IP: `equals`
- official domain: label-aware `suffix`
- ASN: `equals`

Optional authority columns may include `organization_id`, `category`, `rule_id`, and notes. Absence of `organization_id` does not block a name-based result; it remains null.

## 7. Regex and classification rules

Regex/rule classification is a first-class deterministic method, not lower-grade evidence. Method quality is controlled through rule provenance, field semantics, false-positive review, reproducibility, and ambiguity handling.

A regex rule explicitly declares:

- `rule_id`
- `target`
- `field`
- `operator`
- `pattern`
- `source`
- `notes`
- resolved category/organization where applicable
- executable status

LENS-derived rules are versioned in YAML and described in `docs/LENS_RULE_MIGRATION.md`. FOFA/LENS is never a runtime dependency.

## 8. Multi-field evidence

One asset may match multiple independent rules. Every hit is preserved. Resolution operates over typed evidence rather than overwriting earlier matches.

Examples:

- range -> University A; official domain -> University A: multi-rule agreement.
- range -> University A; ASN/network -> CERNET: University A identity plus CERNET network context.
- official domain -> University A; ASN/infrastructure -> AWS: University A association plus AWS infrastructure context.

## 9. Organization and infrastructure are orthogonal

`organization attribution != network infrastructure attribution`.

A university domain hosted on AWS may support a university association while AWS remains infrastructure. An institutional range announced through CERNET may support an institution association while CERNET remains network context. A generic cloud/CDN/ISP ASN must never become the hosted organization merely because it supplies connectivity or hosting.

## 10. Conflict preservation

Conflicting identity evidence is never silently overwritten. If two identity-bearing rules resolve different organizations, the output sets:

- `status = conflict`
- `ambiguity_status = ambiguous_conflict`
- `agreement_status = conflict`
- `organization_name = null`
- `conflicting_organizations = [...]`

All underlying evidence remains present.

## 11. Deterministic resolution

Resolution does not calculate an opaque confidence score. Identity-bearing evidence is grouped by resolved organization identifier/name. If exactly one identity remains, the result is resolved; if multiple identities remain, the result is conflict. Category-only evidence yields `category_only`; no identity/category evidence yields `unresolved`.

The conceptual specificity order is direct range, exact IP, official domain, then organization-role ASN. It is used for deterministic presentation and review, not for deleting contrary evidence.

`agreement_status` separately records whether a resolved identity rests on one identity hit or multiple agreeing hits. `ambiguity_status` separately records whether identity is absent, unambiguous, or conflicting.

## 12. Evidence and provenance

Every rule hit preserves:

`rule_id`, `rule_family`, `target`, `matched_field`, `observed_value`, `operator`, `pattern`, `source`, `authority`, optional organization/category/infrastructure outputs, notes, and provenance.

Structured authority provenance includes the authority digest, schema/type, row count, configured source, file path, and supplied provenance metadata. Rule evidence retains its versioned source and catalog identity.

## 13. External authority validation

Each external authority load requires:

- local `path`
- `expected_sha256`
- authority type/schema
- source name
- optional expected row count
- provenance metadata

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
- ASN data primarily identify routing/network context; only explicitly organization-role authority rows may resolve identity.
- Historical ownership, shared hosting, compromised hosts, reverse proxies, CDN origins, legal ownership, and operational control may diverge from association evidence.
- The method does not claim global completeness and performs no network queries.
- `LENS-20260602.zip` is not present in this repository; the recorded archive digest and migration provenance must be revalidated if the archive is reintroduced.
