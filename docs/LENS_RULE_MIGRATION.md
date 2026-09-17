# LENS-20260602 Rule Migration

This document records the source-verified Phase 1 migration from `LENS-20260602` into the Hunter organization-attribution method. LENS/FOFA is a methodology and rule source only; it is never a runtime dependency and its output labels are never imported as attribution truth.

## Verified source provenance

- archive: `LENS-20260602.zip`
- independently verified archive SHA-256: `0e76e38b27859339f952ae34d49302c8fdd358458a4d5c3b29fbfccc1221f10c`
- embedded repository remote: `https://github.com/Cristliu/LENS`
- embedded repository `main` commit: `19a155697284c58d895b47a1506472a23b338594`
- reviewed source path: `utils/cn_org_ip_stats.py`
- reviewed source-file SHA-256: `b4faa14c6a6fe0b0ef6e62c6e3d339d547a5f1cf6348788a85224856426f7e29`
- source-level review date: `2026-09-17`
- runtime dependency: **none**
- archive committed to this repository: **no** (`*.zip` is ignored)

The archive hash now matches the digest recorded by the initial repository freeze. The previous source-completeness blocker is closed.

## What the source actually contains

The general classifier is `classify_org(org, domain)`. It evaluates, in order:

1. `EDU_RESEARCH_PAT` -> `education_research`
2. `GOV_PAT` -> `government`
3. `FINANCE_PAT` -> `finance`
4. `HEALTH_PAT` -> `healthcare`
5. `SOE_PAT` -> `state_owned_enterprise`
6. `CLOUD_PAT` -> `cloud_vendor`
7. `ISP_PAT` on `org` only -> `isp_carrier`
8. otherwise `other`

The source also has a distinct `detect_sensitive` classifier with ten `SENSITIVE_RULES`, plus `CLOUD_ISP_SKIP` and `STRONG_GOV_SIGNAL` guards. That subsystem is not equivalent to general organization category classification.

## Migration principle

The migration copies rule semantics and provenance, not FOFA observations or LENS output labels. Rules execute only on approved `NormalizedHunterRecord` fields.

The source classifier concatenates `org + domain`. The Hunter method deliberately splits that combined string into field-local rules so every hit records which Hunter field produced it. This preserves the source regex while improving provenance.

LENS uses first-match precedence. The Hunter attribution method deliberately does **not** inherit this precedence because its resolution contract requires all matching evidence to remain visible. Therefore source expressions are preserved, while final multi-category semantics are evidence-preserving rather than winner-takes-first.

Organization identity and organization category remain separate. Infrastructure patterns also remain orthogonal to hosted organization identity.

## Field mapping

| LENS/FOFA field | Hunter field | status | runtime semantics |
|---|---|---|---|
| `org` | `asn_organization` | supported with semantic narrowing | ASN/network registration context; not automatic hosted-organization identity |
| `domain` | `domain` | supported | normalized field-local domain evidence |
| `hosts` | `host` | supported with cardinality narrowing | LENS aggregates hosts; one Hunter record carries one host observation |
| `titles` | `web_title` | supported with cardinality narrowing | LENS aggregates titles; one Hunter record carries one title observation |
| `country` | `hunter_reported_country` | supported | observation context; not used by the general category classifier |
| `platform` | none | deliberately not migrated | service/discovery label, not organization-attribution truth |
| `body` | none | unsupported | no approved Hunter attribution field |
| `server` | none | unsupported | no approved Hunter attribution field |
| `app` | none | unsupported | FOFA discovery fingerprint/query field, no approved Hunter attribution field |

Unsupported fields are never synthesized from other Hunter values.

## Executable rule inventory

The repository contains **16 executable rules** across the default rule catalog:

| file | rules | status |
|---|---:|---|
| `rules/categories.yaml` | 10 | exact source regexes from EDU/GOV/FINANCE/HEALTH/SOE, split across `asn_organization` and `domain` |
| `rules/organization_patterns.yaml` | 5 | exact CLOUD/ISP source signals plus named AWS/CERNET method refinements |
| `rules/domain_patterns.yaml` | 1 | explicit root-domain adaptation of the source `.edu.` signal |
| **total** | **16** | |

Of these, **13** use `source: LENS-20260602` and preserve an exact source regex. **3** are explicitly marked `source: method-adaptation`:

- named AWS infrastructure refinement;
- named CERNET network-context refinement;
- normalized root-domain `.edu` refinement.

Each LENS-derived executable rule records the source path, source symbol, source-file SHA-256, archive SHA-256, and adaptation note.

## Source symbols accounted for

The executable catalog accounts for every general-classifier regex symbol:

- `EDU_RESEARCH_PAT`
- `GOV_PAT`
- `FINANCE_PAT`
- `HEALTH_PAT`
- `SOE_PAT`
- `CLOUD_PAT`
- `ISP_PAT`

`SOE_PAT` is now source-verified as:

`state grid|国家电网|petrochina|中石油|sinopec|中石化`

and is executable on both `asn_organization` and `domain`, matching the source classifier's combined `org + domain` semantics.

## Infrastructure retyping

The source returns `cloud_vendor` and `isp_carrier` as categories from `classify_org`. In this method they are intentionally retyped to target `infrastructure`, because cloud/ISP evidence describes hosting/routing context rather than the hosted organization's identity.

Generic cloud/ISP source rules do not fabricate an infrastructure organization name. Named AWS and CERNET rules are separately marked method adaptations. Infrastructure rule categories are emitted through `infrastructure_categories`, never through organization `categories`.

## Sensitive-rule preservation

`rules/sensitive_reference.yaml` preserves verbatim:

- all 10 `SENSITIVE_RULES` regexes;
- `CLOUD_ISP_SKIP`;
- `STRONG_GOV_SIGNAL`;
- source archive/file hashes and embedded repository commit.

These entries are `executable: false` in Phase 1. The reason is semantic, not missing data: `detect_sensitive` answers a separate sensitive-asset question and applies a cross-field cloud/ISP suppression guard. Executing each sensitive regex independently as an organization category would change the source meaning.

## Deliberate non-migrations

Phase 1 does not migrate:

- FOFA discovery/query execution;
- LENS platform/service labels;
- LENS per-IP classification outputs;
- labels produced only because an IP appeared in a LENS output table;
- FOFA `body`, `server`, or `app` into invented Hunter fields;
- the `detect_sensitive` final label into general organization attribution.

## Review gate for future changes

Any future migration change must record:

1. source archive/version and SHA-256;
2. source file/path/symbol and file SHA-256;
3. the Hunter field semantics used by the adaptation;
4. whether the rule targets identity, organization category, or infrastructure;
5. whether source precedence/guards are preserved, deliberately transformed, or not executable;
6. synthetic tests for false-positive controls and organization/infrastructure separation.
