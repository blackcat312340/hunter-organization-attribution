# LENS-20260602 Rule Migration

This document records the Phase 1 migration inventory from `LENS-20260602` into the Hunter organization-attribution method. LENS/FOFA is a methodology and rule source only; it is never a runtime dependency and its output labels are never imported as attribution truth.

## Source archive provenance

- archive: `LENS-20260602.zip`
- recorded SHA-256: `0e76e38b27859339f952ae34d49302c8fdd358458a4d5c3b29fbfccc1221f10c`
- reviewed implementation recorded by the initial freeze: `utils/cn_org_ip_stats.py`
- migration review date: `2026-09-17`
- runtime dependency: **none**
- archive committed to this repository: **no** (`*.zip` is ignored)

The digest above is inherited from the initial Phase 1 freeze commit. This review did not have the archive bytes available to re-hash independently. The currently accessible preserved task notes also state that LENS contains an `SOE` category family, but they do not contain the source expression needed to migrate it faithfully. Therefore this document must not claim complete source-level parity with LENS until the archive is re-materialized and verified.

A future archive re-materialization must first verify the recorded digest, then compare the original classifier implementation rule by rule against this inventory. No missing rule may be reconstructed from memory or a category name alone.

## Migration principle

The migration copies rule semantics, not FOFA observations or LENS output labels. Rules are normalized into field-local deterministic matches with explicit provenance. A rule executes only when its source field has an approved `NormalizedHunterRecord` counterpart.

Organization identity and organization category remain separate. Category regexes such as `university`, `college`, `大学`, or `科学院` may establish `education_research`, but they cannot invent a named institution. Infrastructure patterns such as cloud/ISP/CERNET remain network or hosting context unless a separate identity authority names an organization.

## Field mapping

| LENS/FOFA field | Hunter field | status | runtime semantics |
|---|---|---|---|
| `org` | `asn_organization` | supported with semantic narrowing | ASN/network registration context; not automatic hosted-organization identity |
| `domain` | `domain` / reviewed `root_domain` | supported | field-local domain evidence |
| `hosts` | `host` | supported | one normalized host value per Hunter observation |
| `titles` | `web_title` | supported | one reviewed web-title value per Hunter observation |
| `body` | none | unsupported | no approved Hunter equivalent |
| `server` | none | unsupported | no approved Hunter equivalent |
| `app` | none | unsupported | no approved Hunter equivalent |

Unsupported fields must never be synthesized from other Hunter values.

## Current repository rule inventory

The repository currently contains **15 LENS-derived inventory entries**:

- **12 executable rules**
- **3 documentation-only unsupported-field rules**

Executable rules by repository file:

| file | executable rules | purpose |
|---|---:|---|
| `rules/categories.yaml` | 7 | education/research, government, finance, healthcare category signals |
| `rules/organization_patterns.yaml` | 4 | AWS, CERNET, broad cloud/CDN, and ISP/carrier infrastructure context |
| `rules/domain_patterns.yaml` | 1 | root-domain education/research category signal |
| **total** | **12** | |

Unsupported inventory entries in `rules/categories.yaml`:

1. `lens.unsupported.fofa.body.education`
2. `lens.unsupported.fofa.server`
3. `lens.unsupported.fofa.app`

All executable migrated rules carry `source: LENS-20260602` and retain a rule-specific note describing the adaptation.

## Known source-verification gap

The preserved Phase 1 task context states that the LENS classifier also contains an **SOE** category family. The exact original field combination, expression, and exclusions are not present in the accessible material. Because the archive bytes are unavailable in this review session, no executable SOE rule is added here.

Status:

- known LENS family: `SOE`
- current repository migration: **not yet source-verified**
- executable rule fabricated from summary text: **no**
- required action before claiming complete LENS migration: verify `LENS-20260602.zip` SHA-256 and inspect the original classifier implementation

This is a provenance/completeness gate, not a reason to import LENS output labels directly.

## Migrated semantic families

The currently verified executable migration covers:

- education/research terms derived from the recorded LENS education/research classifier, including CERNET, education-and-research wording, `.edu`/academic-domain signals, university/college, academy-of-sciences, CNIC-CAS, and Chinese equivalents;
- government domain-category signals;
- finance organization-text signals;
- healthcare title signals;
- cloud/CDN and ISP/carrier patterns moved to **infrastructure context**, not organization identity;
- named AWS and CERNET infrastructure/network context for the required orthogonality tests.

The initial freeze records LENS identifiers/ideas such as `EDU_RESEARCH_PAT`, government/finance/health patterns, and cloud/ISP skip logic. This repository does not depend on those Python symbols at runtime; their normalized counterparts are the versioned YAML rules.

## Deliberate non-migrations

Phase 1 does not migrate:

- FOFA discovery or query execution;
- LENS `platform` or service labels;
- LENS per-IP category results;
- any label produced only because an IP appeared in a LENS output table;
- any rule requiring `body`, `server`, or `app` until Hunter supplies a reviewed semantically equivalent field.

These deliberate non-migrations are distinct from the unresolved SOE source-verification gap above.

## Review gate before modifying this inventory

Any future change must record:

1. the source archive/version and SHA-256;
2. the original rule or rule family being adapted;
3. the Hunter field semantics used by the new rule;
4. whether the rule targets identity, category, or infrastructure;
5. supported/unsupported runtime status;
6. synthetic tests demonstrating false-positive controls and organization/infrastructure separation.

Phase 1 may freeze the method implementation independently, but it must not label the LENS migration as source-complete until the archive gate is closed.
