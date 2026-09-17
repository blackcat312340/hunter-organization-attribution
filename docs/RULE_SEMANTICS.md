# Rule Semantics and LENS Migration

## Executable rule record

Every YAML rule contains `rule_id`, `target`, `field`, `operator`, `pattern`,
`source`, and `notes`, plus `resolved_category` and/or `organization` when
applicable. `target` is one of `organization_identity`,
`organization_category`, or `infrastructure`. Supported operators are
case-insensitive `regex`, `equals`, and label-aware `suffix`.

Rules marked `executable: false` are documentation-only. The loader retains
them for review but the engine excludes them.

## What was reused from LENS-20260602

The reviewed implementation was `utils/cn_org_ip_stats.py`. It:

- classified a combined string of FOFA `org`, `domain`, `hosts`, and `titles`;
- used education/research terms including CERNET, “education and research”,
  `.edu`, university, college, academy of sciences, CNIC-CAS, and Chinese
  equivalents;
- used category regexes for government, finance, healthcare, state-owned
  enterprise, cloud vendors, and ISP/carriers;
- skipped generic cloud/ISP organizations for sensitive-organization results
  unless a stronger organization signal existed.

The reusable methodology is field-aware rule matching, category assignment,
and explicit suppression of generic infrastructure as an organization. This
repository strengthens it by preserving each field-level match, separating
identity/category/infrastructure, and making conflicts explicit.

## Migrated executable rules

- Education/research: ASN organization, domain, root domain, host, and title.
- Government: domain suffix signal.
- Finance: ASN organization text.
- Healthcare: web-title signal.
- Cloud/CDN and ISP patterns: infrastructure context only.
- AWS and CERNET: named infrastructure context for required semantic cases.

Every migrated rule has `source: LENS-20260602`. Exact patterns and notes are
in `rules/*.yaml`.

## Unsupported references

LENS/FOFA discovery queries use `body`, `server`, and `app`. There is no
approved equivalent in `NormalizedHunterRecord`. These rules are recorded as
`executable: false` in `rules/categories.yaml` and mapped to `null` in
`rules/field_mapping.yaml`. They must not run against guessed or synthesized
Hunter values.

FOFA `org` is narrowed to Hunter `asn_organization`. Its meaning is network
registration/context, not automatic hosted-organization identity.

