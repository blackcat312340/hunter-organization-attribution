# Method Freeze: Hunter Organization Attribution v1.0.0

This document is the normative authority for future reuse. Code or rules that
conflict with it are defects. Phase 1 freezes the method only; Measurement-212
must not be run as part of this phase.

## Research question

Given one Hunter-observed Internet asset, what organization identity (if any)
is deterministically supported by reviewed structured authorities and explicit
rules, what organization category is supported, and what network or hosting
infrastructure is merely contextual? The method must expose all supporting and
conflicting evidence rather than collapse observations into an opaque label.

## Runtime input

The sole operational input is `NormalizedHunterRecord` (schema version 1).
Hunter and reviewed Hunter enrichment may populate its fields. FOFA objects,
FOFA field names, LENS output records, and missing-field guesses are forbidden
runtime inputs. IPv6 is out of scope for this freeze.

## Identity and category

Organization identity answers *which named institution controls or officially
owns the asset*. Organization category answers *what kind of organization the
evidence suggests*. A generic expression such as “university” supports
`education_research`; it does not name a university. Only structured range,
exact-IP, official-domain, explicitly organization-role ASN authorities, or an
explicit identity rule may resolve identity.

## Rule families

1. `direct_range`: inclusive IPv4 start/end authority.
2. `exact_ip_mapping`: exact IPv4 authority.
3. `official_domain`: exact or label-boundary suffix domain authority.
4. `organization_asn`: ASN authority whose role explicitly says
   `organization`; `infrastructure` and `network` roles remain context.
5. `asn_org_regex`, `domain_regex`, `host_regex`, `title_regex`: field-local
   YAML rules. Category and infrastructure targets cannot create identity.

Rules run only on their declared normalized field. Concatenating unrelated
fields is forbidden because it obscures the origin of evidence.

## Evidence semantics

Every match preserves `rule_id`, `rule_type`, `matched_field`, the exact
`observed_value`, `matched_pattern`, authority/source, optional resolved
organization, optional category, optional infrastructure organization, and
provenance. All matches are sorted deterministically and retained. Absence of a
match is not evidence of absence.

## Resolution semantics

Resolution uses typed evidence, not a synthetic numeric confidence score.
Evidence types remain visible. If all identity-bearing evidence names one
organization, status is `resolved`; multiple rules may agree and add
`multi_rule`. Two or more distinct organization names produce `conflict`, a
null resolved organization, and an explicit sorted conflict set. Category-only
evidence produces `category_only`. No evidence produces `unresolved`.

The frozen identity ordering is direct range, exact IP, official domain, then
organization-role ASN. This ordering describes specificity and deterministic
presentation; it never deletes evidence and cannot conceal a conflict.

## Infrastructure is not organization

`organization attribution != infrastructure attribution`. An official
university domain on AWS resolves the university while reporting AWS as
infrastructure. An institutional range announced through CERNET resolves the
institution while reporting CERNET as network context. Generic cloud, CDN,
hosting, and ISP names never become the hosted organization unless a separate,
explicit organization authority says so.

## Provenance requirements

External authorities are local runtime inputs. Each load requires path,
expected SHA-256, authority type/schema, source name, optional expected row
count, and provenance metadata. Loading fails closed on hash, row-count, or
schema mismatch. Audit output records the actual digest, rows, schema, source,
path, and supplied provenance. Source data are excluded from version control.

LENS archive reviewed for this freeze:

- reference: `LENS-20260602`
- SHA-256: `0e76e38b27859339f952ae34d49302c8fdd358458a4d5c3b29fbfccc1221f10c`
- role: methodology/rule reference only; not a runtime dependency

## Limitations

- IPv4 only; no IPv6 range attribution.
- Root-domain derivation is conservative and not a public-suffix-list
  replacement; reviewed Hunter enrichment should supply `root_domain` where
  precision matters.
- Regexes classify textual signals and may be ambiguous; they do not establish
  identity unless explicitly defined as identity rules.
- ASN data primarily identify routing/network context. Only authority rows
  explicitly marked `organization` may resolve organization identity.
- Historical ownership, shared hosting, compromised hosts, reverse proxies,
  CDN origins, legal ownership, and operational control may diverge.
- The method does not claim completeness and performs no network queries.

