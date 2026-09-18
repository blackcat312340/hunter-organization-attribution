"""Public Suffix List (PSL) matcher used as an authority-quality gate.

The PSL (https://publicsuffix.org) is the formal specification of which domain
suffixes are *public suffixes*: a public suffix is a domain suffix under which
anyone can register directly (for example ``com``, ``co.uk``, ``edu.cn``,
``github.io``), so it is not itself a registrable domain. The matcher below
implements the full rule semantics defined by the PSL reference algorithm:

- **normal rules** ``example.com``: the domain's public suffix is the rule
  itself when the domain ends with it.
- **wildcard rules** ``*.foo``: any label directly below ``foo`` is a public
  suffix (``x.foo``, ``a.x.foo`` are public suffixes).
- **exception rules** ``!bar.foo``: ``bar.foo`` itself is *not* a public
  suffix; its public suffix is ``foo``.
- **longest-match**: the prevailing rule is the matching rule with the most
  labels.
- **sections**: rules live in the ICANN section or the PRIVATE section; both
  are honored (an organization authority key must never be a *shared* public
  suffix from either section).

Domain canonicalization matches the rest of the package: lowercase, trim
leading/trailing dots, no whitespace, labels joined by ``.``.

The matcher is read-only: the snapshot file is never modified and its SHA256 is
recorded for the frozen runtime manifest.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# The only approved runtime authority source for the PSL.
PSL_SOURCE_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

PSL_ICANN_SECTION = "ICANN"
PSL_PRIVATE_SECTION = "PRIVATE"

_ICANN_BEGIN = "// ===BEGIN ICANN DOMAINS==="
_ICANN_END = "// ===END ICANN DOMAINS==="
_PRIVATE_BEGIN = "// ===BEGIN PRIVATE DOMAINS==="
_PRIVATE_END = "// ===END PRIVATE DOMAINS==="


@dataclass(frozen=True)
class PslRule:
    """One parsed PSL rule (labels are stored rightmost-first)."""

    labels: tuple[str, ...]
    is_wildcard: bool
    is_exception: bool
    section: str


@dataclass(frozen=True)
class PslMatch:
    """The public suffix computed for one domain plus its prevailing rule.

    ``rule`` is ``None`` when only the PSL default rule (the last label) applied,
    which happens when the domain matches no explicit rule.
    """

    public_suffix: str
    rule: PslRule | None


def _parse_rule(line: str, section: str) -> PslRule:
    if line.startswith("!"):
        labels = tuple(line[1:].lower().split("."))
        return PslRule(labels, False, True, section)
    if line.startswith("*."):
        labels = tuple(line[2:].lower().split("."))
        return PslRule(labels, True, False, section)
    return PslRule(tuple(line.lower().split(".")), False, False, section)


def _canonical_labels(domain: str) -> tuple[str, ...]:
    labels = domain.lower().strip().strip(".").split(".")
    if any(not label for label in labels):
        return ()
    return tuple(labels)


class PublicSuffixList:
    """A parsed Public Suffix List snapshot with reference semantics."""

    def __init__(
        self,
        rules: Iterable[PslRule],
        *,
        sha256: str = "",
        source: str = PSL_SOURCE_URL,
        retrieved_at: str = "",
    ) -> None:
        self._exceptions = tuple(
            sorted((r for r in rules if r.is_exception), key=lambda r: len(r.labels), reverse=True)
        )
        self._normal = tuple(
            sorted((r for r in rules if not r.is_exception), key=lambda r: len(r.labels), reverse=True)
        )
        self.sha256 = sha256
        self.source = source
        self.retrieved_at = retrieved_at
        self.icann_rule_count = sum(1 for r in rules if r.section == PSL_ICANN_SECTION)
        self.private_rule_count = sum(1 for r in rules if r.section == PSL_PRIVATE_SECTION)

    @classmethod
    def parse(
        cls,
        text: str,
        *,
        sha256: str = "",
        source: str = PSL_SOURCE_URL,
        retrieved_at: str = "",
    ) -> "PublicSuffixList":
        rules: list[PslRule] = []
        section: str | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(_ICANN_BEGIN):
                section = PSL_ICANN_SECTION
                continue
            if stripped.startswith(_ICANN_END):
                section = None
                continue
            if stripped.startswith(_PRIVATE_BEGIN):
                section = PSL_PRIVATE_SECTION
                continue
            if stripped.startswith(_PRIVATE_END):
                section = None
                continue
            if not stripped or stripped.startswith("//") or section is None:
                continue
            rules.append(_parse_rule(stripped, section))
        return cls(rules, sha256=sha256, source=source, retrieved_at=retrieved_at)

    @classmethod
    def from_file(cls, path: str | Path, *, expected_sha256: str = "") -> "PublicSuffixList":
        resolved = Path(path)
        data = resolved.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if expected_sha256 and actual.lower() != expected_sha256.lower():
            raise ValueError(f"SHA256 mismatch for {resolved}: expected {expected_sha256}, got {actual}")
        return cls.parse(data.decode("utf-8", "replace"), sha256=actual)

    def match(self, domain: str) -> PslMatch | None:
        """Compute the public suffix of ``domain`` with the PSL reference algorithm."""
        labels = _canonical_labels(domain)
        if not labels:
            return None
        size = len(labels)

        # 1. Exception rules match only the exact domain; the public suffix is
        #    the exception rule with its leftmost label removed.
        for rule in self._exceptions:
            if size == len(rule.labels) and labels == rule.labels:
                if len(rule.labels) == 1:
                    return PslMatch("", rule)
                return PslMatch(".".join(labels[1:]), rule)

        # 2. Longest matching normal/wildcard rule.
        for rule in self._normal:
            width = len(rule.labels)
            if width > size:
                continue
            if rule.is_wildcard:
                # A wildcard needs one label above the rule to match.
                if width < size and labels[size - width :] == rule.labels:
                    return PslMatch(".".join(labels[size - width - 1 :]), rule)
            else:
                if labels[size - width :] == rule.labels:
                    return PslMatch(".".join(labels[size - width :]), rule)

        # 3. Default rule: the last (rightmost) label is the public suffix.
        return PslMatch(labels[-1], None)

    def public_suffix(self, domain: str) -> str | None:
        match = self.match(domain)
        return match.public_suffix if match is not None else None

    def is_public_suffix(self, domain: str) -> bool:
        """True when ``domain`` is itself a PSL public suffix (a shared suffix)."""
        match = self.match(domain)
        if match is None:
            return False
        canonical = ".".join(_canonical_labels(domain))
        return bool(canonical) and match.public_suffix == canonical
