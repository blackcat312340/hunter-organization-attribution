"""Shared inline Public Suffix List snapshot used by Phase 5.2 unit tests.

Self-contained and deterministic: the unit tests never depend on the downloaded
runtime snapshot (which lives outside the repository). Mirrors the real list's
structure (ICANN + PRIVATE sections; normal / wildcard / exception rules).
"""

from hunter_org_attribution import PSL_SOURCE_URL, PublicSuffixList


MINI_PSL = """
// ===BEGIN ICANN DOMAINS===
com
net
org
edu
gov
cn
jp
in
th
mx
br
et
ng
np
om
ua
ac
ac.uk
co.uk
ac.th
edu.cn
edu.in
edu.mx
edu.br
edu.et
edu.ng
edu.np
edu.om
edu.ua
*.ck
*.np
*.kawasaki.jp
!city.kawasaki.jp
// ===END ICANN DOMAINS===

// ===BEGIN PRIVATE DOMAINS===
github.io
appspot.com
// ===END PRIVATE DOMAINS===
"""


def build_psl() -> PublicSuffixList:
    return PublicSuffixList.parse(MINI_PSL, sha256="0" * 64, source=PSL_SOURCE_URL, retrieved_at="2026-09-18T00:00:00Z")
