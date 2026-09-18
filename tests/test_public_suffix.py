"""Phase 5.2: Public Suffix List matcher unit tests.

The matcher implements the PSL reference algorithm over a self-contained inline
snapshot that mirrors the real list's structure (ICANN + PRIVATE sections,
normal / wildcard / exception rules, longest-match). These tests pin the full
rule semantics; they do not test a hardcoded list of known-bad values.
"""

from hunter_org_attribution import (
    PSL_ICANN_SECTION,
    PSL_PRIVATE_SECTION,
    PSL_SOURCE_URL,
    PublicSuffixList,
)

from psl_mini import MINI_PSL, build_psl  # noqa: F401  (MINI_PSL re-exported for other test modules)


# --------------------------------------------------------------------------
# Rule semantics
# --------------------------------------------------------------------------

def test_normal_rule():
    psl = build_psl()
    assert psl.public_suffix("example.com") == "com"
    assert psl.public_suffix("a.b.example.com") == "com"
    assert psl.public_suffix("com") == "com"


def test_multi_label_public_suffix():
    psl = build_psl()
    assert psl.public_suffix("example.co.uk") == "co.uk"
    assert psl.public_suffix("a.b.example.co.uk") == "co.uk"
    assert psl.public_suffix("example.edu.cn") == "edu.cn"
    assert psl.public_suffix("tsinghua.edu.cn") == "edu.cn"


def test_wildcard_rule():
    psl = build_psl()
    # *.kawasaki.jp : any label directly below kawasaki.jp is itself a public suffix.
    assert psl.public_suffix("foo.kawasaki.jp") == "foo.kawasaki.jp"
    assert psl.is_public_suffix("foo.kawasaki.jp") is True
    assert psl.public_suffix("bar.foo.kawasaki.jp") == "foo.kawasaki.jp"
    # *.ck
    assert psl.public_suffix("foo.ck") == "foo.ck"
    assert psl.is_public_suffix("foo.ck") is True
    assert psl.public_suffix("www.foo.ck") == "foo.ck"


def test_exception_rule():
    psl = build_psl()
    # !city.kawasaki.jp : city.kawasaki.jp itself is NOT a public suffix.
    assert psl.public_suffix("city.kawasaki.jp") == "kawasaki.jp"
    assert psl.is_public_suffix("city.kawasaki.jp") is False
    # Subdomains of the exception are registrable, not public suffixes.
    assert psl.public_suffix("www.city.kawasaki.jp") == "city.kawasaki.jp"
    assert psl.is_public_suffix("www.city.kawasaki.jp") is False


def test_longest_match_behavior():
    psl = build_psl()
    # edu.cn (2 labels) beats cn (1 label) and is the prevailing rule.
    assert psl.public_suffix("s.tsinghua.edu.cn") == "edu.cn"
    # co.uk beats uk; uk is not even a rule here, com is independent.
    assert psl.public_suffix("deep.example.co.uk") == "co.uk"


def test_icann_rule_section():
    psl = build_psl()
    match = psl.match("edu.cn")
    assert match is not None
    assert match.rule is not None
    assert match.rule.section == PSL_ICANN_SECTION
    assert psl.icann_rule_count > 0
    assert psl.private_rule_count > 0


def test_private_rule_section():
    psl = build_psl()
    match = psl.match("github.io")
    assert match is not None
    assert match.rule is not None
    assert match.rule.section == PSL_PRIVATE_SECTION
    assert psl.public_suffix("myorg.github.io") == "github.io"
    assert psl.public_suffix("appspot.com") == "appspot.com"


def test_default_rule_for_unlisted_tld():
    psl = build_psl()
    # An unlisted TLD falls back to the default rule (its last label).
    assert psl.public_suffix("example.unknown-tld-zz") == "unknown-tld-zz"


def test_canonicalization_matches_package_domain_normalization():
    psl = build_psl()
    assert psl.public_suffix("  TSingHua.Edu.CN.  ") == "edu.cn"
    assert psl.is_public_suffix("EDU.CN") is True
    assert psl.is_public_suffix("TsIngHua.Edu.CN") is False


def test_invalid_domain_returns_none():
    psl = build_psl()
    assert psl.match("") is None
    assert psl.match("a..b") is None
    assert psl.match("  ") is None


def test_snapshot_sha_mismatch_fails_closed(tmp_path):
    snapshot = tmp_path / "psl.dat"
    snapshot.write_text(MINI_PSL, encoding="utf-8")
    try:
        PublicSuffixList.from_file(snapshot, expected_sha256="1" * 64)
        raise AssertionError("expected SHA256 mismatch to fail closed")
    except ValueError as exc:
        assert "SHA256 mismatch" in str(exc)
