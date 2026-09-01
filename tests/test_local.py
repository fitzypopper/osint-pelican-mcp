"""Unit tests for pure/local logic that does not require the network."""

from __future__ import annotations

from pelican.tools import suite
from pelican.tools.social import email_permutations


def test_email_permutations_contains_common_patterns():
    res = email_permutations("Jane", "Doe", "acme.com")
    assert res["count"] > 0
    perms = set(res["permutations"])
    assert "jane@acme.com" in perms
    assert "jane.doe@acme.com" in perms
    assert "jdoe@acme.com" in perms
    assert "jd@acme.com" in perms
    # all normalized to lowercase / trimmed
    assert all(p.endswith("@acme.com") for p in perms)


def test_email_permutations_deduplicates():
    # first/last with a shared initial still stays deduped by set
    res = email_permutations("Ann", "A", "x.io")
    assert len(res["permutations"]) == len(set(res["permutations"]))


def test_email_permutations_requires_names():
    res = email_permutations("", "", "x.io")
    assert "error" in res


def test_list_sources_reports_structure():
    res = suite.list_sources()
    assert res["server"] == "pelican"
    srcs = res["sources"]
    # free sources always present
    for name in ("dns", "whois_rdap", "certificate_transparency", "geoip", "github"):
        assert name in srcs
    # key-gated sources expose status
    assert "key_configured" in srcs["github"]
    assert "key_configured" in srcs["hibp_breaches"]


def test_spf_dmarc_policy_helpers():
    from pelican.tools.domain import _dmarc_policy, _spf_policy

    assert _spf_policy(["v=spf1 include:_spf.x.com -all"]) == "hardfail"
    assert _spf_policy(["v=spf1 include:_spf.x.com ~all"]) == "softfail"
    assert _spf_policy(["v=spf1 include:_spf.x.com +all"]) == "passall"
    assert _spf_policy(["v=spf1 include:_spf.x.com"]) == "weak"
    assert _spf_policy(["not-spf"]) is None

    assert _dmarc_policy(["v=DMARC1; p=reject; sp=reject"]) == "reject"
    assert _dmarc_policy(["v=DMARC1; p=quarantine"]) == "quarantine"
    assert _dmarc_policy(["v=DMARC1; p=none"]) == "none"
    assert _dmarc_policy(["nope"]) is None
