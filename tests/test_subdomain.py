"""Offline unit tests for subdomain candidate building and guardrails."""

import pytest

from recon_mcp.tools.subdomain import (
    build_candidates,
    SubdomainEnumError,
    COMMON_SUBDOMAINS,
    MAX_CANDIDATES,
)


def test_default_wordlist_builds_fqdns():
    cands = build_candidates("example.com")
    assert len(cands) == len(COMMON_SUBDOMAINS)
    assert "www.example.com" in cands
    assert all(c.endswith(".example.com") for c in cands)


def test_custom_wordlist_string():
    assert build_candidates("x.io", "www,api,dev") == ["www.x.io", "api.x.io", "dev.x.io"]


def test_custom_wordlist_dedup_and_normalize():
    cands = build_candidates("x.io", "WWW, www , api,")
    assert cands == ["www.x.io", "api.x.io"]


def test_empty_wordlist_rejected():
    with pytest.raises(SubdomainEnumError):
        build_candidates("x.io", " , ,")


def test_exceeding_cap_rejected():
    big = ",".join(f"s{i}" for i in range(MAX_CANDIDATES + 1))
    with pytest.raises(SubdomainEnumError):
        build_candidates("x.io", big)
