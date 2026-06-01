"""Offline unit tests for input normalization."""

from recon_mcp.util import normalize_host


def test_strips_scheme_and_path():
    assert normalize_host("https://Example.com/path?q=1") == "example.com"
    assert normalize_host("http://example.com") == "example.com"


def test_strips_port():
    assert normalize_host("example.com:443") == "example.com"
    assert normalize_host("https://example.com:8443/x") == "example.com"


def test_strips_trailing_dot_and_whitespace():
    assert normalize_host("  example.com.  ") == "example.com"


def test_plain_domain_unchanged():
    assert normalize_host("example.com") == "example.com"


def test_lowercases():
    assert normalize_host("WWW.Example.COM") == "www.example.com"


def test_ipv6_with_multiple_colons_preserved():
    # multiple colons => not treated as host:port
    assert normalize_host("2606:4700::1") == "2606:4700::1"
