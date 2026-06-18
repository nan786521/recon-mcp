"""Offline unit tests for CT-log parsing and subdomain source merging."""

import json

from recon_mcp.tools.ct import parse_crt_sh
from recon_mcp.tools.subdomain import merge_subdomain_sources


def _crt_payload(records):
    return json.dumps(records)


def test_parse_extracts_name_value_and_common_name():
    raw = _crt_payload([
        {"name_value": "www.example.com", "common_name": "example.com"},
        {"name_value": "api.example.com"},
        {"common_name": "mail.example.com"},
    ])
    assert parse_crt_sh(raw, "example.com") == [
        "api.example.com", "mail.example.com", "www.example.com",
    ]


def test_parse_splits_multiline_name_value_and_dedups():
    raw = _crt_payload([
        {"name_value": "a.example.com\nb.example.com\na.example.com"},
    ])
    assert parse_crt_sh(raw, "example.com") == ["a.example.com", "b.example.com"]


def test_parse_strips_wildcards_and_drops_apex():
    raw = _crt_payload([
        {"name_value": "*.example.com"},
        {"name_value": "example.com"},
        {"name_value": "EXAMPLE.com."},
    ])
    # wildcard reduces to apex (dropped), apex variants dropped → nothing left
    assert parse_crt_sh(raw, "example.com") == []


def test_parse_excludes_unrelated_domains():
    raw = _crt_payload([
        {"name_value": "good.example.com"},
        {"name_value": "evil.notexample.com"},
        {"name_value": "x.example.com.attacker.com"},
    ])
    assert parse_crt_sh(raw, "example.com") == ["good.example.com"]


def test_parse_bad_json_returns_empty():
    assert parse_crt_sh("not json", "example.com") == []
    assert parse_crt_sh("{}", "example.com") == []


def test_merge_combines_sources_and_dedups():
    dns = {"found": [{"subdomain": "www.example.com", "ips": ["1.2.3.4"]}]}
    ct = {"found": [{"subdomain": "www.example.com"}, {"subdomain": "api.example.com"}]}
    merged = merge_subdomain_sources("example.com", dns, ct)

    assert merged["sources"] == ["dns", "ct"]
    assert merged["found_count"] == 2
    www = next(e for e in merged["found"] if e["subdomain"] == "www.example.com")
    assert sorted(www["sources"]) == ["ct", "dns"]
    assert www["ips"] == ["1.2.3.4"]
    api = next(e for e in merged["found"] if e["subdomain"] == "api.example.com")
    assert "ips" not in api  # CT-only, no resolved IPs


def test_merge_surfaces_errors_without_dropping_other_source():
    dns = {"found": [{"subdomain": "www.example.com", "ips": ["1.2.3.4"]}]}
    ct = {"error": "crt.sh returned HTTP 502"}
    merged = merge_subdomain_sources("example.com", dns, ct)

    assert merged["found_count"] == 1
    assert merged["errors"] == {"ct": "crt.sh returned HTTP 502"}


def test_merge_skips_unrequested_source():
    dns = {"found": [{"subdomain": "www.example.com", "ips": ["1.2.3.4"]}]}
    merged = merge_subdomain_sources("example.com", dns, None)
    assert merged["sources"] == ["dns"]
