"""Offline unit tests for CORS verdict logic."""

from recon_mcp.tools.cors import analyze_cors, PROBE_ORIGIN


def test_reflects_origin_with_credentials_is_high():
    headers = {
        "access-control-allow-origin": PROBE_ORIGIN,
        "access-control-allow-credentials": "true",
    }
    v = analyze_cors(PROBE_ORIGIN, headers)
    assert v["severity"] == "high"
    assert v["reflects_origin"] is True
    assert v["allows_credentials"] is True


def test_reflects_origin_without_credentials_is_medium():
    v = analyze_cors(PROBE_ORIGIN, {"access-control-allow-origin": PROBE_ORIGIN})
    assert v["severity"] == "medium"
    assert v["reflects_origin"] is True


def test_null_origin_is_medium():
    v = analyze_cors(PROBE_ORIGIN, {"access-control-allow-origin": "null"})
    assert v["severity"] == "medium"
    assert any("null" in f["title"].lower() for f in v["findings"])


def test_wildcard_alone_is_low():
    v = analyze_cors(PROBE_ORIGIN, {"access-control-allow-origin": "*"})
    assert v["severity"] == "low"
    assert v["wildcard"] is True


def test_wildcard_with_credentials_is_medium():
    v = analyze_cors(PROBE_ORIGIN, {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    })
    assert v["severity"] == "medium"


def test_no_cors_header_is_clean():
    v = analyze_cors(PROBE_ORIGIN, {"content-type": "text/html"})
    assert v["severity"] == "none"
    assert v["findings"] == []
    assert v["acao"] is None


def test_specific_allowed_origin_not_flagged():
    # Server returns its own fixed origin, not the probe -> not a reflection.
    v = analyze_cors(PROBE_ORIGIN, {"access-control-allow-origin": "https://trusted.example"})
    assert v["severity"] == "none"
    assert v["reflects_origin"] is False
