"""Offline unit tests for HTTP-methods grading (pure assess_methods)."""

from recon_mcp.tools.http_methods import assess_methods


def _methods(assessment):
    return {f["method"] for f in assessment["findings"] if f["method"]}


def test_only_safe_methods_is_grade_a():
    a = assess_methods("GET, HEAD, POST, OPTIONS", trace_enabled=False)
    assert a["grade"] == "A"
    assert a["score"] == 100
    assert a["dangerous_methods"] == []
    assert [f["severity"] for f in a["findings"]] == ["ok"]


def test_advertised_methods_parsed_and_normalized():
    a = assess_methods(" get , Post ,options", trace_enabled=False)
    assert a["advertised_methods"] == ["GET", "OPTIONS", "POST"]


def test_trace_via_probe_is_high_xst():
    a = assess_methods("GET, POST", trace_enabled=True)
    assert "TRACE" in a["dangerous_methods"]
    assert a["score"] == 60  # -40
    trace = next(f for f in a["findings"] if f["method"] == "TRACE")
    assert trace["severity"] == "high"
    assert "xst" in trace["message"].lower()


def test_trace_via_allow_header_also_flagged():
    a = assess_methods("GET, TRACE", trace_enabled=False)
    assert "TRACE" in a["dangerous_methods"]


def test_put_and_delete_are_high():
    a = assess_methods("GET, PUT, DELETE", trace_enabled=False)
    assert {"PUT", "DELETE"} <= set(a["dangerous_methods"])
    assert a["score"] == 40  # -30 -30
    assert a["grade"] == "D"
    for m in ("PUT", "DELETE"):
        sev = [f["severity"] for f in a["findings"] if f["method"] == m]
        assert sev == ["high"]


def test_connect_is_medium_and_patch_is_info():
    a = assess_methods("GET, CONNECT, PATCH", trace_enabled=False)
    assert a["dangerous_methods"] == ["CONNECT", "PATCH"]
    assert a["score"] == 75  # -20 connect, -5 patch
    sev = {f["method"]: f["severity"] for f in a["findings"] if f["method"]}
    assert sev["CONNECT"] == "medium"
    assert sev["PATCH"] == "info"


def test_dangerous_findings_carry_recommendations():
    a = assess_methods("GET, PUT, DELETE, TRACE", trace_enabled=True)
    for f in a["findings"]:
        if f["severity"] != "ok":
            assert f.get("recommendation")


def test_empty_allow_header_no_crash():
    a = assess_methods(None, trace_enabled=False)
    assert a["advertised_methods"] == []
    assert a["grade"] == "A"
