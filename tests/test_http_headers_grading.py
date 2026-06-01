"""Offline unit tests for the HTTP-headers scoring/grading logic (no network)."""

from recon_mcp.tools.http_headers import HTTPHeadersAnalyzer, TOTAL_WEIGHT


def _score(checks):
    return HTTPHeadersAnalyzer()._calculate_score(checks)


def _grade(score):
    return HTTPHeadersAnalyzer()._calculate_grade(score)


def test_score_all_pass_is_100():
    assert _score([{"status": "pass", "weight": TOTAL_WEIGHT}]) == 100


def test_score_all_fail_is_0():
    assert _score([{"status": "fail", "weight": TOTAL_WEIGHT}]) == 0


def test_score_warn_is_half():
    assert _score([{"status": "warn", "weight": TOTAL_WEIGHT}]) == 50


def test_grade_boundaries():
    assert _grade(100) == "A+"
    assert _grade(95) == "A+"
    assert _grade(94) == "A"
    assert _grade(85) == "A"
    assert _grade(84) == "B"
    assert _grade(70) == "B"
    assert _grade(50) == "C"
    assert _grade(30) == "D"
    assert _grade(29) == "F"
    assert _grade(0) == "F"
