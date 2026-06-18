"""Offline unit tests for cookie parsing, grading, and redirect-chain analysis."""

from recon_mcp.tools.cookies import (
    parse_set_cookie,
    grade_cookies,
    analyze_redirect_chain,
)


def test_parse_extracts_flags_and_drops_value():
    c = parse_set_cookie("sid=secret-value; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert c == {"name": "sid", "secure": True, "httponly": True, "samesite": "lax"}


def test_parse_defaults_when_flags_absent():
    c = parse_set_cookie("tracking=abc; Path=/")
    assert c == {"name": "tracking", "secure": False, "httponly": False, "samesite": None}


def test_grade_perfect_cookie_is_top():
    cookies = [{"name": "sid", "secure": True, "httponly": True, "samesite": "strict"}]
    grade, score, findings = grade_cookies(cookies)
    assert score == 100
    assert grade == "A+"
    assert findings == []


def test_grade_flags_each_missing_attribute():
    cookies = [{"name": "sid", "secure": False, "httponly": False, "samesite": None}]
    grade, score, findings = grade_cookies(cookies)
    assert score == 0
    assert grade == "F"
    severities = {f["severity"] for f in findings}
    assert severities == {"high", "medium", "low"}  # secure / httponly / samesite


def test_grade_samesite_none_without_secure_flagged():
    cookies = [{"name": "x", "secure": False, "httponly": True, "samesite": "none"}]
    _, _, findings = grade_cookies(cookies)
    assert any("SameSite=None without Secure" in f["title"] for f in findings)


def test_grade_no_cookies_returns_none():
    grade, score, findings = grade_cookies([])
    assert grade is None and score is None and findings == []


def test_redirect_downgrade_detected():
    chain = [{"url": "https://x.com/", "status": 302, "location": "http://x.com/login"}]
    findings = analyze_redirect_chain(chain)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_redirect_upgrade_is_clean():
    chain = [{"url": "http://x.com/", "status": 301, "location": "https://x.com/"}]
    assert analyze_redirect_chain(chain) == []
