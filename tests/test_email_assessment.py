"""Offline unit tests for the email-security grading logic."""

from recon_mcp.tools.dns import grade_email_security


def _email(spf=None, dmarc=None, dkim=None):
    """Build the email-result shape that grade_email_security consumes."""
    return {
        "spf": spf or {"found": False},
        "dmarc": dmarc or {"found": False},
        "dkim": dkim or {"found": False},
    }


def _severities(assessment, check):
    return [f["severity"] for f in assessment["findings"] if f["check"] == check]


def test_fully_hardened_scores_perfect():
    a = grade_email_security(_email(
        spf={"found": True, "all_mechanism": "fail"},
        dmarc={"found": True, "policy": "reject"},
        dkim={"found": True, "selector": "default"},
    ))
    assert a["score"] == 100
    assert a["grade"] == "A"
    assert _severities(a, "SPF") == ["ok"]
    assert _severities(a, "DMARC") == ["ok"]
    assert _severities(a, "DKIM") == ["ok"]


def test_everything_missing_fails():
    a = grade_email_security(_email())
    # -30 SPF, -20 DKIM, -30 DMARC = 20
    assert a["score"] == 20
    assert a["grade"] == "F"
    assert _severities(a, "SPF") == ["warning"]
    assert _severities(a, "DKIM") == ["warning"]
    assert _severities(a, "DMARC") == ["warning"]


def test_softfail_spf_and_missing_dmarc():
    """The real-world 'SPF ~all, DKIM ok, no DMARC' case → C / 65."""
    a = grade_email_security(_email(
        spf={"found": True, "all_mechanism": "softfail"},
        dmarc={"found": False},
        dkim={"found": True, "selector": "google"},
    ))
    assert a["score"] == 65  # -5 softfail, -30 missing DMARC
    assert a["grade"] == "C"
    assert _severities(a, "SPF") == ["info"]
    assert _severities(a, "DMARC") == ["warning"]


def test_spf_plus_all_is_critical():
    a = grade_email_security(_email(
        spf={"found": True, "all_mechanism": "pass"},  # +all
        dmarc={"found": True, "policy": "reject"},
        dkim={"found": True, "selector": "default"},
    ))
    assert _severities(a, "SPF") == ["critical"]
    assert a["summary"].lower().startswith("a misconfiguration")
    assert a["score"] == 60  # 100 - 40


def test_dmarc_monitor_only_is_info():
    a = grade_email_security(_email(
        spf={"found": True, "all_mechanism": "fail"},
        dmarc={"found": True, "policy": "none"},
        dkim={"found": True, "selector": "default"},
    ))
    assert _severities(a, "DMARC") == ["info"]
    assert a["score"] == 90  # 100 - 10
    assert a["grade"] == "A"


def test_findings_carry_recommendations_when_not_ok():
    a = grade_email_security(_email())
    for f in a["findings"]:
        if f["severity"] != "ok":
            assert f.get("recommendation")
