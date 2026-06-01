"""Offline unit tests for the aggregate recon report logic (no network)."""

from recon_mcp.tools.report import worst_grade, build_report


def test_worst_grade_picks_lowest():
    assert worst_grade(["A", "B", "F"]) == "F"
    assert worst_grade(["A", "A"]) == "A"
    assert worst_grade(["B", "C", "D"]) == "D"


def test_worst_grade_ignores_unknown_and_none():
    assert worst_grade([None, "B", None]) == "B"
    assert worst_grade(["B", "?", ""]) == "B"
    assert worst_grade([]) is None
    assert worst_grade([None, None]) is None


def test_worst_grade_uses_first_char():
    assert worst_grade(["A+", "B-"]) == "B"


def _dns(grade="A", a_ip="1.2.3.4"):
    return {
        "records": {"A": [{"value": a_ip}]},
        "email": {"assessment": {
            "grade": grade,
            "summary": "ok",
            "findings": [
                {"severity": "ok", "check": "SPF", "message": "fine"},
                {"severity": "warning", "check": "DMARC", "message": "no DMARC"},
            ],
        }},
    }


def _tls(grade="B"):
    return {
        "grade": grade,
        "findings": [{"severity": "medium", "title": "weak cipher", "description": "..."}],
        "vulnerabilities": [
            {"name": "POODLE", "vulnerable": False, "severity": "info", "description": "n/a"},
            {"name": "BEAST", "vulnerable": True, "severity": "high", "description": "cbc"},
        ],
    }


def _headers(grade="F"):
    return {
        "grade": grade, "score": 0,
        "findings": [{"severity": "high", "title": "Missing CSP", "description": "no csp"}],
    }


def test_build_report_overall_is_worst():
    r = build_report("example.com", _dns("A"), _tls("B"), _headers("F"))
    assert r["overall_grade"] == "F"
    assert r["ip"] == "1.2.3.4"
    assert r["components"]["email"]["grade"] == "A"
    assert r["components"]["tls"]["grade"] == "B"
    assert r["components"]["headers"]["grade"] == "F"


def test_build_report_filters_ok_and_info_issues():
    r = build_report("example.com", _dns(), _tls(), _headers())
    # email: only the DMARC warning survives (SPF ok dropped)
    assert [i["label"] for i in r["components"]["email"]["issues"]] == ["DMARC"]
    # tls: medium finding kept; only the vulnerable=True vuln added, info vuln dropped
    tls_labels = [i["label"] for i in r["components"]["tls"]["issues"]]
    assert "weak cipher" in tls_labels and "BEAST" in tls_labels and "POODLE" not in tls_labels


def test_build_report_handles_component_error():
    r = build_report("example.com", _dns("A"), {"error": "connection refused"}, _headers("C"))
    assert r["components"]["tls"]["grade"] is None
    assert r["components"]["tls"]["issues"][0]["severity"] == "error"
    # overall ignores the errored component → worst of A and C is C
    assert r["overall_grade"] == "C"


def test_build_report_all_failed():
    r = build_report("x.test", {"error": "e"}, {"error": "e"}, {"error": "e"})
    assert r["overall_grade"] is None
    assert "Could not assess" in r["summary"]
