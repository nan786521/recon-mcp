"""Offline unit tests for subdomain-takeover service matching and verdicts.

All tests exercise the pure functions (match_service / assess_takeover) so they
never touch the network.
"""

from recon_mcp.tools.takeover import (
    FINGERPRINTS,
    assess_takeover,
    check_takeovers,
    match_service,
)


# ---- match_service ---------------------------------------------------------

def test_match_service_recognizes_known_cname():
    entry = match_service("myrepo.github.io")
    assert entry is not None
    assert entry["service"] == "GitHub Pages"


def test_match_service_is_case_insensitive():
    assert match_service("MyBucket.S3.AMAZONAWS.COM")["service"] == "AWS S3"


def test_match_service_unknown_returns_none():
    assert match_service("example.internal-thing.net") is None


def test_match_service_empty_returns_none():
    assert match_service("") is None
    assert match_service(None) is None


def test_every_fingerprint_entry_is_well_formed():
    for entry in FINGERPRINTS:
        assert entry["cnames"] and all(isinstance(c, str) for c in entry["cnames"])
        assert entry["fingerprints"]
        assert entry["status"] in ("vulnerable", "edge")


# ---- assess_takeover -------------------------------------------------------

def test_no_cname_is_not_applicable():
    r = assess_takeover("www.example.com", None, False, None, None)
    assert r["status"] == "not_applicable"
    assert r["vulnerable"] is False
    assert r["service"] is None


def test_fingerprint_match_is_vulnerable_high():
    body = "<html>There isn't a GitHub Pages site here.</html>"
    r = assess_takeover("blog.example.com", "victim.github.io", True, body, None)
    assert r["status"] == "vulnerable"
    assert r["vulnerable"] is True
    assert r["severity"] == "high"
    assert r["service"] == "GitHub Pages"
    assert "github" in r["fingerprint"].lower()


def test_known_service_with_unresolving_target_is_vulnerable():
    # No fingerprint in the body, but the CNAME target itself is dead (dangling).
    r = assess_takeover("shop.example.com", "victim.herokuapp.com", False, "", None)
    assert r["status"] == "vulnerable"
    assert r["vulnerable"] is True
    assert r["service"] == "Heroku"


def test_generic_dangling_cname_is_medium():
    r = assess_takeover("old.example.com", "gone.somewhere.net", False, None, "timeout")
    assert r["status"] == "dangling_cname"
    assert r["vulnerable"] is True
    assert r["severity"] == "medium"
    assert r["service"] is None


def test_known_service_unfetchable_is_potential():
    r = assess_takeover("app.example.com", "victim.herokuapp.com", True, None, "ConnectionError")
    assert r["status"] == "potential"
    assert r["vulnerable"] is False
    assert r["severity"] == "low"


def test_claimed_service_resource_is_not_vulnerable():
    body = "<html>Welcome to my live site</html>"
    r = assess_takeover("blog.example.com", "victim.github.io", True, body, None)
    assert r["status"] == "not_vulnerable"
    assert r["vulnerable"] is False


def test_unknown_service_that_resolves_is_not_vulnerable():
    r = assess_takeover("api.example.com", "lb.somecdn.example", True, "ok", None)
    assert r["status"] == "not_vulnerable"
    assert r["vulnerable"] is False
    assert r["service"] is None


# ---- check_takeovers guardrails (no network) -------------------------------

def test_check_takeovers_empty_is_error():
    assert "error" in check_takeovers([])


def test_check_takeovers_over_cap_is_error():
    res = check_takeovers([f"h{i}.example.com" for i in range(101)])
    assert "error" in res
