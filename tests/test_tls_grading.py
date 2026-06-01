"""Offline unit tests for the TLS grading logic (no network)."""

from recon_mcp.tools.tls import SSLAnalyzer


def _baseline():
    """A fully-hardened result that should grade A+."""
    return {
        "certificate": {"is_expired": False, "key_bits": 2048, "key_algorithm": "RSA"},
        "chain_valid": True,
        "protocols": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True,
                      "TLSv1.3": True, "SSLv3": False},
        "hsts": {"enabled": True, "preload": True, "include_subdomains": True},
        "vulnerabilities": [],
        "forward_secrecy": True,
    }


def _grade(result):
    return SSLAnalyzer()._calculate_grade(result)


def test_hardened_is_a_plus():
    assert _grade(_baseline()) == "A+"


def test_expired_cert_is_f():
    r = _baseline()
    r["certificate"]["is_expired"] = True
    assert _grade(r) == "F"


def test_no_modern_tls_is_f():
    r = _baseline()
    r["protocols"]["TLSv1.2"] = False
    r["protocols"]["TLSv1.3"] = False
    assert _grade(r) == "F"


def test_sslv3_is_f():
    r = _baseline()
    r["protocols"]["SSLv3"] = True
    assert _grade(r) == "F"


def test_weak_rsa_key_is_d():
    r = _baseline()
    r["certificate"]["key_bits"] = 1024
    assert _grade(r) == "D"


def test_legacy_tls10_is_c():
    r = _baseline()
    r["protocols"]["TLSv1.0"] = True
    assert _grade(r) == "C"


def test_no_forward_secrecy_is_b():
    r = _baseline()
    r["forward_secrecy"] = False
    assert _grade(r) == "B"


def test_no_hsts_is_b():
    r = _baseline()
    r["hsts"]["enabled"] = False
    assert _grade(r) == "B"


def test_good_but_no_preload_is_a():
    r = _baseline()
    r["hsts"]["preload"] = False
    assert _grade(r) == "A"
