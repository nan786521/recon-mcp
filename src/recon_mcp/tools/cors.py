"""CORS misconfiguration probe.

Sends one GET carrying a crafted Origin header and inspects the
Access-Control-Allow-Origin / -Allow-Credentials response headers. A server
that reflects an arbitrary Origin while also allowing credentials lets any
website read authenticated responses on behalf of a logged-in victim — a
high-impact misconfiguration. One request, read-only.
"""

import http.client
import ssl

from recon_mcp.util import USER_AGENT

# A probe Origin the target should never legitimately trust.
PROBE_ORIGIN = "https://recon-probe.example"


def analyze_cors(test_origin, headers):
    """Judge a CORS configuration from the probe Origin and response headers.

    `headers` is a dict with lowercase keys. Returns a structured verdict:
    whether the Allow-Origin reflects the probe origin or is a wildcard, whether
    credentials are allowed, an overall severity, and findings. Pure — no
    network — so it is easy to test.
    """
    acao = headers.get("access-control-allow-origin")
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower() == "true"

    reflects = acao is not None and acao.strip() == test_origin
    wildcard = acao is not None and acao.strip() == "*"
    null_origin = acao is not None and acao.strip().lower() == "null"

    findings = []
    severity = "none"

    if reflects and acac:
        severity = "high"
        findings.append(_finding(
            "high", "Reflects arbitrary Origin with credentials",
            f"The server echoed the probe Origin ({test_origin}) in "
            "Access-Control-Allow-Origin and allows credentials. Any site can "
            "read authenticated responses.",
            f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true",
        ))
    elif reflects:
        severity = "medium"
        findings.append(_finding(
            "medium", "Reflects arbitrary Origin",
            "The server echoes any Origin into Access-Control-Allow-Origin, "
            "exposing non-credentialed cross-origin reads of this resource.",
            f"Access-Control-Allow-Origin: {acao}",
        ))
    elif null_origin:
        severity = "medium"
        findings.append(_finding(
            "medium", "Allow-Origin: null accepted",
            "A 'null' Origin (sandboxed iframes, local files) is trusted, which "
            "attackers can forge.",
            f"Access-Control-Allow-Origin: {acao}",
        ))
    elif wildcard and acac:
        # Browsers reject *+credentials, but it signals an intent to be permissive.
        severity = "medium"
        findings.append(_finding(
            "medium", "Wildcard Allow-Origin with credentials",
            "Access-Control-Allow-Origin: * combined with credentials is invalid "
            "per spec and signals an overly permissive intent.",
            "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
        ))
    elif wildcard:
        severity = "low"
        findings.append(_finding(
            "low", "Wildcard Allow-Origin",
            "Access-Control-Allow-Origin: * lets any site read this resource. "
            "Acceptable only for truly public, non-sensitive data.",
            "Access-Control-Allow-Origin: *",
        ))

    return {
        "test_origin": test_origin,
        "acao": acao,
        "allows_credentials": acac,
        "reflects_origin": reflects,
        "wildcard": wildcard,
        "severity": severity,
        "findings": findings,
    }


def _finding(severity, title, description, evidence):
    return {
        "id": f"cors-{title.lower().split()[0]}",
        "category": "cors", "severity": severity,
        "title": title, "description": description, "evidence": evidence,
        "remediation": "Allow only an explicit allowlist of trusted origins; never "
                       "reflect the Origin header while allowing credentials.",
    }


def cors_check(host, port=None, use_ssl=True, timeout=5.0, origin=PROBE_ORIGIN):
    """Probe a host's CORS policy with a crafted Origin and grade the response.

    Returns the analyze_cors verdict plus host/port context. Certificate
    verification is disabled so a host with a broken cert is still testable.
    """
    if port is None:
        port = 443 if use_ssl else 80

    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", "/", headers={
                "User-Agent": USER_AGENT,
                "Origin": origin,
            })
            resp = conn.getresponse()
            resp.read()
            headers = {k.lower(): v for k, v in resp.getheaders()}
        finally:
            conn.close()
    except Exception as e:
        return {"host": host, "error": f"{type(e).__name__}: {e}"}

    result = {"host": host, "port": port}
    result.update(analyze_cors(origin, headers))
    return result
