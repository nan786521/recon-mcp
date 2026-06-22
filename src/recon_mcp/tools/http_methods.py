"""HTTP methods audit — which request methods a server allows, graded.

Enabled write/diagnostic methods widen the attack surface: TRACE enables
Cross-Site Tracing (XST), and PUT / DELETE can let an attacker upload or remove
files when access control is weak. This tool reports the methods a server
permits and grades the risk.

**Safety:** it never sends a mutating request. It actively probes only
non-destructive methods (OPTIONS, HEAD, TRACE — TRACE merely echoes the
request). The dangerous methods (PUT, DELETE, PATCH, CONNECT) are read from the
OPTIONS `Allow` header only — they are reported as *advertised*, never invoked.
The grading (`assess_methods`) is a pure function, split from the network for
easy offline testing. Authorized use only.
"""

import http.client
import ssl

from recon_mcp.util import USER_AGENT, normalize_host

# Methods that cannot change server state — safe to actually send.
SAFE_METHODS = {"GET", "HEAD", "POST", "OPTIONS", "TRACE"}

# Advertised method -> (score penalty, severity, why it matters, fix).
_DANGEROUS = {
    "PUT": (30, "high", "PUT is allowed; with weak access control an attacker may upload arbitrary files.",
            "Disable PUT unless a WebDAV/upload endpoint genuinely needs it, and require authentication."),
    "DELETE": (30, "high", "DELETE is allowed; with weak access control an attacker may remove server resources.",
               "Disable DELETE unless required, and gate it behind authentication."),
    "CONNECT": (20, "medium", "CONNECT is allowed; a misconfigured server may be abused as an open proxy.",
                "Disable CONNECT on the web server."),
    "PATCH": (5, "info", "PATCH is allowed; ensure write operations are authenticated and authorized.",
              "Restrict PATCH to authenticated, authorized clients."),
}


def assess_methods(allow_header, trace_enabled):
    """Grade a server's allowed HTTP methods. Pure — no network.

    Args:
        allow_header: the value of the OPTIONS `Allow` response header, or None.
        trace_enabled: whether an active TRACE probe was answered (status 200).

    Returns:
        A dict with advertised_methods, trace_enabled, dangerous_methods, grade,
        score, and a findings list (severity / method / message / recommendation).
    """
    advertised = sorted({m.strip().upper() for m in (allow_header or "").split(",") if m.strip()})

    findings = []
    dangerous = []
    score = 100

    # TRACE — confirmed by probe or advertised. Cross-Site Tracing risk.
    if trace_enabled or "TRACE" in advertised:
        dangerous.append("TRACE")
        score -= 40
        findings.append({
            "severity": "high", "method": "TRACE",
            "message": ("TRACE is enabled, which allows Cross-Site Tracing (XST): a request's "
                        "headers (including cookies) are echoed back, aiding credential theft."),
            "recommendation": "Disable the TRACE method on the web server.",
        })

    for method, (penalty, severity, message, fix) in _DANGEROUS.items():
        if method in advertised:
            dangerous.append(method)
            score -= penalty
            findings.append({"severity": severity, "method": method,
                             "message": message, "recommendation": fix})

    if not dangerous:
        findings.append({
            "severity": "ok", "method": None,
            "message": "Only safe methods are exposed; no dangerous methods detected.",
        })

    score = max(score, 0)
    grade = (
        "A" if score >= 90 else
        "B" if score >= 75 else
        "C" if score >= 60 else
        "D" if score >= 40 else "F"
    )

    return {
        "advertised_methods": advertised,
        "trace_enabled": bool(trace_enabled),
        "dangerous_methods": sorted(set(dangerous)),
        "grade": grade,
        "score": score,
        "findings": findings,
    }


def _probe(method, host, port, use_ssl, path, timeout):
    """Send one request with the given method. Returns {status, allow} or {error}."""
    conn = None
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, headers={"User-Agent": USER_AGENT})
        resp = conn.getresponse()
        status, allow = resp.status, resp.getheader("Allow")
        resp.read(2048)  # drain so the connection can close cleanly
        return {"status": status, "allow": allow}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        if conn is not None:
            conn.close()


def http_methods_audit(host, port=None, use_ssl=True, path="/", timeout=5.0):
    """Audit which HTTP methods a server allows and grade the risk. Network I/O.

    Sends a non-destructive OPTIONS (for the Allow header) and a TRACE probe;
    dangerous methods are read from Allow, never invoked.
    """
    host = normalize_host(host)
    if port is None:
        port = 443 if use_ssl else 80
    path = path or "/"
    scheme = "https" if use_ssl else "http"
    default_port = (use_ssl and port == 443) or (not use_ssl and port == 80)
    url = f"{scheme}://{host}{'' if default_port else ':' + str(port)}{path}"

    options = _probe("OPTIONS", host, port, use_ssl, path, timeout)
    if options.get("error"):
        return {"host": host, "url": url, "error": options["error"]}

    trace = _probe("TRACE", host, port, use_ssl, path, timeout)
    trace_enabled = trace.get("status") == 200

    result = assess_methods(options.get("allow"), trace_enabled)
    result.update({
        "host": host,
        "url": url,
        "allow_header": options.get("allow"),
        "options_status": options.get("status"),
    })
    return result
