"""Cookie security and redirect-chain analysis.

Follows a host's redirect chain (recording every hop and flagging an
HTTPS->HTTP downgrade) and audits the cookies set along the way for the three
flags that matter: Secure, HttpOnly, and SameSite. Parsing and grading are pure
functions; only the chain walk touches the network.
"""

import http.client
import ssl

MAX_HOPS = 10

# Per-flag weights for a single cookie's score (sum to 100).
_W_SECURE = 40
_W_HTTPONLY = 30
_W_SAMESITE = 30


def parse_set_cookie(line):
    """Parse one Set-Cookie header value into {name, secure, httponly, samesite}.

    Only the security-relevant attributes are extracted; the cookie value is
    intentionally dropped (it may be a secret). `samesite` is the lowercased
    attribute value, or None if absent.
    """
    parts = [p.strip() for p in str(line).split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and "=" in parts[0] else parts[0].strip()
    cookie = {"name": name, "secure": False, "httponly": False, "samesite": None}
    for attr in parts[1:]:
        low = attr.lower()
        if low == "secure":
            cookie["secure"] = True
        elif low == "httponly":
            cookie["httponly"] = True
        elif low.startswith("samesite"):
            _, _, val = attr.partition("=")
            cookie["samesite"] = val.strip().lower() or None
    return cookie


def grade_cookies(cookies):
    """Score parsed cookies and produce findings. Returns (grade, score, findings).

    Each cookie earns points for Secure / HttpOnly / a non-None SameSite; the
    score is the average across cookies. A SameSite=None without Secure is a
    distinct misconfiguration (browsers reject it) and is called out. With no
    cookies, returns grade None.
    """
    findings = []
    if not cookies:
        return None, None, findings

    total = 0
    for c in cookies:
        score = 0
        if c["secure"]:
            score += _W_SECURE
        else:
            findings.append(_finding("high", c["name"], "secure", "missing the Secure flag",
                                     "may be sent over plaintext HTTP"))
        if c["httponly"]:
            score += _W_HTTPONLY
        else:
            findings.append(_finding("medium", c["name"], "httponly", "missing the HttpOnly flag",
                                     "readable by JavaScript (XSS can steal it)"))
        if c["samesite"] in ("lax", "strict"):
            score += _W_SAMESITE
        elif c["samesite"] == "none" and not c["secure"]:
            findings.append(_finding("medium", c["name"], "samesite", "SameSite=None without Secure",
                                     "browsers reject this combination"))
        else:
            findings.append(_finding("low", c["name"], "samesite", "missing or weak SameSite",
                                     "offers no CSRF protection by default"))
        total += score

    avg = round(total / len(cookies))
    return _grade(avg), avg, findings


def analyze_redirect_chain(chain):
    """Inspect a list of redirect hops for security issues.

    `chain` is a list of {url, status, location}. Flags any HTTPS->HTTP
    downgrade redirect, which exposes the user to a plaintext hop.
    """
    findings = []
    for hop in chain:
        loc = (hop.get("location") or "").lower()
        if hop.get("url", "").lower().startswith("https://") and loc.startswith("http://"):
            findings.append({
                "id": "redirect-downgrade", "category": "redirect", "severity": "high",
                "title": "HTTPS to HTTP downgrade redirect",
                "description": f"{hop['url']} redirects to a plaintext URL",
                "evidence": f"Location: {hop.get('location')}",
                "remediation": "Never redirect from HTTPS to HTTP; keep the whole chain on TLS.",
            })
    return findings


def _finding(severity, name, flag, what, why):
    return {
        "id": f"cookie-{name.lower()}-{flag}",
        "category": "cookie", "severity": severity,
        "title": f"Cookie '{name}' {what}",
        "description": why,
        "evidence": f"Set-Cookie: {name}",
        "remediation": "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on session cookies.",
    }


def _grade(score):
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


# ==================== network ====================

def _request(host, port, use_ssl, path, timeout):
    """Single HTTP(S) HEADless GET returning (status, set_cookie_list, location)."""
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "recon-kit-mcp/0.8"})
        resp = conn.getresponse()
        resp.read()
        set_cookies = resp.headers.get_all("Set-Cookie") or []
        location = resp.getheader("Location")
        return resp.status, set_cookies, location
    finally:
        conn.close()


def _split_url(url):
    """Return (use_ssl, host, port, path) for an absolute http(s) URL."""
    use_ssl = url.lower().startswith("https://")
    rest = url.split("://", 1)[1]
    netloc, _, path = rest.partition("/")
    path = "/" + path
    host, _, port_s = netloc.partition(":")
    port = int(port_s) if port_s.isdigit() else (443 if use_ssl else 80)
    return use_ssl, host, port, path


def cookie_audit(host, port=None, use_ssl=True, timeout=5.0, max_hops=MAX_HOPS):
    """Walk the redirect chain from a host and audit the cookies it sets.

    Returns a dict with the redirect chain, the final URL, parsed cookies (no
    values), an overall cookie grade, and combined findings (cookie flags plus
    any downgrade redirect). Certificate verification is disabled so a host with
    a broken cert is still auditable.
    """
    if port is None:
        port = 443 if use_ssl else 80
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}/"

    chain = []
    cookies = []
    seen = set()
    for _ in range(max_hops):
        cur_ssl, cur_host, cur_port, cur_path = _split_url(url)
        if url in seen:
            break
        seen.add(url)
        try:
            status, set_cookies, location = _request(cur_host, cur_port, cur_ssl, cur_path, timeout)
        except Exception as e:
            return {"host": host, "error": f"{type(e).__name__}: {e}", "redirect_chain": chain}

        for sc in set_cookies:
            cookies.append(parse_set_cookie(sc))
        hop = {"url": url, "status": status, "location": location}
        chain.append(hop)

        if status in (301, 302, 303, 307, 308) and location:
            url = location if "://" in location else _resolve(scheme, cur_host, cur_port, location)
        else:
            break

    grade, score, cookie_findings = grade_cookies(cookies)
    findings = cookie_findings + analyze_redirect_chain(chain)
    return {
        "host": host,
        "redirect_chain": chain,
        "final_url": chain[-1]["url"] if chain else url,
        "cookies": cookies,
        "cookie_grade": grade,
        "cookie_score": score,
        "findings": findings,
    }


def _resolve(scheme, host, port, location):
    """Resolve a relative Location header to an absolute URL."""
    if location.startswith("/"):
        return f"{scheme}://{host}:{port}{location}"
    return f"{scheme}://{host}:{port}/{location}"
