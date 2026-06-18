"""Well-known resource recon: security.txt (RFC 9116) and robots.txt.

Fetches and parses two standard, publicly-served files that reveal an
operator's posture and intent: security.txt (vulnerability-disclosure contact
and policy) and robots.txt (paths the operator asks crawlers to avoid, which
often point at admin or internal areas). Both are plain GETs of public paths —
no probing beyond what any browser or crawler fetches.
"""

from recon_mcp.util import http_get

# RFC 9116 fields. Contact and Expires are mandatory; the rest are optional.
_SECURITY_TXT_FIELDS = {
    "contact", "expires", "encryption", "acknowledgments", "acknowledgements",
    "preferred-languages", "canonical", "policy", "hiring", "csaf",
}
_MULTI_VALUE_FIELDS = {"contact", "encryption", "acknowledgments",
                       "acknowledgements", "canonical", "policy"}


def parse_security_txt(text):
    """Parse a security.txt body into structured fields plus structural issues.

    Lines are `Field: value`; blank lines and `#` comments are ignored. Fields
    that may appear multiple times (Contact, Encryption, ...) collect into
    lists. Reports the RFC 9116 must-haves that are missing. Expiry is parsed as
    a raw string but not compared to the current time, so this stays pure and
    deterministic. Returns {fields, issues}.
    """
    fields = {}
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key not in _SECURITY_TXT_FIELDS or not value:
            continue
        if key in _MULTI_VALUE_FIELDS:
            fields.setdefault(key, []).append(value)
        else:
            fields[key] = value

    issues = []
    if "contact" not in fields:
        issues.append("Missing required Contact field")
    if "expires" not in fields:
        issues.append("Missing required Expires field (RFC 9116)")

    return {"fields": fields, "issues": issues}


def parse_robots_txt(text):
    """Parse a robots.txt body into sitemaps and per-agent disallow rules.

    Returns {sitemaps, user_agents, disallow, allow} where disallow/allow are
    de-duplicated path lists across all groups. The disallow list is the
    interesting recon signal — operators often list admin/internal paths there.
    """
    sitemaps, user_agents = [], []
    disallow, allow = [], []
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "sitemap" and value not in sitemaps:
            sitemaps.append(value)
        elif key == "user-agent" and value not in user_agents:
            user_agents.append(value)
        elif key == "disallow" and value not in disallow:
            disallow.append(value)
        elif key == "allow" and value not in allow:
            allow.append(value)

    return {
        "sitemaps": sitemaps,
        "user_agents": user_agents,
        "disallow": disallow,
        "allow": allow,
    }


def fetch_well_known(host, timeout=5.0):
    """Fetch and parse security.txt and robots.txt for a host over HTTPS.

    security.txt is tried at its RFC 9116 location (/.well-known/security.txt)
    with a fallback to the legacy /security.txt. Certificate verification is
    disabled so a host with a broken cert still yields its public files.
    Returns a dict with `security_txt` and `robots_txt` sections, each either
    parsed content (with `present: True`) or `present: False`.
    """
    result = {"host": host}

    sec = None
    for path in ("/.well-known/security.txt", "/security.txt"):
        resp = http_get(f"https://{host}{path}", timeout=timeout, verify=False)
        if not resp.get("error") and resp.get("status") == 200 and resp.get("body", "").strip():
            parsed = parse_security_txt(resp["body"])
            parsed["present"] = True
            parsed["location"] = path
            sec = parsed
            break
    result["security_txt"] = sec or {"present": False}

    robots = http_get(f"https://{host}/robots.txt", timeout=timeout, verify=False)
    if not robots.get("error") and robots.get("status") == 200 and robots.get("body", "").strip():
        parsed = parse_robots_txt(robots["body"])
        parsed["present"] = True
        result["robots_txt"] = parsed
    else:
        result["robots_txt"] = {"present": False}

    return result
