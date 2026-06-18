"""Certificate Transparency subdomain discovery via crt.sh.

Passive recon: queries public Certificate Transparency logs (through crt.sh's
JSON endpoint) for every name that has ever appeared in a certificate for the
domain. Unlike DNS brute-force enumeration this finds real, historically-issued
hostnames that no wordlist would guess. No packets are sent to the target.
"""

import json

from recon_mcp.util import http_get

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
MAX_RESULTS = 2000  # cap the parsed set; very large domains can return tens of thousands


def parse_crt_sh(raw_json, domain):
    """Extract unique subdomains of `domain` from a crt.sh JSON response.

    crt.sh returns a list of certificate records; the relevant names live in the
    `name_value` (may hold several newline-separated names) and `common_name`
    fields. Wildcards (`*.x`) are reduced to their base label. Names are
    lowercased, de-duplicated, filtered to those under `domain`, and the apex
    itself is dropped (it is not a subdomain). Returns a sorted list.
    """
    domain = str(domain).strip().lower().rstrip(".")
    try:
        records = json.loads(raw_json)
    except (ValueError, TypeError):
        return []
    if not isinstance(records, list):
        return []

    suffix = "." + domain
    found = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        names = []
        nv = rec.get("name_value")
        if nv:
            names.extend(str(nv).splitlines())
        cn = rec.get("common_name")
        if cn:
            names.append(str(cn))

        for name in names:
            host = name.strip().lower().rstrip(".")
            if host.startswith("*."):
                host = host[2:]
            if not host or host == domain:
                continue
            if host.endswith(suffix):
                found.add(host)

    return sorted(found)


def query_crt_sh(domain, timeout=15.0):
    """Fetch and parse CT-log subdomains for `domain` from crt.sh.

    Returns a dict with `domain`, `source`, `found_count`, and `found` (a list
    of subdomain names). On a network/transport failure returns an `error`
    field. crt.sh can be slow, so this defaults to a generous timeout.
    """
    resp = http_get(CRT_SH_URL.format(domain=domain), timeout=timeout, verify=True)
    if resp.get("error"):
        return {"domain": domain, "source": "ct", "error": resp["error"]}
    if resp.get("status") != 200:
        return {"domain": domain, "source": "ct",
                "error": f"crt.sh returned HTTP {resp.get('status')}"}

    names = parse_crt_sh(resp.get("body", ""), domain)
    truncated = len(names) > MAX_RESULTS
    names = names[:MAX_RESULTS]
    result = {
        "domain": domain,
        "source": "ct",
        "found_count": len(names),
        "found": [{"subdomain": n} for n in names],
    }
    if truncated:
        result["truncated"] = True
    return result
