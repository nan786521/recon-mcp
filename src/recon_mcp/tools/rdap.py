"""IP ownership enrichment via RDAP.

Resolves a host to its IP and looks the IP up in the Registration Data Access
Protocol (RDAP) through rdap.org's bootstrap, which redirects to the
authoritative RIR (ARIN, RIPE, APNIC, ...). Reports who owns the address block
and where to report abuse — useful context for any recon target. Read-only:
RDAP is a public registry query, no packets reach the target.
"""

import json

from recon_mcp.tools.dns import DNSRecon
from recon_mcp.util import http_get

RDAP_IP_URL = "https://rdap.org/ip/{ip}"


def _vcard_value(vcard_array, field):
    """Pull a single field's value out of a jCard (RDAP vcardArray) structure.

    A vcardArray is ["vcard", [[name, params, type, value], ...]]. Returns the
    first matching field's value, or None.
    """
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    for entry in vcard_array[1]:
        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == field:
            return entry[3]
    return None


def _walk_entities(entities):
    """Yield every entity dict in a (possibly nested) RDAP entities list."""
    for ent in entities or []:
        if not isinstance(ent, dict):
            continue
        yield ent
        yield from _walk_entities(ent.get("entities"))


def parse_rdap_ip(data):
    """Reduce an RDAP IP response to {handle, name, country, cidr, org, abuse_email}.

    Tolerant of missing fields and of RIR-to-RIR shape differences. The abuse
    email and org name are dug out of nested entity vCards by role. Pure — no
    network — so it is easy to test.
    """
    if not isinstance(data, dict):
        return {}

    cidr = None
    cidrs = data.get("cidr0_cidrs")
    if isinstance(cidrs, list) and cidrs:
        first = cidrs[0]
        prefix = first.get("v4prefix") or first.get("v6prefix")
        length = first.get("length")
        if prefix and length is not None:
            cidr = f"{prefix}/{length}"
    if not cidr and data.get("startAddress") and data.get("endAddress"):
        cidr = f"{data['startAddress']} - {data['endAddress']}"

    org = None
    abuse_email = None
    for ent in _walk_entities(data.get("entities")):
        roles = ent.get("roles") or []
        vcard = ent.get("vcardArray")
        if "abuse" in roles and not abuse_email:
            abuse_email = _vcard_value(vcard, "email")
        if not org and ({"registrant", "owner"} & set(roles)):
            org = _vcard_value(vcard, "fn")

    return {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "country": data.get("country"),
        "cidr": cidr,
        "org": org,
        "abuse_email": abuse_email,
    }


def ip_info(host, timeout=8.0):
    """Resolve a host and enrich its IP with RDAP registry data.

    Returns {host, ip, rdap: {...}}. If the host does not resolve, or RDAP is
    unreachable, the relevant section carries an `error` field instead.
    """
    recon = DNSRecon(timeout=timeout)
    resp = recon.dns_query(host, "A")
    ips = [r["value"] for r in resp.get("records", []) if r.get("value")]
    if not ips:
        return {"host": host, "error": resp.get("error") or "host did not resolve to an A record"}
    ip = ips[0]

    rdap_resp = http_get(RDAP_IP_URL.format(ip=ip), timeout=timeout, verify=True)
    if rdap_resp.get("error"):
        return {"host": host, "ip": ip, "rdap": {"error": rdap_resp["error"]}}
    if rdap_resp.get("status") != 200:
        return {"host": host, "ip": ip,
                "rdap": {"error": f"RDAP returned HTTP {rdap_resp.get('status')}"}}
    try:
        data = json.loads(rdap_resp.get("body", ""))
    except (ValueError, TypeError):
        return {"host": host, "ip": ip, "rdap": {"error": "RDAP response was not valid JSON"}}

    return {"host": host, "ip": ip, "rdap": parse_rdap_ip(data)}
