"""Subdomain takeover detection — pure standard library, with guardrails.

A *subdomain takeover* happens when a subdomain has a dangling DNS record —
typically a CNAME pointing at a third-party service (GitHub Pages, S3, Heroku,
Azure, ...) whose resource has been deleted or was never claimed. Anyone who can
register that resource then controls content served on the victim's subdomain.

This module detects the classic CNAME-based case passively:
  1. resolve the subdomain's CNAME target;
  2. recognize whether the target belongs to a takeover-prone service;
  3. fetch the page and look for the provider's "unclaimed resource" fingerprint,
     and/or notice the CNAME target no longer resolves (a dangling CNAME).

It is read-only recon — ordinary DNS lookups plus one HTTP GET per host. The
network layer and the verdict logic are split so the (pure) assessment is easy
to test without touching the network. Authorized use only.

Fingerprints are a curated subset of the community "can-i-take-over-xyz"
catalogue, biased toward high-confidence signals.
"""

import concurrent.futures

from recon_mcp.tools.dns import DNSRecon
from recon_mcp.util import http_get, normalize_host

MAX_HOSTS = 100         # refuse to check more hosts than this per call
MAX_CONCURRENCY = 20

# Each entry: the service name, CNAME substrings that identify it, and the
# response-body fingerprints that mean the resource is unclaimed. `status` is
# "vulnerable" (commonly exploitable) or "edge" (provider-dependent / needs
# conditions); it is reported so the caller can weigh confidence.
FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cnames": ["github.io"],
        "fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "status": "edge",
    },
    {
        "service": "AWS S3",
        "cnames": ["s3.amazonaws.com", "s3-website", ".s3.", ".s3-"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
        "status": "vulnerable",
    },
    {
        "service": "Amazon CloudFront",
        "cnames": ["cloudfront.net"],
        "fingerprints": ["The request could not be satisfied", "ERROR: The request could not be satisfied"],
        "status": "edge",
    },
    {
        "service": "Heroku",
        "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"],
        "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "status": "edge",
    },
    {
        "service": "Microsoft Azure",
        "cnames": [
            "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
            "trafficmanager.net", "blob.core.windows.net", "azureedge.net",
            "azurefd.net", "azure-api.net",
        ],
        "fingerprints": ["404 Web Site not found"],
        "status": "vulnerable",
    },
    {
        "service": "Fastly",
        "cnames": ["fastly.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "status": "edge",
    },
    {
        "service": "Shopify",
        "cnames": ["myshopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable.",
            "Only one step left!",
        ],
        "status": "edge",
    },
    {
        "service": "Tumblr",
        "cnames": ["domains.tumblr.com"],
        "fingerprints": [
            "Whatever you were looking for doesn't currently exist at this address.",
            "There's nothing here.",
        ],
        "status": "vulnerable",
    },
    {
        "service": "Pantheon",
        "cnames": ["pantheonsite.io"],
        "fingerprints": ["The gods are wise, but do not know of the site which you seek.", "404 error unknown site!"],
        "status": "vulnerable",
    },
    {
        "service": "Surge.sh",
        "cnames": ["surge.sh"],
        "fingerprints": ["project not found"],
        "status": "vulnerable",
    },
    {
        "service": "Bitbucket",
        "cnames": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "status": "vulnerable",
    },
    {
        "service": "Ghost",
        "cnames": ["ghost.io"],
        "fingerprints": ["The thing you were looking for is no longer here, or never was"],
        "status": "edge",
    },
    {
        "service": "Readme.io",
        "cnames": ["readme.io", "readmessl.com"],
        "fingerprints": ["Project doesnt exist... yet!"],
        "status": "vulnerable",
    },
    {
        "service": "Webflow",
        "cnames": ["proxy.webflow.com", "proxy-ssl.webflow.com"],
        "fingerprints": ["The page you are looking for doesn't exist or has been moved."],
        "status": "edge",
    },
    {
        "service": "Wordpress.com",
        "cnames": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
        "status": "edge",
    },
    {
        "service": "Help Scout",
        "cnames": ["helpscoutdocs.com"],
        "fingerprints": ["No settings were found for this company:"],
        "status": "vulnerable",
    },
    {
        "service": "Cargo Collective",
        "cnames": ["cargocollective.com"],
        "fingerprints": ["If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel."],
        "status": "edge",
    },
    {
        "service": "Netlify",
        "cnames": ["netlify.app", "netlify.com"],
        "fingerprints": ["Not Found - Request ID"],
        "status": "edge",
    },
]


def match_service(cname):
    """Return the FINGERPRINTS entry whose CNAME substrings match, or None.

    Pure string match against a (already lowercased) CNAME target.
    """
    if not cname:
        return None
    target = cname.lower()
    for entry in FINGERPRINTS:
        if any(sub in target for sub in entry["cnames"]):
            return entry
    return None


def assess_takeover(host, cname, target_resolves, body, http_error):
    """Decide a takeover verdict from already-collected facts. Pure — no network.

    Args:
        host: the subdomain that was checked.
        cname: its CNAME target (lowercased, no trailing dot), or None/"" if it
            has no CNAME.
        target_resolves: whether the CNAME target itself resolves (has A records).
        body: the fetched response body (any case), or None if not fetched.
        http_error: the HTTP fetch error string, or None on success.

    Returns:
        A dict with host, cname, service (or None), status, vulnerable (bool),
        severity, and a human detail. status is one of: not_applicable,
        not_vulnerable, potential, dangling_cname, vulnerable.
    """
    result = {"host": host, "cname": cname or None}

    if not cname:
        result.update(
            service=None, status="not_applicable", vulnerable=False, severity="info",
            detail=("No CNAME record. Subdomain-takeover detection applies to hosts "
                    "that CNAME to a third-party service."),
        )
        return result

    service = match_service(cname)
    result["service"] = service["service"] if service else None

    body_l = (body or "").lower()
    matched_fp = None
    if service:
        for fp in service["fingerprints"]:
            if fp.lower() in body_l:
                matched_fp = fp
                break

    if service and matched_fp:
        result.update(
            status="vulnerable", vulnerable=True, severity="high",
            confidence=service["status"], fingerprint=matched_fp,
            detail=(f"The response carries {service['service']}'s unclaimed-resource "
                    f"fingerprint (\"{matched_fp}\"). The CNAME points to "
                    f"{service['service']} but the resource is not claimed — it can "
                    f"likely be registered to take over this subdomain."),
        )
    elif service and not target_resolves:
        result.update(
            status="vulnerable", vulnerable=True, severity="high",
            confidence=service["status"],
            detail=(f"CNAME points to {service['service']} ({cname}) but the target "
                    f"does not resolve (dangling). The service slot is likely "
                    f"unclaimed and can be registered."),
        )
    elif not target_resolves:
        result.update(
            status="dangling_cname", vulnerable=True, severity="medium",
            detail=(f"CNAME points to {cname}, which does not resolve (NXDOMAIN). A "
                    f"dangling CNAME can be hijacked if the target is registrable. "
                    f"Verify whether the target can be claimed."),
        )
    elif service and http_error:
        result.update(
            status="potential", vulnerable=False, severity="low",
            confidence=service["status"],
            detail=(f"CNAME points to {service['service']}, but the page could not be "
                    f"fetched to confirm ({http_error}). Verify manually whether the "
                    f"resource is claimed."),
        )
    elif service:
        result.update(
            status="not_vulnerable", vulnerable=False, severity="info",
            detail=(f"CNAME points to {service['service']} and the resource appears "
                    f"claimed (no unclaimed-resource fingerprint in the response)."),
        )
    else:
        result.update(
            status="not_vulnerable", vulnerable=False, severity="info",
            detail=(f"CNAME points to {cname} (not a recognized takeover-prone "
                    f"service) and the target resolves."),
        )

    if http_error and not matched_fp:
        result["note"] = f"HTTP fetch issue: {http_error}"
    return result


def _fetch_body(host, timeout):
    """Fetch the host's page (HTTPS then HTTP). Returns (body, error).

    TLS verification is disabled: a host pending takeover frequently serves a
    mismatched or missing certificate, but its body still carries the provider
    fingerprint we need.
    """
    last_err = None
    for scheme in ("https", "http"):
        resp = http_get(f"{scheme}://{host}/", timeout=timeout, verify=False)
        if not resp.get("error"):
            return resp.get("body", ""), None
        last_err = resp["error"]
    return None, last_err


def check_takeover(host, timeout=6.0):
    """Check one host for a CNAME-based subdomain takeover. Performs network I/O."""
    host = normalize_host(host)
    recon = DNSRecon(timeout=timeout)

    cname = None
    cname_resp = recon.dns_query(host, "CNAME")
    for rec in cname_resp.get("records", []):
        value = rec.get("value")
        if value:
            cname = value.rstrip(".").lower()
            break

    if not cname:
        return assess_takeover(host, None, False, None, None)

    a_resp = recon.dns_query(cname, "A")
    target_resolves = any(r.get("value") for r in a_resp.get("records", []))

    body, http_error = _fetch_body(host, timeout)
    return assess_takeover(host, cname, target_resolves, body, http_error)


def check_takeovers(hosts, timeout=6.0):
    """Check several hosts concurrently. Returns a summarized result dict.

    `hosts` is a list of hostnames (already split). Deduplicated and capped at
    MAX_HOSTS. Each host is one DNS+HTTP probe; they run in a bounded pool.
    """
    seen = set()
    targets = []
    for host in hosts:
        norm = normalize_host(host)
        if norm and norm not in seen:
            seen.add(norm)
            targets.append(norm)

    if not targets:
        return {"error": "no hosts to check"}
    if len(targets) > MAX_HOSTS:
        return {"error": f"{len(targets)} hosts requested; this tool checks at most {MAX_HOSTS} per call"}

    results = []
    workers = min(MAX_CONCURRENCY, len(targets))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_takeover, host, timeout): host for host in targets}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:  # never let one host sink the batch
                results.append({"host": host, "status": "error", "vulnerable": False,
                                "severity": "info", "error": f"{type(e).__name__}: {e}"})

    results.sort(key=lambda r: r.get("host", ""))
    vulnerable = [r for r in results if r.get("vulnerable")]
    return {
        "checked": len(results),
        "vulnerable_count": len(vulnerable),
        "results": results,
    }
