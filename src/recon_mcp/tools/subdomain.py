"""Subdomain enumeration — DNS-based, pure standard library, with guardrails.

Resolves a list of candidate subdomains against a domain using DNS A queries
(reusing the DNS engine). Passive recon: it only performs ordinary DNS lookups.
Capped per call so it cannot be turned into a DNS flood. Authorized use only.
"""

import concurrent.futures

from recon_mcp.tools.dns import DNSRecon

MAX_CANDIDATES = 512    # refuse to probe more candidate subdomains than this
MAX_CONCURRENCY = 50

# A compact list of commonly-used subdomain labels.
COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "dns", "mx",
    "email", "cpanel", "autodiscover", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "remote", "blog", "shop", "store", "m", "mobile", "app",
    "apps", "gateway", "secure", "server", "host", "cloud", "cdn", "static",
    "assets", "img", "images", "media", "files", "download", "support", "help",
    "docs", "wiki", "git", "gitlab", "jenkins", "ci", "status", "monitor",
    "grafana", "kibana", "db", "sql", "backup", "intranet", "internal", "beta",
    "demo", "sandbox", "old", "new", "www2", "ads", "analytics", "auth", "sso",
    "ftp", "ssh", "proxy", "dashboard", "panel",
]


class SubdomainEnumError(ValueError):
    """Raised when an enumeration request violates the guardrails."""


def build_candidates(domain, wordlist=None):
    """Build the list of fully-qualified candidate hostnames to probe.

    `wordlist` may be a list of labels or a comma-separated string; omit it to
    use the built-in common list. Enforces the MAX_CANDIDATES cap.
    """
    if wordlist is None:
        labels = list(COMMON_SUBDOMAINS)
    else:
        items = wordlist if isinstance(wordlist, list) else str(wordlist).split(",")
        labels = []
        seen = set()
        for item in items:
            label = str(item).strip().lower().rstrip(".")
            if label and label not in seen:
                seen.add(label)
                labels.append(label)

    if not labels:
        raise SubdomainEnumError("no subdomain labels to probe")
    if len(labels) > MAX_CANDIDATES:
        raise SubdomainEnumError(
            f"{len(labels)} candidates requested; this tool probes at most "
            f"{MAX_CANDIDATES} per call"
        )
    return [f"{label}.{domain}" for label in labels]


class SubdomainEnumerator:
    """DNS-based subdomain enumerator with a concurrency cap."""

    def __init__(self, timeout=3.0, max_concurrency=MAX_CONCURRENCY):
        self.recon = DNSRecon(timeout=timeout)
        self.max_concurrency = max(1, min(int(max_concurrency), MAX_CONCURRENCY))

    def enumerate(self, domain, wordlist=None):
        """Probe candidate subdomains; return those that resolve."""
        candidates = build_candidates(domain, wordlist)

        found = []
        workers = min(self.max_concurrency, len(candidates))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._resolve, host): host for host in candidates}
            for fut in concurrent.futures.as_completed(futures):
                host = futures[fut]
                ips = fut.result()
                if ips:
                    found.append({"subdomain": host, "ips": ips})

        found.sort(key=lambda r: r["subdomain"])
        return {
            "domain": domain,
            "checked": len(candidates),
            "found_count": len(found),
            "found": found,
        }

    def _resolve(self, host):
        """Return the list of A-record IPs for host, or [] if it does not resolve."""
        resp = self.recon.dns_query(host, "A")
        if resp.get("error"):
            return []
        return [r["value"] for r in resp.get("records", []) if r.get("value")]
