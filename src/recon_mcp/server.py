"""recon-mcp server entry point.

Exposes network & security reconnaissance tools to MCP clients
(Claude Code, Codex, Cline, ...) over stdio.

Intended for AUTHORIZED security testing, CTF, and education only. Only run
these tools against assets you own or have explicit permission to assess.
"""

import concurrent.futures
import functools

from mcp.server.fastmcp import FastMCP

from recon_mcp import __version__
from recon_mcp.tools.dns import DNSRecon
from recon_mcp.tools.tls import SSLAnalyzer, quick_tls_check
from recon_mcp.tools.http_headers import HTTPHeadersAnalyzer
from recon_mcp.tools.portscan import PortScanner, PortScanError
from recon_mcp.tools.subdomain import SubdomainEnumerator, SubdomainEnumError, merge_subdomain_sources
from recon_mcp.tools.ct import query_crt_sh
from recon_mcp.tools.wellknown import fetch_well_known
from recon_mcp.tools.cookies import cookie_audit as _cookie_audit
from recon_mcp.tools.rdap import ip_info as _ip_info
from recon_mcp.tools.cors import cors_check as _cors_check
from recon_mcp.tools.takeover import check_takeovers
from recon_mcp.tools.tech import tech_detect as _tech_detect
from recon_mcp.tools.report import build_report
from recon_mcp.util import normalize_host

mcp = FastMCP(
    "recon-mcp",
    instructions=(
        "recon-kit-mcp provides read-only network & security reconnaissance tools "
        "for a single target. Tools: recon_report (one-call DNS+TLS+headers overview "
        "with an overall grade), dns_recon, subdomain_enum (DNS brute-force and/or "
        "Certificate Transparency logs), subdomain_takeover (dangling-CNAME hijack "
        "risk), tls_check, http_headers_audit, cookie_audit "
        "(redirect chain + cookie flags), cors_check, tech_detect (web stack "
        "fingerprint), well_known_audit "
        "(security.txt + robots.txt), ip_info (RDAP ownership), and port_scan. Most "
        "return structured JSON with a letter grade — start with recon_report for the "
        "full picture. Only run these against assets the user owns or is explicitly "
        "authorized to assess (pentest engagement, CTF, or education); if "
        "authorization is unclear, ask before scanning."
    ),
    website_url="https://github.com/nan786521/recon-mcp",
)

# FastMCP doesn't forward a server version, so it defaults to the MCP SDK's
# version in the initialize handshake. Set ours on the low-level server so
# clients see the package version (single source of truth from __init__).
mcp._mcp_server.version = __version__


def _safe_tool(fn):
    """Ensure a tool always returns a structured result: on any unexpected
    exception, return {"error": ...} instead of propagating. functools.wraps
    preserves the signature so FastMCP still builds the correct input schema."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
    return wrapper


@mcp.tool()
@_safe_tool
def dns_recon(
    domain: str,
    checks: list[str] | None = None,
    timeout: float = 5.0,
) -> dict:
    """Passive DNS/WHOIS reconnaissance for a domain using only public data.

    Args:
        domain: The domain to inspect, e.g. "example.com".
        checks: Which checks to run. Any of "records", "whois", "email".
            Defaults to all three when omitted.
        timeout: Per-query network timeout in seconds.

    Returns:
        A structured dict keyed by the requested checks:
          - records: DNS records grouped by type (A, AAAA, MX, NS, TXT, SOA, CNAME)
          - whois: parsed registration fields plus the raw WHOIS text
          - email: SPF / DMARC / DKIM posture, plus advisory MTA-STS, TLS-RPT,
            BIMI, and DNSSEC signals, with a graded assessment
    """
    domain = normalize_host(domain)
    selected = checks or ["records", "whois", "email"]
    recon = DNSRecon(timeout=timeout)
    result: dict = {"domain": domain}

    if "records" in selected:
        result["records"] = recon.dns_query_all(domain).get("records", {})
    if "whois" in selected:
        result["whois"] = recon.whois_lookup(domain)
    if "email" in selected:
        result["email"] = recon.analyze_email_security(domain)

    return result


@mcp.tool()
@_safe_tool
def tls_check(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Inspect a host's SSL/TLS configuration and grade it.

    Checks the certificate (validity, expiry, key algorithm), supported
    protocol versions (flagging legacy SSLv3/TLS 1.0/1.1), cipher suites and
    forward secrecy, TLS compression, HSTS, OCSP stapling, and known protocol
    vulnerabilities. Returns a letter grade plus structured findings.

    Args:
        host: Hostname or IP to inspect, e.g. "example.com".
        port: TLS port (default 443).
        timeout: Per-connection network timeout in seconds.

    Returns:
        A structured dict with: grade, certificate, protocols, cipher info,
        forward_secrecy, hsts, vulnerabilities, and a findings list.
    """
    return SSLAnalyzer(timeout=timeout).analyze(normalize_host(host), port=port)


@mcp.tool()
@_safe_tool
def http_headers_audit(
    host: str,
    port: int | None = None,
    use_ssl: bool = True,
    timeout: float = 5.0,
) -> dict:
    """Audit a web server's HTTP security response headers and grade them.

    Inspects headers such as Content-Security-Policy, Strict-Transport-Security
    (HSTS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, and the COEP/COOP/CORP isolation headers. Returns a
    letter grade plus per-header findings with recommendations.

    Args:
        host: Hostname or IP to audit, e.g. "example.com".
        port: TCP port. Defaults to 443 when use_ssl is True, else 80.
        use_ssl: Connect over HTTPS (default True).
        timeout: Per-connection network timeout in seconds.

    Returns:
        A structured dict with: grade, score, the observed headers, and a
        findings list.
    """
    if port is None:
        port = 443 if use_ssl else 80
    return HTTPHeadersAnalyzer(timeout=timeout).analyze(normalize_host(host), port=port, use_ssl=use_ssl)


@mcp.tool()
@_safe_tool
def port_scan(
    host: str,
    ports: str | None = None,
    timeout: float = 1.0,
) -> dict:
    """TCP connect scan of a single host, reporting open ports and services.

    Scoped to a single host with a hard cap of 1024 ports per call — it is recon
    for one authorized target, not a mass scanner. Only scan hosts you own or
    have explicit permission to assess.

    Args:
        host: Hostname or IP to scan, e.g. "example.com".
        ports: Ports to scan as a string: "22,80,443", a range "1-1024", or a
            mix "1-100,443,8080". Omit to scan a built-in set of common ports.
        timeout: Per-port connection timeout in seconds.

    Returns:
        A dict with: host, ip, scanned (count), open_count, and open_ports
        (each with port and service). Returns an error field on bad input or
        DNS failure.
    """
    try:
        return PortScanner(timeout=timeout).scan(normalize_host(host), ports=ports)
    except PortScanError as e:
        return {"host": host, "error": str(e)}


@mcp.tool()
@_safe_tool
def subdomain_enum(
    domain: str,
    wordlist: str | None = None,
    source: str = "dns",
    timeout: float = 3.0,
) -> dict:
    """Discover subdomains of a domain via DNS brute-force and/or CT logs.

    Two complementary sources:
      - "dns": probe candidate labels with DNS A lookups (active but light,
        capped at 512 candidates). Returns resolved IPs.
      - "ct": query public Certificate Transparency logs (crt.sh) for every
        name ever certified for the domain — fully passive, and finds real
        hosts no wordlist would guess.
      - "both": run both and merge, marking which source saw each host.

    Enumerate only domains you are authorized to assess.

    Args:
        domain: The base domain, e.g. "example.com".
        wordlist: Comma-separated labels for the DNS source (e.g. "www,api,dev").
            Omit to use a built-in list of common labels. Ignored for "ct".
        source: "dns" (default), "ct", or "both".
        timeout: Per-query DNS timeout in seconds (the CT query uses its own
            longer timeout since crt.sh can be slow).

    Returns:
        A dict with domain, sources, found_count, and found (each with
        subdomain, the source(s) that saw it, and resolved ips when known).
    """
    domain = normalize_host(domain)
    src = (source or "dns").strip().lower()
    if src not in ("dns", "ct", "both"):
        return {"domain": domain, "error": "source must be one of: dns, ct, both"}

    dns_result = ct_result = None
    if src in ("dns", "both"):
        try:
            dns_result = SubdomainEnumerator(timeout=timeout).enumerate(domain, wordlist=wordlist)
        except SubdomainEnumError as e:
            dns_result = {"error": str(e)}
    if src in ("ct", "both"):
        ct_result = query_crt_sh(domain)

    return merge_subdomain_sources(domain, dns_result, ct_result)


@mcp.tool()
@_safe_tool
def well_known_audit(host: str, timeout: float = 5.0) -> dict:
    """Fetch and parse a host's security.txt and robots.txt.

    Both are standard public files. security.txt (RFC 9116) gives the
    vulnerability-disclosure contact, policy, and encryption key; its absence is
    itself a finding for a security-conscious site. robots.txt lists the paths
    the operator asks crawlers to skip — frequently admin/internal areas worth
    noting during recon.

    Args:
        host: Hostname to inspect, e.g. "example.com".
        timeout: Per-request network timeout in seconds.

    Returns:
        A dict with host, security_txt (present flag, parsed fields, structural
        issues, location), and robots_txt (present flag, sitemaps, disallow/allow
        paths, user_agents).
    """
    return fetch_well_known(normalize_host(host), timeout=timeout)


@mcp.tool()
@_safe_tool
def cookie_audit(host: str, port: int | None = None, use_ssl: bool = True,
                 timeout: float = 5.0) -> dict:
    """Follow a host's redirect chain and audit the cookies it sets.

    Walks each redirect hop (capped at 10) from the host, recording status and
    Location and flagging any HTTPS->HTTP downgrade. Every Set-Cookie seen along
    the way is checked for the Secure, HttpOnly, and SameSite flags and graded.
    Cookie values are never returned (they may be secrets).

    Args:
        host: Hostname to inspect, e.g. "example.com".
        port: TCP port. Defaults to 443 when use_ssl is True, else 80.
        use_ssl: Start the chain over HTTPS (default True).
        timeout: Per-hop network timeout in seconds.

    Returns:
        A dict with host, redirect_chain, final_url, cookies (flags only),
        cookie_grade, cookie_score, and a findings list.
    """
    return _cookie_audit(normalize_host(host), port=port, use_ssl=use_ssl, timeout=timeout)


@mcp.tool()
@_safe_tool
def ip_info(host: str, timeout: float = 20.0) -> dict:
    """Resolve a host and enrich its IP with RDAP registry ownership data.

    Looks up the IP in the public RDAP registry (via rdap.org's bootstrap to the
    right RIR) and reports who owns the address block, the country, the CIDR
    range, and the abuse-reporting contact. Read-only registry query; nothing is
    sent to the target.

    Args:
        host: Hostname or IP, e.g. "example.com".
        timeout: Per-request network timeout in seconds. Defaults high because
            rdap.org's bootstrap redirect can take 10-15s on its own.

    Returns:
        A dict with host, ip, and rdap (handle, name, country, cidr, org,
        abuse_email). An unresolved host or RDAP failure is reported via an
        error field.
    """
    return _ip_info(normalize_host(host), timeout=timeout)


@mcp.tool()
@_safe_tool
def cors_check(host: str, port: int | None = None, use_ssl: bool = True,
               timeout: float = 5.0) -> dict:
    """Probe a host's CORS policy with a crafted Origin and flag misconfigurations.

    Sends one GET with an untrusted Origin header and inspects the
    Access-Control-Allow-Origin / -Allow-Credentials response. Reflecting an
    arbitrary Origin while allowing credentials is high severity (any site can
    read authenticated responses); a wildcard or a trusted 'null' origin are
    lesser issues. One request, read-only.

    Args:
        host: Hostname to test, e.g. "example.com".
        port: TCP port. Defaults to 443 when use_ssl is True, else 80.
        use_ssl: Connect over HTTPS (default True).
        timeout: Network timeout in seconds.

    Returns:
        A dict with host, port, test_origin, acao, allows_credentials,
        reflects_origin, wildcard, severity, and a findings list.
    """
    return _cors_check(normalize_host(host), port=port, use_ssl=use_ssl, timeout=timeout)


@mcp.tool()
@_safe_tool
def subdomain_takeover(hosts: str, timeout: float = 6.0) -> dict:
    """Check subdomains for a dangling-CNAME takeover risk.

    A subdomain is takeover-prone when it CNAMEs to a third-party service
    (GitHub Pages, S3, Heroku, Azure, ...) whose resource was deleted or never
    claimed — anyone who registers that resource then controls the subdomain.
    For each host this resolves the CNAME, recognizes known takeover-prone
    services, fetches the page, and flags the provider's "unclaimed resource"
    fingerprint and/or a CNAME target that no longer resolves.

    Read-only recon (DNS lookups + one HTTP GET per host). Pair it with
    subdomain_enum: enumerate first, then pass the interesting hosts here. Only
    check domains you are authorized to assess.

    Args:
        hosts: One hostname or a comma-separated list, e.g.
            "blog.example.com,shop.example.com". Capped at 100 per call.
        timeout: Per-probe network timeout in seconds.

    Returns:
        A dict with checked, vulnerable_count, and results (one entry per host
        with host, cname, service, status, vulnerable, severity, and detail).
        status is one of not_applicable, not_vulnerable, potential,
        dangling_cname, or vulnerable.
    """
    return check_takeovers([h for h in (hosts or "").split(",") if h.strip()], timeout=timeout)


@mcp.tool()
@_safe_tool
def tech_detect(host: str, port: int | None = None, use_ssl: bool = True,
                timeout: float = 10.0) -> dict:
    """Fingerprint the technology stack behind a website from one HTTP GET.

    Passively identifies the web server, reverse proxy / CDN, WAF, programming
    language, web framework, CMS, JavaScript framework, and analytics by matching
    response headers, set cookies, the HTML body, and the meta-generator tag
    against a signature table. Disclosed versions are captured and flagged
    (a precise version eases known-CVE lookup). One read-only HTTP GET.

    Args:
        host: Hostname to fingerprint, e.g. "example.com".
        port: TCP port. Defaults to 443 when use_ssl is True, else 80.
        use_ssl: Connect over HTTPS (default True).
        timeout: Network timeout in seconds.

    Returns:
        A dict with host, url, status, technology_count, technologies (each with
        name, category, version when known, and evidence), and a findings list
        noting any version disclosure. An error field on fetch failure.
    """
    return _tech_detect(normalize_host(host), port=port, use_ssl=use_ssl, timeout=timeout)


@mcp.tool()
@_safe_tool
def recon_report(domain: str, timeout: float = 5.0) -> dict:
    """One-shot security posture report for a domain.

    Runs DNS/email, TLS, and HTTP-header recon concurrently and returns a
    single graded overview: an overall grade (as weak as the weakest
    component), each component's grade, and the actionable issues found. Use
    this for a quick full picture; call the individual tools for raw detail.

    Args:
        domain: The domain to assess, e.g. "example.com".
        timeout: Per-connection network timeout in seconds.

    Returns:
        A dict with domain, ip, overall_grade, summary, and components
        (email / tls / headers), each with a grade and a list of issues. A
        component that errors is reported without breaking the rest.
    """
    domain = normalize_host(domain)
    recon = DNSRecon(timeout=timeout)

    def _safe(fn):
        try:
            return fn()
        except Exception as e:  # never let one component sink the report
            return {"error": str(e)}

    # A quick single-handshake TLS check keeps the report fast; tls_check does the
    # full analysis (cipher enumeration, vulnerabilities) on demand.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        f_email = pool.submit(_safe, lambda: recon.analyze_email_security(domain))
        f_records = pool.submit(_safe, lambda: recon.dns_query_all(domain))
        f_tls = pool.submit(_safe, lambda: quick_tls_check(domain, timeout=timeout))
        f_headers = pool.submit(_safe, lambda: HTTPHeadersAnalyzer(timeout=timeout).analyze(domain, port=443, use_ssl=True))

        dns_result = {"email": {"assessment": (f_email.result() or {}).get("assessment", {})},
                      "records": (f_records.result() or {}).get("records", {})}
        tls_result = f_tls.result()
        headers_result = f_headers.result()

    return build_report(domain, dns_result, tls_result, headers_result)


@mcp.prompt(title="Security recon report")
def security_recon(domain: str) -> str:
    """Guided full security reconnaissance of a domain, summarized by severity."""
    return (
        f"Run a security reconnaissance report on {domain}, then summarize it for me.\n\n"
        f"1. Call `recon_report` on {domain} to get the overall posture.\n"
        f"2. Optionally run `subdomain_enum` to see exposed subdomains, then "
        f"`subdomain_takeover` on any that look interesting to flag dangling-CNAME "
        f"hijack risks.\n"
        f"3. Report the overall grade and each component's grade (email, TLS, headers), "
        f"then list the top issues by severity, each with a concrete fix.\n\n"
        f"Only proceed if I am authorized to assess {domain}."
    )


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
