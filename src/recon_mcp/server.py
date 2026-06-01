"""recon-mcp server entry point.

Exposes network & security reconnaissance tools to MCP clients
(Claude Code, Codex, Cline, ...) over stdio.

Intended for AUTHORIZED security testing, CTF, and education only. Only run
these tools against assets you own or have explicit permission to assess.
"""

import concurrent.futures

from mcp.server.fastmcp import FastMCP

from recon_mcp.tools.dns import DNSRecon
from recon_mcp.tools.tls import SSLAnalyzer
from recon_mcp.tools.http_headers import HTTPHeadersAnalyzer
from recon_mcp.tools.portscan import PortScanner, PortScanError
from recon_mcp.tools.subdomain import SubdomainEnumerator, SubdomainEnumError
from recon_mcp.tools.report import build_report

mcp = FastMCP(
    "recon-mcp",
    instructions=(
        "recon-kit-mcp provides read-only network & security reconnaissance tools "
        "for a single target. Tools: recon_report (one-call DNS+TLS+headers overview "
        "with an overall grade), dns_recon, subdomain_enum, tls_check, "
        "http_headers_audit, and port_scan. Each returns structured JSON with a "
        "letter grade — start with recon_report for the full picture. "
        "Only run these against assets the user owns or is explicitly authorized to "
        "assess (pentest engagement, CTF, or education); if authorization is unclear, "
        "ask before scanning."
    ),
    website_url="https://github.com/nan786521/recon-mcp",
)


@mcp.tool()
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
          - email: SPF / DMARC / DKIM posture
    """
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
    return SSLAnalyzer(timeout=timeout).analyze(host, port=port)


@mcp.tool()
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
    return HTTPHeadersAnalyzer(timeout=timeout).analyze(host, port=port, use_ssl=use_ssl)


@mcp.tool()
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
        return PortScanner(timeout=timeout).scan(host, ports=ports)
    except PortScanError as e:
        return {"host": host, "error": str(e)}


@mcp.tool()
def subdomain_enum(
    domain: str,
    wordlist: str | None = None,
    timeout: float = 3.0,
) -> dict:
    """Discover subdomains of a domain via DNS resolution.

    Probes candidate subdomain labels against the domain and returns those that
    resolve. Passive recon (ordinary DNS A lookups), capped at 512 candidates
    per call. Enumerate only domains you are authorized to assess.

    Args:
        domain: The base domain, e.g. "example.com".
        wordlist: Comma-separated subdomain labels to try (e.g. "www,api,dev").
            Omit to use a built-in list of common labels.
        timeout: Per-query DNS timeout in seconds.

    Returns:
        A dict with domain, checked (count), found_count, and found (each with
        subdomain and its resolved ips).
    """
    try:
        return SubdomainEnumerator(timeout=timeout).enumerate(domain, wordlist=wordlist)
    except SubdomainEnumError as e:
        return {"domain": domain, "error": str(e)}


@mcp.tool()
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
    def _safe(fn):
        try:
            return fn()
        except Exception as e:  # never let one component sink the report
            return {"error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_dns = pool.submit(_safe, lambda: DNSRecon(timeout=timeout).analyze_email_security(domain))
        f_records = pool.submit(_safe, lambda: DNSRecon(timeout=timeout).dns_query_all(domain))
        f_tls = pool.submit(_safe, lambda: SSLAnalyzer(timeout=timeout).analyze(domain))
        f_headers = pool.submit(_safe, lambda: HTTPHeadersAnalyzer(timeout=timeout).analyze(domain, port=443, use_ssl=True))

        dns_result = {"email": {"assessment": (f_dns.result() or {}).get("assessment", {})},
                      "records": (f_records.result() or {}).get("records", {})}
        tls_result = f_tls.result()
        headers_result = f_headers.result()

    return build_report(domain, dns_result, tls_result, headers_result)


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
