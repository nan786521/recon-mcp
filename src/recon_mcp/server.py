"""recon-mcp server entry point.

Exposes network & security reconnaissance tools to MCP clients
(Claude Code, Codex, Cline, ...) over stdio.

Intended for AUTHORIZED security testing, CTF, and education only. Only run
these tools against assets you own or have explicit permission to assess.
"""

from mcp.server.fastmcp import FastMCP

from recon_mcp.tools.dns import DNSRecon

mcp = FastMCP("recon-mcp")


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


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
