# recon-mcp

**English** | [繁體中文](./README.zh-TW.md)

[![CI](https://github.com/nan786521/recon-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/nan786521/recon-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/recon-kit-mcp)](https://pypi.org/project/recon-kit-mcp/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

An [MCP](https://modelcontextprotocol.io) server that gives AI coding agents —
**Claude Code, Codex, Cline, and any MCP client** — safe, structured network and
security **reconnaissance** tools.

Most MCP servers wrap CRUD APIs. `recon-mcp` instead exposes the kind of
read-only recon an engineer reaches for when investigating an asset, and returns
clean JSON — with a graded verdict — so the agent can reason over results
instead of parsing console output.

> ⚠️ **Authorized use only.** These tools are for security testing of assets you
> own or have explicit written permission to assess, for CTF practice, and for
> education. Do not point them at third-party infrastructure without
> authorization. You are responsible for how you use this software.

## Tools

| Tool | What it does |
|------|--------------|
| `recon_report` | **Start here.** One call → DNS, TLS, and HTTP headers checked together, with an overall grade |
| `dns_recon` | DNS + WHOIS + email security (SPF/DMARC/DKIM), graded |
| `subdomain_enum` | Discover subdomains via DNS brute-force and/or Certificate Transparency logs |
| `tls_check` | Certificate, protocols, ciphers, and known TLS vulnerabilities, graded |
| `http_headers_audit` | HTTP security headers (CSP, HSTS, X-Frame-Options, …), graded |
| `cookie_audit` | Redirect chain + cookie flags (Secure / HttpOnly / SameSite), graded |
| `cors_check` | CORS policy probe — flags arbitrary-Origin reflection and wildcard misuse |
| `well_known_audit` | Fetches & parses `security.txt` (RFC 9116) and `robots.txt` |
| `ip_info` | Resolves the host and enriches its IP via RDAP (owner, country, CIDR, abuse) |
| `port_scan` | TCP port scan of one host (≤1024 ports/call), open ports + services |

## Example

Just ask your agent: *"run a security recon report on example.com."* It calls
`recon_report` once and gets a graded overview it can act on:

```json
{
  "domain": "example.com",
  "overall_grade": "F",
  "summary": "Overall posture F: email A, TLS B, headers F; 13 actionable issue(s).",
  "components": {
    "email":   { "grade": "A", "issues": [] },
    "tls":     { "grade": "B", "issues": [] },
    "headers": { "grade": "F", "issues": [
      { "severity": "high", "label": "Missing Content-Security-Policy", "detail": "CSP not set; cannot restrict resource load sources" }
    ] }
  }
}
```

Need more detail on one area? The agent can call `dns_recon`, `subdomain_enum`,
`tls_check`, `http_headers_audit`, `cookie_audit`, `cors_check`,
`well_known_audit`, `ip_info`, or `port_scan` directly.

## Install

Requires Python ≥ 3.10. Runs on Linux, macOS, and Windows (tested in CI).

**Recommended — no clone, via [uv](https://docs.astral.sh/uv/):**

```bash
uvx recon-kit-mcp
```

**Or from source (for development):**

```bash
git clone https://github.com/nan786521/recon-mcp
cd recon-mcp
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
pip install -e .
```

## Use with Claude Code

Add the server (stdio transport). With `uvx` you don't need an absolute path:

```bash
claude mcp add recon -- uvx recon-kit-mcp
```

Or add it manually to any MCP client config:

```json
{
  "mcpServers": {
    "recon": {
      "command": "uvx",
      "args": ["recon-kit-mcp"]
    }
  }
}
```

(From a source checkout, point the command at `/absolute/path/to/.venv/bin/recon-kit-mcp` instead.)

Then just ask: *"run a security recon report on example.com"* — or target one
area, e.g. *"check the email security of example.com."*

The server also ships a **`security_recon` prompt**: pick it from your client's
prompt menu and pass a domain for a guided, severity-sorted audit.

## Tool reference

### `recon_report(domain, timeout?) -> dict`

Runs DNS/email, TLS, and HTTP-header checks together and returns `overall_grade`
(as weak as the weakest component), a one-line `summary`, and `components`
(`email` / `tls` / `headers`), each with its `grade` and actionable `issues`.
Uses a fast single-handshake TLS check for speed — call `tls_check` for the full
cipher/vulnerability analysis. The best starting point; use the tools below for
raw detail.

### `dns_recon(domain, checks?, timeout?) -> dict`

- **records** — A, AAAA, MX, NS, TXT, SOA, CNAME, CAA records
- **whois** — parsed registration fields + raw WHOIS text
- **email** — SPF, DMARC, and DKIM posture, plus a graded `assessment`
  (letter grade A–F, a summary, and per-check findings with severity and a
  recommended fix)

`checks` is any subset of `["records", "whois", "email"]`; omit it to run all.

### `subdomain_enum(domain, wordlist?, source="dns", timeout?) -> dict`

Discovers subdomains from two complementary sources:
- `source="dns"` (default) — resolves candidate labels via DNS. `wordlist` is
  comma-separated labels (`"www,api,dev"`); omit it for a built-in common list.
  Capped at 512 candidates per call. Returns resolved `ips`.
- `source="ct"` — queries public **Certificate Transparency** logs (crt.sh) for
  every name ever certified for the domain. Fully passive; finds real hosts no
  wordlist would guess.
- `source="both"` — runs both and merges, recording which source(s) saw each host.

Returns `sources`, `found_count`, and `found` (each with `subdomain`, the
`sources` that saw it, and `ips` when resolved).

### `tls_check(host, port=443, timeout?) -> dict`

Returns `grade`, `certificate` (validity / expiry / key algorithm),
`protocols` (flags legacy SSLv3 / TLS 1.0 / 1.1), cipher info,
`forward_secrecy`, `hsts`, `vulnerabilities` (each with a `vulnerable` flag),
and a `findings` list.

### `http_headers_audit(host, port?, use_ssl=True, timeout?) -> dict`

Returns `grade`, `score`, the observed security headers, and a `findings`
list with a recommendation per header. Defaults to HTTPS (port 443).

### `cookie_audit(host, port?, use_ssl=True, timeout?) -> dict`

Follows the redirect chain from the host (capped at 10 hops, flagging any
HTTPS→HTTP downgrade) and audits every `Set-Cookie` seen for the `Secure`,
`HttpOnly`, and `SameSite` flags. Returns `redirect_chain`, `final_url`,
`cookies` (flags only — values are never returned), `cookie_grade`,
`cookie_score`, and a `findings` list.

### `cors_check(host, port?, use_ssl=True, timeout?) -> dict`

Sends one GET with an untrusted `Origin` and inspects the
`Access-Control-Allow-Origin` / `-Allow-Credentials` response. Reflecting an
arbitrary Origin **with** credentials is high severity (any site can read
authenticated responses); a wildcard or trusted `null` origin are lesser issues.
Returns `acao`, `allows_credentials`, `reflects_origin`, `wildcard`, `severity`,
and `findings`.

### `well_known_audit(host, timeout?) -> dict`

Fetches and parses `security.txt` (RFC 9116, tried at `/.well-known/` then the
legacy path) and `robots.txt`. Returns `security_txt` (parsed fields, structural
`issues`, `location`) and `robots_txt` (`sitemaps`, `disallow`/`allow` paths,
`user_agents`), each with a `present` flag.

### `ip_info(host, timeout?) -> dict`

Resolves the host's IP and looks it up in the public **RDAP** registry (via
rdap.org's bootstrap to the right RIR). Returns `ip` and `rdap` (`handle`,
`name`, `country`, `cidr`, `org`, `abuse_email`).

### `port_scan(host, ports?, timeout?) -> dict`

TCP connect scan of a **single** host. `ports` is a string — `"22,80,443"`, a
range `"1-1024"`, or a mix — and omitting it scans a built-in common-port set.
Hard-capped at 1024 ports per call (single-host recon, not mass scanning).
Returns `host`, `ip`, `scanned`, `open_count`, and `open_ports` (port +
service). Scan only hosts you are authorized to assess.

## License

[MIT](./LICENSE)

<!-- mcp-name: io.github.nan786521/recon-kit-mcp -->
