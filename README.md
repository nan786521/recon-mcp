# recon-mcp

**English** | [繁體中文](./README.zh-TW.md)

[![CI](https://github.com/nan786521/recon-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/nan786521/recon-mcp/actions/workflows/ci.yml)
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
| `tls_check` | Certificate, protocols, ciphers, and known TLS vulnerabilities, graded |
| `http_headers_audit` | HTTP security headers (CSP, HSTS, X-Frame-Options, …), graded |
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

Need more detail on one area? The agent can call `dns_recon`, `tls_check`,
`http_headers_audit`, or `port_scan` directly.

## Install

Requires Python ≥ 3.10.

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

## Tool reference

### `recon_report(domain, timeout?) -> dict`

Runs DNS/email, TLS, and HTTP-header checks together and returns `overall_grade`
(as weak as the weakest component), a one-line `summary`, and `components`
(`email` / `tls` / `headers`), each with its `grade` and actionable `issues`.
The best starting point; use the tools below for raw detail.

### `dns_recon(domain, checks?, timeout?) -> dict`

- **records** — A, AAAA, MX, NS, TXT, SOA, CNAME records
- **whois** — parsed registration fields + raw WHOIS text
- **email** — SPF, DMARC, and DKIM posture, plus a graded `assessment`
  (letter grade A–F, a summary, and per-check findings with severity and a
  recommended fix)

`checks` is any subset of `["records", "whois", "email"]`; omit it to run all.

### `tls_check(host, port=443, timeout?) -> dict`

Returns `grade`, `certificate` (validity / expiry / key algorithm),
`protocols` (flags legacy SSLv3 / TLS 1.0 / 1.1), cipher info,
`forward_secrecy`, `hsts`, `vulnerabilities` (each with a `vulnerable` flag),
and a `findings` list.

### `http_headers_audit(host, port?, use_ssl=True, timeout?) -> dict`

Returns `grade`, `score`, the observed security headers, and a `findings`
list with a recommendation per header. Defaults to HTTPS (port 443).

### `port_scan(host, ports?, timeout?) -> dict`

TCP connect scan of a **single** host. `ports` is a string — `"22,80,443"`, a
range `"1-1024"`, or a mix — and omitting it scans a built-in common-port set.
Hard-capped at 1024 ports per call (single-host recon, not mass scanning).
Returns `host`, `ip`, `scanned`, `open_count`, and `open_ports` (port +
service). Scan only hosts you are authorized to assess.

## License

[MIT](./LICENSE)

<!-- mcp-name: io.github.nan786521/recon-kit-mcp -->
