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
| `dns_recon` | Passive DNS + WHOIS + email-security (SPF/DMARC/DKIM) lookup, with a graded email-security assessment |
| `tls_check` | SSL/TLS inspection: certificate, protocol versions, cipher suites, forward secrecy, HSTS, OCSP, known protocol vulnerabilities — graded |
| `http_headers_audit` | Audits HTTP security response headers (CSP, HSTS, X-Frame-Options, COEP/COOP/CORP, …) — graded |

Roadmap: `port_scan` (rate-limited, opt-in, authorized targets only).

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

Then ask the agent things like *"run dns_recon on example.com and tell me if its
email security is properly configured"* or *"audit the TLS and security headers
of example.com."*

## Tool reference

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

## License

[MIT](./LICENSE)
