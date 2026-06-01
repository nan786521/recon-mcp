# recon-mcp

An [MCP](https://modelcontextprotocol.io) server that gives AI coding agents —
**Claude Code, Codex, Cline, and any MCP client** — safe, structured network and
security **reconnaissance** tools.

Most MCP servers wrap CRUD APIs. `recon-mcp` instead exposes the kind of
read-only recon an engineer reaches for when investigating an asset: DNS and
WHOIS lookups today, with TLS inspection, HTTP-header auditing, and guarded port
scanning on the roadmap. Every tool returns clean JSON so the agent can reason
over the results instead of parsing console output.

> ⚠️ **Authorized use only.** These tools are for security testing of assets you
> own or have explicit written permission to assess, for CTF practice, and for
> education. Do not point them at third-party infrastructure without
> authorization. You are responsible for how you use this software.

## Status

Early / `v0.1`. Implemented tools:

| Tool | What it does |
|------|--------------|
| `dns_recon` | Passive DNS + WHOIS + email-security (SPF/DMARC/DKIM) lookup, all from public data |

Roadmap: `tls_check`, `http_headers_audit`, `port_scan` (rate-limited, opt-in).

## Install

Requires Python ≥ 3.10.

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

Add the server (stdio transport):

```bash
claude mcp add recon -- /absolute/path/to/.venv/bin/recon-mcp
```

Or add it manually to your MCP client config:

```json
{
  "mcpServers": {
    "recon": {
      "command": "/absolute/path/to/.venv/bin/recon-mcp"
    }
  }
}
```

Then ask the agent things like *"run dns_recon on example.com and tell me if its
email security is properly configured."*

## The `dns_recon` tool

```
dns_recon(domain: str, checks?: ["records"|"whois"|"email"], timeout?: float) -> dict
```

- **records** — A, AAAA, MX, NS, TXT, SOA, CNAME records
- **whois** — parsed registration fields + raw WHOIS text
- **email** — SPF, DMARC, and DKIM posture

Omit `checks` to run all three.

## License

[MIT](./LICENSE)
