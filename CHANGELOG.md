# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.6.0] — 2026-06-01

### Added
- `dns_recon` now reports **CAA** records (relevant to certificate issuance).
- ruff linting in CI; CI now also runs on Windows and macOS.

### Changed
- `recon_report` uses a fast single-handshake TLS check, so the overview no
  longer pays for full cipher enumeration (much faster on slow/dead hosts).
  `tls_check` still does the full analysis.
- Every tool now returns a consistent `{"error": ...}` on unexpected failures
  instead of propagating, while keeping its input schema intact.

## [0.5.1] — 2026-06-01

### Changed
- All tools now normalize the target input: a URL, `host:port`, trailing dot, or
  mixed case is accepted and reduced to a bare hostname (e.g.
  `https://Example.com/path` → `example.com`). IPv6 literals are preserved.

## [0.5.0] — 2026-06-01

### Added
- `security_recon` MCP prompt — a guided "audit this domain" workflow that
  clients can offer from their prompt menu, so users don't need to know tool
  names.

## [0.4.1] — 2026-06-01

### Added
- Server-level `instructions` so any MCP client is told what the tools do, to
  start with `recon_report`, and to only scan authorized targets. Added the
  repository `website_url` to server metadata.

## [0.4.0] — 2026-06-01

### Added
- `subdomain_enum` — DNS-based subdomain discovery using a built-in or custom
  wordlist, capped at 512 candidates per call.

## [0.3.0] — 2026-06-01

### Added
- `recon_report` — one call runs DNS/email, TLS, and HTTP-header checks together
  and returns an overall grade (as weak as the weakest component), a summary, and
  per-component actionable issues.

## [0.2.0] — 2026-06-01

### Added
- `port_scan` — single-host TCP connect scan reporting open ports and services.
  Guardrails: capped at 1024 ports per call, single host only.

## [0.1.1] — 2026-06-01

### Added
- Published to the official MCP Registry (`io.github.nan786521/recon-kit-mcp`)
  via GitHub Actions OIDC.

## [0.1.0] — 2026-06-01

### Added
- Initial release with `dns_recon`, `tls_check`, and `http_headers_audit`, each
  returning structured JSON with a graded verdict.
- Published to PyPI as `recon-kit-mcp`.

[0.6.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.6.0
[0.5.1]: https://github.com/nan786521/recon-mcp/releases/tag/v0.5.1
[0.5.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.5.0
[0.4.1]: https://github.com/nan786521/recon-mcp/releases/tag/v0.4.1
[0.4.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.4.0
[0.3.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.3.0
[0.2.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.2.0
[0.1.1]: https://github.com/nan786521/recon-mcp/releases/tag/v0.1.1
[0.1.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.1.0
