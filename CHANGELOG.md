# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

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

[0.4.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.4.0
[0.3.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.3.0
[0.2.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.2.0
[0.1.1]: https://github.com/nan786521/recon-mcp/releases/tag/v0.1.1
[0.1.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.1.0
