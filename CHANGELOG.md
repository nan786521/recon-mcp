# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.12.0] — 2026-06-22

### Changed
- `recon_report` is now a fuller one-stop overview: alongside email/TLS/headers
  it also runs `tech_detect` (web-stack fingerprint) and a dangling-CNAME
  takeover check on the apex, all concurrently. The report gains a `tech`
  section (detected technologies + any version disclosure) and, when the apex
  is at risk, a `takeover` section — a confirmed takeover is surfaced as a
  critical issue and caps the overall grade at F. The three graded components
  (email/TLS/headers) still drive the grade otherwise; `build_report`'s new
  arguments are optional, so existing behavior is unchanged when they're absent.

## [0.11.0] — 2026-06-22

### Added
- `tech_detect` — passive web technology fingerprinting from a single HTTP GET.
  Identifies the web server, reverse proxy / CDN, WAF, programming language, web
  framework, CMS, JavaScript framework, and analytics by matching response
  headers, set cookies, the HTML body, and the meta-generator tag against a
  signature table. Disclosed versions are captured and flagged as `info`
  findings (a precise version eases known-CVE lookup). The signature matching is
  a pure function, split from the network and unit-tested offline.

## [0.10.0] — 2026-06-22

### Added
- `dns_recon`'s email analysis now also reports **MTA-STS** (`_mta-sts` TXT,
  SMTP TLS enforcement), **TLS-RPT** (`_smtp._tls` TXT, SMTP TLS failure
  reporting), **BIMI** (`default._bimi` TXT, brand logo), and **DNSSEC** (a
  DNSKEY at the apex means the zone is signed). All four are passive DNS lookups.
  They surface as graded findings (missing MTA-STS/TLS-RPT/DNSSEC are advisory
  `info`; present ones are `ok`) but, being secondary to SPF/DKIM/DMARC, do not
  move the core email letter grade. `recon_report` inherits them.

## [0.9.0] — 2026-06-22

### Added
- `subdomain_takeover` — checks one or many subdomains for a dangling-CNAME
  takeover risk. For each host it resolves the CNAME, recognizes known
  takeover-prone services (GitHub Pages, S3, Heroku, Azure, Fastly, Shopify,
  and more), fetches the page, and flags either the provider's "unclaimed
  resource" fingerprint or a CNAME target that no longer resolves. Read-only
  (DNS + one HTTP GET per host), capped at 100 hosts per call. The network and
  verdict logic are split so the assessment is unit-tested without the network.
  Pair it with `subdomain_enum` — enumerate, then check the interesting hosts.

## [0.8.4] — 2026-06-18

### Fixed
- The `initialize` handshake reported the MCP SDK's own version (e.g. `1.28.0`)
  as the server version, because FastMCP doesn't forward one. It now sets the
  package version (`__version__`, the single source of truth) on the underlying
  server, so clients see the real recon-kit-mcp version. Added a test to guard
  against an SDK change silently reverting this.

## [0.8.3] — 2026-06-18

### Fixed
- `__version__` had drifted to 0.6.0 because manual version bumps kept missing
  `__init__.py`. It now derives from the installed package metadata
  (`importlib.metadata`), so it can never drift again. The hardcoded User-Agent
  strings (previously `recon-kit-mcp/0.8`) now follow it too.
- `cookie_audit` resolved a relative redirect `Location` against the chain's
  original scheme instead of the current hop's. After an http→https upgrade, a
  subsequent relative redirect produced a wrong `http://host:443/...` URL. It
  now uses the current hop's scheme. Added unit tests for the redirect URL
  helpers, which were previously untested.

## [0.8.2] — 2026-06-18

### Fixed
- Raised the default timeouts on the two tools that depend on slow external
  bootstrap services, which made them fail out of the box: `ip_info` 8s → 20s
  (rdap.org's redirect to the authoritative RIR can take 10-15s alone) and the
  `subdomain_enum` CT source 15s → 30s (crt.sh routinely needs 20s+ for large
  domains). Caught during live verification — both now succeed at their defaults.

## [0.8.1] — 2026-06-18

### Fixed
- MCP Registry publish failed for 0.8.0 because `server.json`'s `description`
  exceeded the registry's 100-character limit. Shortened it. The PyPI 0.8.0
  package itself published fine; this release re-registers with valid metadata.

## [0.8.0] — 2026-06-18

### Added
- `subdomain_enum` gained a **Certificate Transparency** source. Pass
  `source="ct"` to query public CT logs (via crt.sh) for every name ever
  certified for the domain — fully passive, and it finds real hosts no wordlist
  would guess. `source="both"` merges DNS brute-force and CT, marking which
  source saw each host.
- `cookie_audit` — follows the redirect chain from a host (flagging any
  HTTPS→HTTP downgrade) and audits every cookie set along the way for the
  Secure, HttpOnly, and SameSite flags, with a letter grade. Cookie values are
  never returned.
- `cors_check` — probes the CORS policy with a crafted Origin and flags
  misconfigurations, the worst being a server that reflects an arbitrary Origin
  while allowing credentials (any site can read authenticated responses).
- `well_known_audit` — fetches and parses `security.txt` (RFC 9116) and
  `robots.txt`, surfacing the disclosure contact and the paths an operator asks
  crawlers to avoid.
- `ip_info` — resolves a host and enriches its IP with RDAP registry data
  (owning org, country, CIDR block, abuse contact).

## [0.7.0] — 2026-06-16

### Fixed
- `dns_recon` no longer loses large DNS answers. Queries are sent without EDNS0,
  so any response over 512 bytes was truncated by the server (TC bit) and
  silently parsed as **zero records** — breaking SPF/DKIM analysis on TXT-heavy
  domains (e.g. `google.com` returned 0 TXT records, `microsoft.com` likewise).
  Truncated answers now fall back to TCP, recovering the full record set.
- UDP queries retry on timeout (a dropped datagram no longer makes a record type
  look empty). Real negative answers (NXDOMAIN) still return immediately, so
  subdomain enumeration stays fast.

### Changed
- `tls_check` runs its independent probes (chain, protocol versions, cipher
  enumeration, negotiated cipher, compression, HSTS, OCSP) concurrently instead
  of one handshake after another; wall-clock drops to roughly the single slowest
  probe. Output is unchanged.
- `dns_recon` queries all record types concurrently, so the worst case is one
  query timeout instead of the sum of all of them (~8× faster on dead hosts).
  `recon_report` inherits both speedups.

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

[0.12.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.12.0
[0.11.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.11.0
[0.10.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.10.0
[0.9.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.9.0
[0.8.4]: https://github.com/nan786521/recon-mcp/releases/tag/v0.8.4
[0.8.3]: https://github.com/nan786521/recon-mcp/releases/tag/v0.8.3
[0.8.2]: https://github.com/nan786521/recon-mcp/releases/tag/v0.8.2
[0.8.1]: https://github.com/nan786521/recon-mcp/releases/tag/v0.8.1
[0.8.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.8.0
[0.7.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.7.0
[0.6.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.6.0
[0.5.1]: https://github.com/nan786521/recon-mcp/releases/tag/v0.5.1
[0.5.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.5.0
[0.4.1]: https://github.com/nan786521/recon-mcp/releases/tag/v0.4.1
[0.4.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.4.0
[0.3.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.3.0
[0.2.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.2.0
[0.1.1]: https://github.com/nan786521/recon-mcp/releases/tag/v0.1.1
[0.1.0]: https://github.com/nan786521/recon-mcp/releases/tag/v0.1.0
