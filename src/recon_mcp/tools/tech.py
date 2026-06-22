"""Web technology fingerprinting — passive, pure standard library.

Identifies the technology stack behind a website from a single HTTP(S) GET:
the web server, reverse proxy / CDN, WAF, programming language, web framework,
CMS, JavaScript framework, and analytics — by matching response headers, set
cookies, the HTML body, and the ``<meta name="generator">`` tag against a
signature table. Where a version is exposed it is captured and flagged, since a
disclosed version narrows an attacker's search for known CVEs.

It is read-only recon — one HTTP GET. The signature matching (``detect``) is a
pure function over (headers, body), split from the network so it is easy to test
offline. Authorized use only.
"""

import re

from recon_mcp.util import http_get, normalize_host

# Header signatures. Each matches when `pattern` (lowercased) is a substring of
# the named response header's value; `version_re` (optional) is then searched in
# the original header value to extract a version.
HEADER_SIGS = [
    {"name": "nginx", "category": "Web Server", "header": "server", "pattern": "nginx", "version_re": r"nginx/([\d.]+)"},
    {"name": "Apache", "category": "Web Server", "header": "server", "pattern": "apache", "version_re": r"apache/([\d.]+)"},
    {"name": "Microsoft IIS", "category": "Web Server", "header": "server", "pattern": "microsoft-iis", "version_re": r"iis/([\d.]+)"},
    {"name": "LiteSpeed", "category": "Web Server", "header": "server", "pattern": "litespeed"},
    {"name": "OpenResty", "category": "Web Server", "header": "server", "pattern": "openresty", "version_re": r"openresty/([\d.]+)"},
    {"name": "Caddy", "category": "Web Server", "header": "server", "pattern": "caddy"},
    {"name": "Google Frontend", "category": "Web Server", "header": "server", "pattern": "gws"},
    {"name": "Google Frontend", "category": "Web Server", "header": "server", "pattern": "gse"},

    {"name": "PHP", "category": "Programming Language", "header": "x-powered-by", "pattern": "php", "version_re": r"php/([\d.]+)"},
    {"name": "ASP.NET", "category": "Web Framework", "header": "x-powered-by", "pattern": "asp.net"},
    {"name": "ASP.NET", "category": "Web Framework", "header": "x-aspnet-version", "pattern": "", "version_re": r"([\d.]+)"},
    {"name": "Express", "category": "Web Framework", "header": "x-powered-by", "pattern": "express"},
    {"name": "Next.js", "category": "Web Framework", "header": "x-powered-by", "pattern": "next.js"},
    {"name": "Phusion Passenger", "category": "Web Framework", "header": "x-powered-by", "pattern": "passenger"},

    {"name": "Drupal", "category": "CMS", "header": "x-generator", "pattern": "drupal"},
    {"name": "Drupal", "category": "CMS", "header": "x-drupal-cache", "pattern": ""},
    {"name": "Shopify", "category": "CMS", "header": "x-shopid", "pattern": ""},
    {"name": "Shopify", "category": "CMS", "header": "x-shopify-stage", "pattern": ""},
    {"name": "Wix", "category": "CMS", "header": "x-wix-request-id", "pattern": ""},

    {"name": "Cloudflare", "category": "CDN", "header": "server", "pattern": "cloudflare"},
    {"name": "Cloudflare", "category": "CDN", "header": "cf-ray", "pattern": ""},
    {"name": "Amazon CloudFront", "category": "CDN", "header": "x-amz-cf-id", "pattern": ""},
    {"name": "Amazon CloudFront", "category": "CDN", "header": "via", "pattern": "cloudfront"},
    {"name": "Fastly", "category": "CDN", "header": "x-fastly-request-id", "pattern": ""},
    {"name": "Fastly", "category": "CDN", "header": "x-served-by", "pattern": "cache-"},
    {"name": "Akamai", "category": "CDN", "header": "x-akamai-transformed", "pattern": ""},
    {"name": "Varnish", "category": "CDN", "header": "x-varnish", "pattern": ""},
    {"name": "Vercel", "category": "CDN", "header": "x-vercel-id", "pattern": ""},
    {"name": "Netlify", "category": "CDN", "header": "x-nf-request-id", "pattern": ""},
    {"name": "GitHub Pages", "category": "CDN", "header": "x-github-request-id", "pattern": ""},

    {"name": "Sucuri", "category": "WAF", "header": "x-sucuri-id", "pattern": ""},
    {"name": "Imperva Incapsula", "category": "WAF", "header": "x-iinfo", "pattern": ""},
    {"name": "AWS ELB", "category": "Load Balancer", "header": "server", "pattern": "awselb"},

    {"name": "Jenkins", "category": "CI/CD", "header": "x-jenkins", "pattern": "", "version_re": r"([\d.]+)"},
]

# Cookie-name signatures (the cookie name, lowercased, must appear in Set-Cookie).
COOKIE_SIGS = [
    {"name": "PHP", "category": "Programming Language", "cookie": "phpsessid"},
    {"name": "ASP.NET", "category": "Web Framework", "cookie": "asp.net_sessionid"},
    {"name": "ASP.NET", "category": "Web Framework", "cookie": ".aspxauth"},
    {"name": "Java", "category": "Programming Language", "cookie": "jsessionid"},
    {"name": "Laravel", "category": "Web Framework", "cookie": "laravel_session"},
    {"name": "CodeIgniter", "category": "Web Framework", "cookie": "ci_session"},
    {"name": "Django", "category": "Web Framework", "cookie": "csrftoken"},
    {"name": "Ruby on Rails", "category": "Web Framework", "cookie": "_rails"},
    {"name": "WordPress", "category": "CMS", "cookie": "wordpress_"},
    {"name": "Shopify", "category": "CMS", "cookie": "_shopify_"},
    {"name": "Imperva Incapsula", "category": "WAF", "cookie": "incap_ses_"},
    {"name": "Imperva Incapsula", "category": "WAF", "cookie": "visid_incap_"},
    {"name": "F5 BIG-IP", "category": "Load Balancer", "cookie": "bigipserver"},
    {"name": "AWS ELB", "category": "Load Balancer", "cookie": "awsalb"},
]

# Body (HTML) signatures. Matches when any pattern (lowercased) is in the body.
BODY_SIGS = [
    {"name": "WordPress", "category": "CMS", "patterns": ["/wp-content/", "/wp-includes/"]},
    {"name": "Drupal", "category": "CMS", "patterns": ["drupal.settings", "/sites/default/files", "drupal-"]},
    {"name": "Joomla", "category": "CMS", "patterns": ["/media/jui/", "/media/system/js/", "joomla!"]},
    {"name": "Magento", "category": "CMS", "patterns": ["mage.cookies", "/skin/frontend/", "magento"]},
    {"name": "Shopify", "category": "CMS", "patterns": ["cdn.shopify.com", "shopify.theme"]},
    {"name": "Wix", "category": "CMS", "patterns": ["static.wixstatic.com", "wix.com"]},
    {"name": "Squarespace", "category": "CMS", "patterns": ["static.squarespace.com", "squarespace.com"]},

    {"name": "React", "category": "JavaScript Framework", "patterns": ["data-reactroot", "react-dom", "_reactlistening"]},
    {"name": "Next.js", "category": "JavaScript Framework", "patterns": ["__next_data__", "/_next/static"]},
    {"name": "Nuxt.js", "category": "JavaScript Framework", "patterns": ["__nuxt__", "/_nuxt/"]},
    {"name": "Vue.js", "category": "JavaScript Framework", "patterns": ["data-v-app", "vue.js"]},
    {"name": "Angular", "category": "JavaScript Framework", "patterns": ["ng-version", "ng-app", "_nghost"]},
    {"name": "Gatsby", "category": "JavaScript Framework", "patterns": ["___gatsby", "/page-data/"]},
    {"name": "jQuery", "category": "JavaScript Library", "patterns": ["jquery"], "version_re": r"jquery[-/.](\d+\.\d+\.\d+)"},
    {"name": "Bootstrap", "category": "UI Framework", "patterns": ["bootstrap.min.css", "bootstrap.bundle"], "version_re": r"bootstrap[@/](\d+\.\d+\.\d+)"},

    {"name": "Google Analytics", "category": "Analytics", "patterns": ["google-analytics.com/analytics.js", "gtag(", "googletagmanager.com/gtag/js"]},
    {"name": "Google Tag Manager", "category": "Analytics", "patterns": ["googletagmanager.com/gtm.js", "gtm-"]},
    {"name": "Hotjar", "category": "Analytics", "patterns": ["static.hotjar.com"]},
    {"name": "reCAPTCHA", "category": "Security", "patterns": ["google.com/recaptcha", "grecaptcha"]},
    {"name": "Cloudflare Turnstile", "category": "Security", "patterns": ["challenges.cloudflare.com/turnstile"]},
]

# meta-generator content → category (default CMS when the name is unknown).
GENERATOR_CATEGORIES = {
    "wordpress": "CMS", "drupal": "CMS", "joomla": "CMS", "ghost": "CMS",
    "typo3": "CMS", "wix": "CMS", "squarespace": "CMS", "shopify": "CMS",
    "hugo": "Static Site Generator", "jekyll": "Static Site Generator",
    "gatsby": "Static Site Generator", "hexo": "Static Site Generator",
    "next.js": "Web Framework", "nuxt": "Web Framework", "docusaurus": "Static Site Generator",
}

# Categories whose disclosed version is worth flagging (helps CVE lookup).
_VERSION_FLAG_CATEGORIES = {"Web Server", "Programming Language", "Web Framework", "CMS"}


def _extract_version(version_re, text):
    if not version_re or not text:
        return None
    m = re.search(version_re, text, re.I)
    return m.group(1) if m else None


def detect(headers, body):
    """Identify technologies from response headers and an HTML body. Pure.

    Args:
        headers: dict of response headers with lowercase keys (as util.http_get
            returns). The combined Set-Cookie value, if any, is read from
            headers["set-cookie"].
        body: the response body text (any case).

    Returns:
        (technologies, findings) where technologies is a list of dicts
        {name, category, version?, evidence} sorted by (category, name), and
        findings is a list of {severity, message} (version-disclosure notes).
    """
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    body = body or ""
    body_l = body.lower()
    cookie_blob = (headers.get("set-cookie") or "").lower()

    found = {}  # name -> entry (first/best evidence wins; version fills in)

    def add(name, category, evidence, version=None):
        entry = found.get(name)
        if entry is None:
            found[name] = {"name": name, "category": category, "evidence": evidence}
            entry = found[name]
        if version and not entry.get("version"):
            entry["version"] = version

    # --- headers ---
    for sig in HEADER_SIGS:
        value = headers.get(sig["header"])
        if value is None:
            continue
        if sig["pattern"] and sig["pattern"] not in value.lower():
            continue
        version = _extract_version(sig.get("version_re"), value)
        add(sig["name"], sig["category"], f'header {sig["header"]}: "{value}"', version)

    # --- cookies ---
    for sig in COOKIE_SIGS:
        if sig["cookie"] in cookie_blob:
            add(sig["name"], sig["category"], f'cookie "{sig["cookie"]}"')

    # --- meta generator ---
    for tag in re.findall(r"<meta[^>]+>", body, re.I):
        if not re.search(r'name\s*=\s*["\']generator["\']', tag, re.I):
            continue
        cm = re.search(r'content\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        if not cm:
            continue
        content = cm.group(1).strip()
        version = _extract_version(r"(\d+(?:\.\d+)+)", content)
        name = content.split(version)[0].strip() if version else content
        name = name or content
        category = next((c for key, c in GENERATOR_CATEGORIES.items() if key in name.lower()), "CMS")
        add(name, category, f'meta generator: "{content}"', version)

    # --- body ---
    for sig in BODY_SIGS:
        if any(p in body_l for p in sig["patterns"]):
            version = _extract_version(sig.get("version_re"), body)
            add(sig["name"], sig["category"], "html body", version)

    technologies = sorted(found.values(), key=lambda t: (t["category"], t["name"]))

    findings = []
    disclosed = [t for t in technologies if t.get("version") and t["category"] in _VERSION_FLAG_CATEGORIES]
    for t in disclosed:
        findings.append({
            "severity": "info",
            "message": (f'{t["name"]} version {t["version"]} is disclosed in the response. '
                        f"A precise version lets an attacker look up known vulnerabilities; "
                        f"consider suppressing version strings in banners/headers."),
        })

    return technologies, findings


def tech_detect(host, port=None, use_ssl=True, timeout=10.0):
    """Fetch a host and fingerprint its technology stack. Performs network I/O."""
    host = normalize_host(host)
    scheme = "https" if use_ssl else "http"
    if port is None:
        port = 443 if use_ssl else 80
    default_port = (use_ssl and port == 443) or (not use_ssl and port == 80)
    netloc = host if default_port else f"{host}:{port}"
    url = f"{scheme}://{netloc}/"

    # verify=False: a fingerprint is still useful on a host with a broken cert.
    resp = http_get(url, timeout=timeout, verify=False, max_bytes=600_000)
    if resp.get("error"):
        return {"host": host, "url": url, "error": resp["error"]}

    technologies, findings = detect(resp.get("headers", {}), resp.get("body", ""))
    return {
        "host": host,
        "url": url,
        "status": resp.get("status"),
        "technology_count": len(technologies),
        "technologies": technologies,
        "findings": findings,
    }
