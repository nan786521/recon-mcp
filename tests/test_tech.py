"""Offline unit tests for web technology fingerprinting (pure detect())."""

from recon_mcp.tools.tech import detect


def _names(techs):
    return {t["name"] for t in techs}


def _by_name(techs, name):
    return next(t for t in techs if t["name"] == name)


def test_empty_input_detects_nothing():
    techs, findings = detect({}, "")
    assert techs == []
    assert findings == []


def test_server_header_with_version():
    techs, findings = detect({"server": "nginx/1.25.3"}, "")
    nginx = _by_name(techs, "nginx")
    assert nginx["category"] == "Web Server"
    assert nginx["version"] == "1.25.3"
    # disclosed web-server version is flagged
    assert any("1.25.3" in f["message"] for f in findings)


def test_x_powered_by_php_version():
    techs, _ = detect({"x-powered-by": "PHP/8.2.10"}, "")
    php = _by_name(techs, "PHP")
    assert php["category"] == "Programming Language"
    assert php["version"] == "8.2.10"


def test_cloudflare_via_cf_ray_header():
    techs, _ = detect({"cf-ray": "8abc123", "server": "cloudflare"}, "")
    cf = _by_name(techs, "Cloudflare")
    assert cf["category"] == "CDN"


def test_cookie_signature_detects_language():
    techs, _ = detect({"set-cookie": "PHPSESSID=abc; path=/; HttpOnly"}, "")
    assert "PHP" in _names(techs)


def test_meta_generator_wordpress_with_version():
    body = '<html><head><meta name="generator" content="WordPress 6.4.2" /></head></html>'
    techs, findings = detect({}, body)
    wp = _by_name(techs, "WordPress")
    assert wp["category"] == "CMS"
    assert wp["version"] == "6.4.2"
    assert any("WordPress" in f["message"] for f in findings)


def test_meta_generator_static_site_generator_category():
    body = '<meta name="generator" content="Hugo 0.120.0">'
    techs, _ = detect({}, body)
    hugo = _by_name(techs, "Hugo")
    assert hugo["category"] == "Static Site Generator"


def test_body_signature_nextjs_and_react():
    body = '<div id="__next"></div><script>window.__NEXT_DATA__={}</script><div data-reactroot></div>'
    techs, _ = detect({}, body)
    names = _names(techs)
    assert "Next.js" in names
    assert "React" in names


def test_dedup_keeps_single_entry_and_fills_version():
    # Two header signatures both map to ASP.NET; result should be one entry,
    # and the version from x-aspnet-version should be captured.
    headers = {"x-powered-by": "ASP.NET", "x-aspnet-version": "4.0.30319"}
    techs, _ = detect(headers, "")
    aspnet = [t for t in techs if t["name"] == "ASP.NET"]
    assert len(aspnet) == 1
    assert aspnet[0]["version"] == "4.0.30319"


def test_technologies_sorted_by_category_then_name():
    techs, _ = detect({"server": "nginx", "x-powered-by": "PHP/8"}, "")
    cats = [t["category"] for t in techs]
    assert cats == sorted(cats)


def test_no_version_disclosure_finding_when_versionless():
    techs, findings = detect({"server": "cloudflare", "cf-ray": "x"}, "")
    assert findings == []  # CDN with no version → nothing to flag
