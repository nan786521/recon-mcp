"""Offline unit tests for security.txt / robots.txt parsing."""

from recon_mcp.tools.wellknown import parse_security_txt, parse_robots_txt


def test_security_txt_parses_fields():
    text = (
        "# our policy\n"
        "Contact: mailto:security@example.com\n"
        "Contact: https://example.com/report\n"
        "Expires: 2027-01-01T00:00:00Z\n"
        "Encryption: https://example.com/pgp.txt\n"
        "Preferred-Languages: en, zh-TW\n"
    )
    parsed = parse_security_txt(text)
    assert parsed["fields"]["contact"] == [
        "mailto:security@example.com", "https://example.com/report",
    ]
    assert parsed["fields"]["expires"] == "2027-01-01T00:00:00Z"
    assert parsed["fields"]["preferred-languages"] == "en, zh-TW"
    assert parsed["issues"] == []


def test_security_txt_flags_missing_required_fields():
    parsed = parse_security_txt("Encryption: https://example.com/pgp.txt\n")
    assert any("Contact" in i for i in parsed["issues"])
    assert any("Expires" in i for i in parsed["issues"])


def test_security_txt_ignores_comments_and_unknown_fields():
    parsed = parse_security_txt("# comment\nGarbage: x\nContact: mailto:a@b.c\nExpires: 2027-01-01\n")
    assert "garbage" not in parsed["fields"]
    assert parsed["issues"] == []


def test_robots_txt_collects_sitemaps_and_disallows():
    text = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /internal/\n"
        "Allow: /public/\n"
        "Disallow: /admin/\n"            # duplicate -> deduped
        "Sitemap: https://example.com/sitemap.xml\n"
    )
    parsed = parse_robots_txt(text)
    assert parsed["disallow"] == ["/admin/", "/internal/"]
    assert parsed["allow"] == ["/public/"]
    assert parsed["user_agents"] == ["*"]
    assert parsed["sitemaps"] == ["https://example.com/sitemap.xml"]


def test_robots_txt_skips_blank_and_comment_lines():
    parsed = parse_robots_txt("\n# hello\nDisallow:\nUser-agent: bot\n")
    assert parsed["disallow"] == []      # empty Disallow value dropped
    assert parsed["user_agents"] == ["bot"]
