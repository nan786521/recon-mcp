"""Smoke test: the MCP server exposes the expected tools."""

import asyncio

from recon_mcp import __version__
from recon_mcp.server import mcp


def test_expected_tools_are_registered():
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert {
        "dns_recon", "tls_check", "http_headers_audit", "port_scan",
        "subdomain_enum", "recon_report", "cookie_audit", "cors_check",
        "well_known_audit", "ip_info", "subdomain_takeover",
    } <= names


def test_tools_have_descriptions():
    tools = asyncio.run(mcp.list_tools())
    for t in tools:
        assert t.description, f"{t.name} is missing a description"


def test_server_has_authorized_use_instructions():
    assert mcp.instructions and "authorized" in mcp.instructions.lower()


def test_security_recon_prompt_registered():
    prompts = asyncio.run(mcp.list_prompts())
    assert any(p.name == "security_recon" for p in prompts)


def test_server_reports_package_version():
    # FastMCP doesn't forward a version, so server.py sets it on the low-level
    # server. Guard against an SDK change silently reverting us to the SDK's
    # own version in the initialize handshake.
    assert mcp._mcp_server.version == __version__
