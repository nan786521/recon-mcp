"""Smoke test: the MCP server exposes the expected tools."""

import asyncio

from recon_mcp.server import mcp


def test_expected_tools_are_registered():
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert {"dns_recon", "tls_check", "http_headers_audit"} <= names


def test_tools_have_descriptions():
    tools = asyncio.run(mcp.list_tools())
    for t in tools:
        assert t.description, f"{t.name} is missing a description"


def test_server_has_authorized_use_instructions():
    assert mcp.instructions and "authorized" in mcp.instructions.lower()


def test_security_recon_prompt_registered():
    prompts = asyncio.run(mcp.list_prompts())
    assert any(p.name == "security_recon" for p in prompts)
