"""Tests for the unified tool error contract and that wrapping preserves the
FastMCP input schema (the server wiring layer)."""

import asyncio
import inspect

from recon_mcp.server import _safe_tool, mcp


def test_safe_tool_catches_exceptions():
    @_safe_tool
    def boom(x):
        raise ValueError("kaboom")

    assert boom(1) == {"error": "ValueError: kaboom"}


def test_safe_tool_passes_through_success():
    @_safe_tool
    def ok(x):
        return {"x": x}

    assert ok(5) == {"x": 5}


def test_safe_tool_preserves_signature():
    @_safe_tool
    def f(domain: str, n: int = 3) -> dict:
        return {}

    assert list(inspect.signature(f).parameters) == ["domain", "n"]


def test_tool_input_schemas_intact():
    """Wrapping must not erase the per-tool input schema FastMCP advertises."""
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    assert "domain" in tools["dns_recon"].inputSchema["properties"]
    assert "host" in tools["port_scan"].inputSchema["properties"]
    assert "domain" in tools["recon_report"].inputSchema["properties"]
