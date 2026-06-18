"""recon-mcp — an MCP server exposing safe, structured network & security recon tools."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: read the installed package version so it can never
    # drift from pyproject.toml (it did, when manual bumps missed this file).
    __version__ = version("recon-kit-mcp")
except PackageNotFoundError:  # not installed (e.g. running from a raw checkout)
    __version__ = "0.0.0+unknown"
