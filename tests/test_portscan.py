"""Offline unit tests for port-spec parsing and scan guardrails (no network)."""

import pytest

from recon_mcp.tools.portscan import (
    parse_ports,
    PortScanError,
    DEFAULT_PORTS,
    MAX_PORTS_PER_SCAN,
)


def test_parse_comma_list():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_mixed_and_dedup():
    assert parse_ports("1-3,80,3,80") == [1, 2, 3, 80]


def test_parse_reversed_range():
    assert parse_ports("5-1") == [1, 2, 3, 4, 5]


def test_parse_python_list():
    assert parse_ports([443, 22, 22]) == [22, 443]


def test_default_ports_when_none():
    assert parse_ports(None) == list(DEFAULT_PORTS)
    assert 80 in parse_ports(None) and 443 in parse_ports(None)


def test_out_of_range_rejected():
    with pytest.raises(PortScanError):
        parse_ports("0")
    with pytest.raises(PortScanError):
        parse_ports("70000")


def test_empty_rejected():
    with pytest.raises(PortScanError):
        parse_ports(",")


def test_exceeding_cap_rejected():
    # 1-2000 is more than MAX_PORTS_PER_SCAN
    with pytest.raises(PortScanError):
        parse_ports(f"1-{MAX_PORTS_PER_SCAN + 1000}")


def test_at_cap_allowed():
    result = parse_ports(f"1-{MAX_PORTS_PER_SCAN}")
    assert len(result) == MAX_PORTS_PER_SCAN
