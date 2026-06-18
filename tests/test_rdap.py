"""Offline unit tests for RDAP IP-response parsing."""

from recon_mcp.tools.rdap import parse_rdap_ip, _vcard_value


_SAMPLE = {
    "handle": "NET-1-2-3-0-1",
    "name": "EXAMPLE-NET",
    "country": "US",
    "startAddress": "1.2.3.0",
    "endAddress": "1.2.3.255",
    "cidr0_cidrs": [{"v4prefix": "1.2.3.0", "length": 24}],
    "entities": [
        {
            "roles": ["registrant", "owner"],
            "vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Example Org Inc"],
            ]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Abuse Desk"],
                        ["email", {}, "text", "abuse@example.com"],
                    ]],
                }
            ],
        }
    ],
}


def test_parse_extracts_core_fields():
    p = parse_rdap_ip(_SAMPLE)
    assert p["handle"] == "NET-1-2-3-0-1"
    assert p["name"] == "EXAMPLE-NET"
    assert p["country"] == "US"
    assert p["cidr"] == "1.2.3.0/24"
    assert p["org"] == "Example Org Inc"
    assert p["abuse_email"] == "abuse@example.com"


def test_parse_falls_back_to_address_range():
    data = dict(_SAMPLE)
    data = {k: v for k, v in data.items() if k != "cidr0_cidrs"}
    assert parse_rdap_ip(data)["cidr"] == "1.2.3.0 - 1.2.3.255"


def test_parse_handles_missing_entities():
    p = parse_rdap_ip({"handle": "X", "country": "JP"})
    assert p["handle"] == "X"
    assert p["country"] == "JP"
    assert p["org"] is None
    assert p["abuse_email"] is None


def test_parse_non_dict_returns_empty():
    assert parse_rdap_ip("nope") == {}
    assert parse_rdap_ip(None) == {}


def test_vcard_value_lookup():
    vcard = ["vcard", [["fn", {}, "text", "Name"], ["email", {}, "text", "a@b.c"]]]
    assert _vcard_value(vcard, "email") == "a@b.c"
    assert _vcard_value(vcard, "tel") is None
    assert _vcard_value("garbage", "email") is None
