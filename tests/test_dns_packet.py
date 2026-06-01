"""Offline unit tests for DNS packet building and parsing (no network)."""

import struct

from recon_mcp.tools.dns import DNSRecon


def test_build_query_has_one_question_and_encodes_name():
    recon = DNSRecon()
    packet = recon._build_dns_query("example.com", 1)  # A record

    tx_id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
    assert qd == 1 and an == 0
    assert flags == 0x0100  # standard recursive query

    # Question section: length-prefixed labels "example" "com" then a zero byte
    body = packet[12:]
    assert body[0] == 7
    assert body[1:8] == b"example"
    assert body[8] == 3
    assert body[9:12] == b"com"
    assert body[12] == 0  # end of name
    qtype, qclass = struct.unpack(">HH", body[13:17])
    assert qtype == 1 and qclass == 1  # A / IN


def test_parse_a_record_response():
    recon = DNSRecon()

    # Hand-crafted DNS response: 1 question, 1 answer (A 93.184.216.34)
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack(">HH", 1, 1)
    answer = (
        b"\xc0\x0c"                       # name pointer to offset 12
        + struct.pack(">HHIH", 1, 1, 300, 4)  # type A, class IN, ttl 300, rdlen 4
        + bytes([93, 184, 216, 34])       # rdata
    )
    data = header + question + answer

    parsed = recon._parse_dns_response(data, "A")
    assert "error" not in parsed
    assert len(parsed["records"]) == 1
    rec = parsed["records"][0]
    assert rec["value"] == "93.184.216.34"
    assert rec["ttl"] == 300
    assert rec["type"] == "A"


def test_parse_rejects_servfail():
    recon = DNSRecon()
    # rcode 2 = SERVFAIL in the low nibble of flags
    data = struct.pack(">HHHHHH", 0x1234, 0x8182, 1, 0, 0, 0)
    parsed = recon._parse_dns_response(data, "A")
    assert "error" in parsed


def test_spf_all_mechanism_parsing():
    recon = DNSRecon()
    assert recon._parse_spf_all("v=spf1 -all") == "fail"
    assert recon._parse_spf_all("v=spf1 ~all") == "softfail"
    assert recon._parse_spf_all("v=spf1 +all") == "pass"
    assert recon._parse_spf_all("v=spf1 include:x") == "unknown"
