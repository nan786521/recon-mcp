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


def test_parse_caa_record():
    recon = DNSRecon()
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack(">HH", 257, 1)  # CAA / IN
    rdata = b"\x00" + bytes([5]) + b"issue" + b"letsencrypt.org"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 257, 1, 3600, len(rdata)) + rdata
    parsed = recon._parse_dns_response(header + question + answer, "CAA")
    assert parsed["records"][0]["value"] == '0 issue "letsencrypt.org"'


def test_spf_all_mechanism_parsing():
    recon = DNSRecon()
    assert recon._parse_spf_all("v=spf1 -all") == "fail"
    assert recon._parse_spf_all("v=spf1 ~all") == "softfail"
    assert recon._parse_spf_all("v=spf1 +all") == "pass"
    assert recon._parse_spf_all("v=spf1 include:x") == "unknown"


# ── UDP retry / TC truncation TCP fallback (offline, methods stubbed) ──

def _a_response(ip_bytes, flags):
    """Build a minimal 1-answer A-record response with the given header flags."""
    header = struct.pack(">HHHHHH", 0x1234, flags, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes(ip_bytes)
    return header + question + answer


def test_tc_bit_triggers_tcp_fallback():
    recon = DNSRecon()
    # UDP answer has the TC bit set (0x0200) and carries the "wrong" address;
    # the TCP answer is the fuller one and should win.
    truncated = struct.pack(">HHHHHH", 0x1234, 0x8380, 1, 0, 0, 0)  # QR+TC+RD+RA
    recon._query_udp = lambda pkt, srv, retries: truncated
    recon._query_tcp = lambda pkt, srv: _a_response([1, 2, 3, 4], 0x8180)

    parsed = recon.dns_query("example.com", "A")
    assert parsed["records"][0]["value"] == "1.2.3.4"


def test_no_tc_bit_skips_tcp():
    recon = DNSRecon()
    recon._query_udp = lambda pkt, srv, retries: _a_response([5, 6, 7, 8], 0x8180)
    calls = {"tcp": 0}

    def _tcp(pkt, srv):
        calls["tcp"] += 1
        return b""

    recon._query_tcp = _tcp
    parsed = recon.dns_query("example.com", "A")
    assert parsed["records"][0]["value"] == "5.6.7.8"
    assert calls["tcp"] == 0  # untruncated UDP answer must not hit TCP


def test_udp_no_response_returns_error():
    recon = DNSRecon()
    recon._query_udp = lambda pkt, srv, retries: None  # all retries timed out
    parsed = recon.dns_query("example.com", "A")
    assert "error" in parsed


def test_recv_exactly_reassembles_chunked_stream():
    class OneByteAtATime:
        def __init__(self, data):
            self.data = data

        def recv(self, n):
            chunk, self.data = self.data[:1], self.data[1:]
            return chunk

    assert DNSRecon._recv_exactly(OneByteAtATime(b"hello"), 5) == b"hello"
    # EOF before n bytes returns what was read so far
    assert DNSRecon._recv_exactly(OneByteAtATime(b"hi"), 5) == b"hi"
