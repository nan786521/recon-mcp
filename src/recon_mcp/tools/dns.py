"""DNS / WHOIS reconnaissance — pure standard library, no external dependencies.

Performs passive lookups of publicly available DNS and WHOIS information: DNS
records, WHOIS registration, and email-security posture (SPF / DMARC / DKIM).
"""

import socket
import struct
import random
import concurrent.futures

# WHOIS server map by TLD
WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'io': 'whois.nic.io',
    'tw': 'whois.twnic.net.tw',
    'jp': 'whois.jprs.jp',
    'cn': 'whois.cnnic.cn',
    'uk': 'whois.nic.uk',
    'de': 'whois.denic.de',
    'fr': 'whois.nic.fr',
    'eu': 'whois.eu',
    'us': 'whois.nic.us',
    'me': 'whois.nic.me',
    'co': 'whois.nic.co',
    'dev': 'whois.nic.google',
    'app': 'whois.nic.google',
}

# DNS record type codes
DNS_TYPES = {
    'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'MX': 15,
    'TXT': 16, 'AAAA': 28, 'CAA': 257,
}

# Public DNS resolvers (for propagation checks)
PUBLIC_DNS = {
    'Google': '8.8.8.8',
    'Cloudflare': '1.1.1.1',
    'Quad9': '9.9.9.9',
    'OpenDNS': '208.67.222.222',
}


class DNSRecon:
    """WHOIS and DNS reconnaissance engine (stdlib only)."""

    def __init__(self, timeout=5.0):
        self.timeout = timeout

    # ==================== WHOIS ====================

    def whois_lookup(self, domain):
        """Look up WHOIS registration data for a domain."""
        tld = domain.rsplit('.', 1)[-1].lower()
        whois_server = WHOIS_SERVERS.get(tld, f'whois.nic.{tld}')

        result = {
            'domain': domain,
            'whois_server': whois_server,
            'raw': '',
            'parsed': {},
        }

        try:
            raw = self._query_whois(whois_server, domain)
            result['raw'] = raw

            # Some TLDs (e.g. .com) require a secondary registrar WHOIS query
            if 'Registrar WHOIS Server:' in raw:
                for line in raw.split('\n'):
                    if line.strip().startswith('Registrar WHOIS Server:'):
                        secondary = line.split(':', 1)[1].strip()
                        if secondary and secondary != whois_server:
                            raw2 = self._query_whois(secondary, domain)
                            if raw2:
                                result['raw'] = raw2
                                result['whois_server'] = secondary
                            break

            result['parsed'] = self._parse_whois(result['raw'])

        except Exception as e:
            result['error'] = str(e)

        return result

    def _query_whois(self, server, domain):
        sock = socket.create_connection((server, 43), timeout=self.timeout)
        sock.sendall((domain + '\r\n').encode())
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        return response.decode('utf-8', errors='replace')

    def _parse_whois(self, raw):
        parsed = {}
        field_map = {
            'Domain Name': 'domain_name',
            'Registrar': 'registrar',
            'Registrant Organization': 'organization',
            'Registrant Country': 'country',
            'Creation Date': 'created',
            'Updated Date': 'updated',
            'Registry Expiry Date': 'expires',
            'Expiration Date': 'expires',
            'Name Server': 'name_servers',
            'DNSSEC': 'dnssec',
        }

        name_servers = []
        for line in raw.split('\n'):
            line = line.strip()
            if ':' not in line:
                continue
            key, _, value = line.partition(':')
            key = key.strip()
            value = value.strip()
            if not value:
                continue

            if key == 'Name Server':
                name_servers.append(value.lower())
            elif key in field_map:
                parsed[field_map[key]] = value

        if name_servers:
            parsed['name_servers'] = name_servers

        return parsed

    # ==================== DNS queries ====================

    def dns_query(self, domain, record_type='A', dns_server='8.8.8.8', retries=2):
        """Query a single DNS record type over UDP, with retry and TCP fallback.

        DNS over UDP is lossy and size-limited, which silently corrupts results:
          - a dropped datagram makes the record type look empty (it isn't), so
            retry a couple of times before giving up;
          - a response larger than the UDP buffer is truncated and the server
            sets the TC bit — common for big TXT / many-record answers, exactly
            the data that drives SPF / DKIM analysis. On TC, re-ask over TCP,
            which has no size limit.

        A fast negative answer (NXDOMAIN, rcode 3) is a real response, not a
        timeout, so it returns immediately without burning retries — non-existent
        subdomains during enumeration stay fast.
        """
        qtype = DNS_TYPES.get(record_type.upper(), 1)
        packet = self._build_dns_query(domain, qtype)

        data = self._query_udp(packet, dns_server, retries)
        if data is None:
            return {'error': 'no response from DNS server'}

        # TC (truncated) bit in the response flags → the answer did not fit in
        # the UDP datagram; ask again over TCP and prefer that fuller answer.
        if len(data) >= 4 and (struct.unpack('>H', data[2:4])[0] & 0x0200):
            try:
                tcp_data = self._query_tcp(packet, dns_server)
                if tcp_data:
                    data = tcp_data
            except OSError:
                pass  # keep the truncated UDP answer rather than failing outright

        return self._parse_dns_response(data, record_type.upper())

    def _query_udp(self, packet, dns_server, retries):
        """Send the query over UDP, retrying on timeout. Returns raw bytes or None."""
        for _ in range(max(1, retries)):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(packet, (dns_server, 53))
                    data, _ = sock.recvfrom(4096)
                    return data
            except socket.timeout:
                continue          # lost datagram — try again
            except OSError:
                return None       # unreachable / refused — no point retrying
        return None

    def _query_tcp(self, packet, dns_server):
        """Send the query over TCP (length-prefixed). Returns raw DNS bytes."""
        with socket.create_connection((dns_server, 53), timeout=self.timeout) as sock:
            sock.sendall(struct.pack('>H', len(packet)) + packet)
            length_bytes = self._recv_exactly(sock, 2)
            if len(length_bytes) < 2:
                return b''
            resp_len = struct.unpack('>H', length_bytes)[0]
            return self._recv_exactly(sock, resp_len)

    @staticmethod
    def _recv_exactly(sock, n):
        """Read exactly n bytes from a stream socket (TCP), or fewer on EOF."""
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def dns_query_all(self, domain, record_types=None):
        """Query several DNS record types at once.

        Each record type is an independent UDP round-trip, so they run
        concurrently — wall-clock is one query, not the sum of all of them
        (which matters most when some types time out). Output order follows
        `record_types` regardless of which responses arrive first.
        """
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA']

        def _query(rt):
            resp = self.dns_query(domain, rt)
            return resp.get('records', []) if not resp.get('error') else []

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(record_types)) as pool:
            futures = {rt: pool.submit(_query, rt) for rt in record_types}
            results = {rt: futures[rt].result() for rt in record_types}

        return {'domain': domain, 'records': results}

    def reverse_dns(self, ip):
        """Reverse DNS (PTR) lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return {'ip': ip, 'hostname': hostname}
        except socket.herror:
            return {'ip': ip, 'hostname': None, 'error': 'no PTR record'}
        except Exception as e:
            return {'ip': ip, 'hostname': None, 'error': str(e)}

    def analyze_email_security(self, domain):
        """Inspect SPF / DMARC / DKIM posture for a domain."""
        result = {'domain': domain, 'spf': None, 'dmarc': None, 'dkim': None}

        # SPF — from the apex TXT records
        txt_resp = self.dns_query(domain, 'TXT')
        for rec in txt_resp.get('records', []):
            val = rec.get('value', '')
            if val.startswith('v=spf1'):
                result['spf'] = {
                    'found': True,
                    'record': val,
                    'all_mechanism': self._parse_spf_all(val),
                }
                break
        if not result['spf']:
            result['spf'] = {'found': False}

        # DMARC — from _dmarc.<domain> TXT
        dmarc_resp = self.dns_query(f'_dmarc.{domain}', 'TXT')
        for rec in dmarc_resp.get('records', []):
            val = rec.get('value', '')
            if val.startswith('v=DMARC1'):
                result['dmarc'] = {
                    'found': True,
                    'record': val,
                    'policy': self._parse_dmarc_policy(val),
                }
                break
        if not result['dmarc']:
            result['dmarc'] = {'found': False}

        # DKIM — probe common selectors
        for selector in ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim']:
            dkim_resp = self.dns_query(f'{selector}._domainkey.{domain}', 'TXT')
            for rec in dkim_resp.get('records', []):
                val = rec.get('value', '')
                if 'v=DKIM1' in val or 'p=' in val:
                    result['dkim'] = {
                        'found': True,
                        'selector': selector,
                        'record': val[:100] + '...' if len(val) > 100 else val,
                    }
                    break
            if result['dkim']:
                break
        if not result['dkim']:
            result['dkim'] = {'found': False}

        result['assessment'] = grade_email_security(result)
        return result

    # ==================== DNS packet build / parse ====================

    def _build_dns_query(self, domain, qtype):
        tx_id = random.randint(0, 65535)
        flags = 0x0100  # standard recursive query
        header = struct.pack('>HHHHHH', tx_id, flags, 1, 0, 0, 0)

        qname = b''
        for part in domain.split('.'):
            encoded = part.encode('utf-8')
            qname += bytes([len(encoded)]) + encoded
        qname += b'\x00'

        question = qname + struct.pack('>HH', qtype, 1)  # QCLASS = IN
        return header + question

    def _parse_dns_response(self, data, record_type):
        if len(data) < 12:
            return {'error': 'response too short'}

        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', data[:12])
        rcode = flags & 0x0F
        if rcode != 0:
            return {'error': f'DNS error code: {rcode}'}

        offset = 12
        for _ in range(qdcount):
            offset = self._skip_name(data, offset)
            offset += 4  # QTYPE + QCLASS

        records = []
        for _ in range(ancount):
            name, offset = self._read_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', data[offset:offset + 10])
            offset += 10

            if offset + rdlength > len(data):
                break

            rdata = data[offset:offset + rdlength]
            offset += rdlength

            record = {'name': name, 'ttl': ttl, 'type': record_type}

            if record_type == 'A' and len(rdata) == 4:
                record['value'] = socket.inet_ntoa(rdata)
            elif record_type == 'AAAA' and len(rdata) == 16:
                record['value'] = socket.inet_ntop(socket.AF_INET6, rdata)
            elif record_type == 'MX' and len(rdata) >= 3:
                preference = struct.unpack('>H', rdata[:2])[0]
                mx_name, _ = self._read_name(data, offset - rdlength + 2)
                record['value'] = mx_name
                record['preference'] = preference
            elif record_type in ('NS', 'CNAME'):
                cname, _ = self._read_name(data, offset - rdlength)
                record['value'] = cname
            elif record_type == 'TXT':
                record['value'] = self._read_txt(rdata)
            elif record_type == 'SOA' and len(rdata) >= 20:
                mname, pos = self._read_name(data, offset - rdlength)
                rname, pos = self._read_name(data, pos)
                if pos + 20 <= len(data):
                    serial, refresh, retry, expire, minimum = struct.unpack('>IIIII', data[pos:pos + 20])
                    record['value'] = f'{mname} {rname}'
                    record['serial'] = serial
                    record['refresh'] = refresh
                    record['retry'] = retry
                    record['expire'] = expire
                else:
                    record['value'] = f'{mname} {rname}'
            elif record_type == 'CAA' and len(rdata) >= 2:
                flags = rdata[0]
                tag_len = rdata[1]
                tag = rdata[2:2 + tag_len].decode('ascii', errors='replace')
                value = rdata[2 + tag_len:].decode('utf-8', errors='replace')
                record['value'] = f'{flags} {tag} "{value}"'
            else:
                record['value'] = rdata.hex()

            records.append(record)

        return {'records': records}

    def _skip_name(self, data, offset):
        while offset < len(data):
            length = data[offset]
            if length == 0:
                return offset + 1
            if (length & 0xC0) == 0xC0:
                return offset + 2
            offset += 1 + length
        return offset

    def _read_name(self, data, offset):
        parts = []
        seen = set()
        orig_offset = offset
        jumped = False

        while offset < len(data):
            if offset in seen:
                break
            seen.add(offset)

            length = data[offset]
            if length == 0:
                if not jumped:
                    orig_offset = offset + 1
                break
            if (length & 0xC0) == 0xC0:
                if not jumped:
                    orig_offset = offset + 2
                    jumped = True
                pointer = struct.unpack('>H', data[offset:offset + 2])[0] & 0x3FFF
                offset = pointer
                continue
            offset += 1
            if offset + length > len(data):
                break
            parts.append(data[offset:offset + length].decode('utf-8', errors='replace'))
            offset += length

        return '.'.join(parts), orig_offset

    def _read_txt(self, rdata):
        texts = []
        i = 0
        while i < len(rdata):
            length = rdata[i]
            i += 1
            if i + length > len(rdata):
                break
            texts.append(rdata[i:i + length].decode('utf-8', errors='replace'))
            i += length
        return ''.join(texts)

    def _parse_spf_all(self, spf):
        if '-all' in spf:
            return 'fail'
        if '~all' in spf:
            return 'softfail'
        if '?all' in spf:
            return 'neutral'
        if '+all' in spf:
            return 'pass'
        return 'unknown'

    def _parse_dmarc_policy(self, dmarc):
        for part in dmarc.split(';'):
            part = part.strip()
            if part.startswith('p='):
                return part[2:]
        return 'unknown'


# ==================== Email-security grading ====================

def grade_email_security(email):
    """Turn raw SPF/DMARC/DKIM findings into a graded assessment.

    Returns a dict with an overall letter grade (A–F), a one-line summary, and a
    list of findings. Each finding has:
        severity: "ok" | "info" | "warning" | "critical"
        check:    "SPF" | "DKIM" | "DMARC"
        message:  human-readable explanation
        recommendation: suggested fix (omitted when severity is "ok")
    """
    findings = []
    score = 100

    spf = email.get('spf', {})
    dmarc = email.get('dmarc', {})
    dkim = email.get('dkim', {})

    # --- SPF ---
    if not spf.get('found'):
        score -= 30
        findings.append({
            'severity': 'warning', 'check': 'SPF',
            'message': 'No SPF record. Receivers cannot tell which servers may send for this domain.',
            'recommendation': 'Publish a TXT record, e.g. "v=spf1 include:_spf.google.com -all".',
        })
    else:
        mech = spf.get('all_mechanism')
        if mech == 'pass':  # +all — anyone may send
            score -= 40
            findings.append({
                'severity': 'critical', 'check': 'SPF',
                'message': 'SPF ends with "+all", which authorizes any server to send as this domain.',
                'recommendation': 'Change the "all" mechanism to "-all" (hard fail).',
            })
        elif mech in ('softfail', 'neutral'):
            score -= 5
            findings.append({
                'severity': 'info', 'check': 'SPF',
                'message': f'SPF present but uses "{mech}" ("~all"/"?all"); spoofed mail is only flagged, not rejected.',
                'recommendation': 'Tighten the "all" mechanism to "-all" once you confirm all senders are listed.',
            })
        else:  # fail / hardfail
            findings.append({
                'severity': 'ok', 'check': 'SPF',
                'message': 'SPF present with a hard fail ("-all").',
            })

    # --- DKIM ---
    if not dkim.get('found'):
        score -= 20
        findings.append({
            'severity': 'warning', 'check': 'DKIM',
            'message': 'No DKIM record found on common selectors. Mail is not cryptographically signed (or uses a custom selector).',
            'recommendation': 'Enable DKIM signing in your mail provider and publish the public key.',
        })
    else:
        findings.append({
            'severity': 'ok', 'check': 'DKIM',
            'message': f'DKIM present (selector "{dkim.get("selector")}").',
        })

    # --- DMARC ---
    if not dmarc.get('found'):
        score -= 30
        findings.append({
            'severity': 'warning', 'check': 'DMARC',
            'message': 'No DMARC record. Receivers have no policy for handling spoofed mail, and you get no abuse reports.',
            'recommendation': 'Start with "v=DMARC1; p=none; rua=mailto:you@domain" to monitor, then move to p=quarantine/reject.',
        })
    else:
        policy = dmarc.get('policy')
        if policy in ('reject', 'quarantine'):
            findings.append({
                'severity': 'ok', 'check': 'DMARC',
                'message': f'DMARC enforced (p={policy}).',
            })
        else:  # none / unknown
            score -= 10
            findings.append({
                'severity': 'info', 'check': 'DMARC',
                'message': f'DMARC present but not enforced (p={policy}); it only monitors, spoofed mail is still delivered.',
                'recommendation': 'After reviewing reports, raise the policy to p=quarantine then p=reject.',
            })

    score = max(score, 0)
    grade = (
        'A' if score >= 90 else
        'B' if score >= 75 else
        'C' if score >= 60 else
        'D' if score >= 40 else 'F'
    )

    worst = next((s for s in ('critical', 'warning', 'info')
                  if any(f['severity'] == s for f in findings)), 'ok')
    summary = {
        'ok': 'SPF, DKIM, and DMARC are all configured and enforced.',
        'info': 'Core records present; some hardening recommended.',
        'warning': 'One or more email-authentication records are missing.',
        'critical': 'A misconfiguration actively allows spoofing.',
    }[worst]

    return {'grade': grade, 'score': score, 'summary': summary, 'findings': findings}
