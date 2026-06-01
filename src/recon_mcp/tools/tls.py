"""SSL/TLS deep analysis engine — certificates, protocols, cipher suites, vulnerabilities, security checks"""

import ssl
import socket
import http.client
import concurrent.futures
from datetime import datetime


# Protocol version test list (including SSLv3)
PROTOCOL_TESTS = [
    ('TLSv1.0', ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
    ('TLSv1.1', ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    ('TLSv1.2', ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ('TLSv1.3', ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
]

# Weak/insecure cipher suite keywords
WEAK_CIPHER_KEYWORDS = ['RC4', 'DES', 'NULL', 'EXPORT', 'anon', 'MD5']
INSECURE_CIPHER_KEYWORDS = ['NULL', 'EXPORT', 'anon']


class SSLAnalyzer:
    """SSL/TLS deep analyzer"""

    def __init__(self, timeout=5.0):
        self.timeout = timeout

    def analyze(self, target, port=443):
        """Full SSL/TLS analysis"""
        result = {
            'target': target,
            'port': port,
            'ip': '',
            'grade': 'T',
            'certificate': None,
            'chain_valid': None,
            'chain_error': None,
            'protocols': {},
            'cipher_suites': [],
            'server_ciphers': [],
            'negotiated_cipher': None,
            'forward_secrecy': None,
            'key_algorithm': None,
            'compression': None,
            'hsts': None,
            'ocsp_stapling': None,
            'vulnerabilities': [],
            'findings': [],
        }

        # Resolve IP
        try:
            result['ip'] = socket.gethostbyname(target)
        except socket.gaierror:
            result['findings'].append({
                'severity': 'critical',
                'title': 'DNS resolution failed',
                'description': f'Unable to resolve {target}',
                'remediation': 'Verify the domain name is spelled correctly and that DNS records are configured.',
            })
            result['grade'] = 'F'
            return result

        # Retrieve certificate
        cert_info = self._get_certificate(target, port)
        if cert_info:
            result['certificate'] = cert_info
            result['key_algorithm'] = cert_info.get('key_algorithm', 'unknown')
        else:
            result['findings'].append({
                'severity': 'critical',
                'title': 'Unable to establish SSL connection',
                'description': f'Target {target}:{port} does not support SSL/TLS or the connection was refused',
                'remediation': 'Verify the target port is correct and that SSL/TLS is enabled.',
            })
            result['grade'] = 'F'
            return result

        # Certificate chain verification
        chain_valid, chain_error = self._verify_chain(target, port)
        result['chain_valid'] = chain_valid
        result['chain_error'] = chain_error

        # Test protocols (including SSLv3)
        result['protocols'] = self._test_protocols(target, port)

        # Server-side cipher enumeration
        server_ciphers = self._enumerate_server_ciphers(target, port)
        result['server_ciphers'] = server_ciphers
        result['cipher_suites'] = server_ciphers  # backward compatibility

        # Negotiated cipher
        result['negotiated_cipher'] = self._get_negotiated_cipher(target, port)

        # Forward Secrecy
        result['forward_secrecy'] = any(
            c['name'].startswith(('ECDHE', 'DHE')) for c in server_ciphers
        )

        # TLS compression
        result['compression'] = self._check_compression(target, port)

        # HSTS check
        result['hsts'] = self._check_hsts(target, port)

        # OCSP Stapling
        result['ocsp_stapling'] = self._check_ocsp_stapling(target, port)

        # Known vulnerability detection
        result['vulnerabilities'] = self._check_vulnerabilities(
            target, port, result['protocols'], server_ciphers, result['compression']
        )

        # Generate findings from analysis results
        self._analyze_findings(result)

        # Calculate grade
        result['grade'] = self._calculate_grade(result)

        return result

    # ─── Certificate ───────────────────────────────────────

    def _get_certificate(self, hostname, port):
        """Retrieve and parse certificate information (first try verification mode to get the parsed cert, then fall back to CERT_NONE)"""
        info = {}
        cipher = None

        # Step 1: try verification mode to get the full parsed cert
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
            if cert:
                self._parse_cert_dict(cert, info)
        except (ssl.SSLError, OSError):
            pass  # verification failed (self-signed, expired, etc.), fall back to the next step

        # Step 2: use CERT_NONE to retrieve the DER cert (always succeeds) and fill in missing information
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not cipher:
                        cipher = ssock.cipher()

            if not der_cert and not info:
                return None

            if der_cert:
                info['der_size'] = len(der_cert)
                # Roughly estimate the RSA public key size from the DER
                if 'key_bits' not in info:
                    info['key_bits'] = self._estimate_key_size_from_der(der_cert)

        except Exception:
            if not info:
                return None

        # Key algorithm detection
        if cipher:
            info['cipher_name'] = cipher[0]
            info['symmetric_bits'] = cipher[2]
            info['protocol_version'] = cipher[1]

        if 'key_algorithm' not in info:
            info['key_algorithm'] = self._detect_key_algorithm(hostname, port)

        # Adjust key_bits based on the algorithm
        if info['key_algorithm'] == 'ECDSA' and info.get('key_bits', 0) > 512:
            info['key_bits'] = 256  # P-256 is the most common
        elif info['key_algorithm'] == 'EdDSA':
            info['key_bits'] = 256

        # Ensure the basic fields exist
        info.setdefault('is_self_signed', False)
        info.setdefault('is_expired', None)
        info.setdefault('days_remaining', None)

        return info

    def _parse_cert_dict(self, cert, info):
        """Parse certificate information from the dict returned by getpeercert()"""
        # Subject
        subject = {}
        for rdn in cert.get('subject', ()):
            for key, val in rdn:
                subject[key] = val
        info['subject'] = subject

        # Issuer
        issuer = {}
        for rdn in cert.get('issuer', ()):
            for key, val in rdn:
                issuer[key] = val
        info['issuer'] = issuer

        # SAN
        san = []
        for typ, val in cert.get('subjectAltName', ()):
            san.append(val)
        info['san'] = san

        # Validity period
        info['not_before'] = cert.get('notBefore', '')
        info['not_after'] = cert.get('notAfter', '')

        # Calculate remaining days
        try:
            expire = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            info['days_remaining'] = (expire - datetime.utcnow()).days
            info['is_expired'] = info['days_remaining'] < 0
        except (ValueError, KeyError):
            info['days_remaining'] = None
            info['is_expired'] = None

        # Serial number & version
        info['serial_number'] = cert.get('serialNumber', '')
        info['version'] = cert.get('version', '')

        # Self-signed detection
        info['is_self_signed'] = (
            subject.get('commonName', '') == issuer.get('commonName', '')
            and subject.get('organizationName', '') == issuer.get('organizationName', '')
        )

    def _detect_key_algorithm(self, hostname, port):
        """Detect the certificate key algorithm via a TLS 1.2 connection (TLS 1.2 cipher names contain algorithm information)"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        name = cipher[0]
                        if 'ECDSA' in name:
                            return 'ECDSA'
                        elif 'EdDSA' in name or 'Ed25519' in name:
                            return 'EdDSA'
                        else:
                            return 'RSA'
        except (ssl.SSLError, OSError, ConnectionError):
            pass
        return 'unknown'

    def _estimate_key_size_from_der(self, der_cert):
        """Roughly estimate the public key size (RSA key bits) from the DER certificate"""
        # The RSA public key modulus length can be roughly inferred from the DER size
        der_len = len(der_cert)
        if der_len > 1800:
            return 4096
        elif der_len > 1200:
            return 2048
        elif der_len > 800:
            return 1024
        return 512  # extremely old key

    def _verify_chain(self, hostname, port):
        """Verify whether the certificate chain is trusted by the system CAs"""
        try:
            ctx = ssl.create_default_context()
            # Defaults: check_hostname=True, verify_mode=CERT_REQUIRED
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.getpeercert()
            return True, None
        except ssl.SSLCertVerificationError as e:
            return False, str(e)
        except ssl.SSLError as e:
            return False, f'SSL error: {e}'
        except Exception as e:
            return None, f'Connection error: {e}'

    # ─── Protocols ───────────────────────────────────────

    def _test_protocols(self, hostname, port):
        """Test each TLS/SSL protocol version"""
        results = {}

        # SSLv3 test (special handling, Python may not support it)
        results['SSLv3'] = self._test_sslv3(hostname, port)

        # TLS 1.0 ~ 1.3
        for name, min_ver, max_ver in PROTOCOL_TESTS:
            results[name] = self._test_single_protocol(hostname, port, min_ver, max_ver)

        return results

    def _test_sslv3(self, hostname, port):
        """Test SSLv3 support"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.options &= ~ssl.OP_NO_SSLv3
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    if 'SSLv3' in ssock.version():
                        return True
            return False
        except (ssl.SSLError, OSError, ConnectionError, AttributeError):
            return False

    def _test_single_protocol(self, hostname, port, min_version, max_version):
        """Test a single protocol version"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = min_version
            ctx.maximum_version = max_version

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except (ssl.SSLError, OSError, ConnectionError):
            return False

    # ─── Cipher suites ──────────────────────────────────────

    def _enumerate_server_ciphers(self, hostname, port):
        """Enumerate the cipher suites the server actually accepts"""
        # Get all ciphers available locally
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            all_ciphers = ctx.get_ciphers()
        except Exception:
            return []

        # Also try to add weaker ciphers for testing
        try:
            ctx_all = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_all.check_hostname = False
            ctx_all.verify_mode = ssl.CERT_NONE
            ctx_all.set_ciphers('ALL:eNULL:aNULL:@SECLEVEL=0')
            weak_ciphers = ctx_all.get_ciphers()
            # Merge, deduplicating by name
            seen = {c['name'] for c in all_ciphers}
            for c in weak_ciphers:
                if c['name'] not in seen:
                    all_ciphers.append(c)
                    seen.add(c['name'])
        except Exception:
            pass

        accepted = []

        # Additionally collect TLS 1.3 ciphers (TLS 1.3 ciphers are not controlled by set_ciphers)
        tls13_ciphers = self._get_tls13_ciphers(hostname, port)

        def _test_cipher(cipher_info):
            name = cipher_info['name']
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Key point: disable TLS 1.3 so it does not bypass the set_ciphers restriction
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                try:
                    ctx.set_ciphers(name)
                except ssl.SSLError:
                    return None
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # Confirm the cipher actually used is the specified one
                        actual = ssock.cipher()
                        if actual and actual[0] == name:
                            return cipher_info
                return None
            except (ssl.SSLError, OSError, ConnectionError):
                return None

        # Parallelize testing for speed (limit thread count to avoid excessive connections)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_test_cipher, c): c for c in all_ciphers}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        accepted.append(result)
                except Exception:
                    pass

        # Merge in TLS 1.3 ciphers
        accepted_names = {c['name'] for c in accepted}
        for c in tls13_ciphers:
            if c['name'] not in accepted_names:
                accepted.append(c)
                accepted_names.add(c['name'])

        # Format the results
        server_ciphers = []
        for c in accepted:
            name = c.get('name', '')
            strength = 'insecure'
            if any(kw in name for kw in INSECURE_CIPHER_KEYWORDS):
                strength = 'insecure'
            elif any(kw in name for kw in WEAK_CIPHER_KEYWORDS):
                strength = 'weak'
            else:
                strength = 'strong'

            server_ciphers.append({
                'name': name,
                'protocol': c.get('protocol', ''),
                'bits': c.get('alg_bits', 0),
                'strength': strength,
            })

        # Sort by strength: strong > weak > insecure
        order = {'strong': 0, 'weak': 1, 'insecure': 2}
        server_ciphers.sort(key=lambda x: (order.get(x['strength'], 3), -x['bits']))
        return server_ciphers

    def _get_tls13_ciphers(self, hostname, port):
        """Get the TLS 1.3 ciphers supported by the server (TLS 1.3 ciphers are not controlled by set_ciphers)"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        return [{'name': cipher[0], 'protocol': cipher[1], 'alg_bits': cipher[2]}]
        except (ssl.SSLError, OSError, ConnectionError):
            pass
        return []

    def _get_negotiated_cipher(self, hostname, port):
        """Get the cipher suite actually negotiated"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        return {
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2],
                        }
        except Exception:
            pass
        return None

    # ─── Compression / HSTS / OCSP ───────────────────────────

    def _check_compression(self, hostname, port):
        """Check whether TLS compression is enabled"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.compression() is not None
        except Exception:
            return None

    def _check_hsts(self, hostname, port):
        """Check the HSTS header"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(hostname, port, timeout=self.timeout, context=ctx)
            conn.request('HEAD', '/')
            resp = conn.getresponse()
            resp.read()
            conn.close()

            hsts = resp.getheader('Strict-Transport-Security', '')
            if not hsts:
                return {'enabled': False}

            result = {'enabled': True, 'raw': hsts}
            if 'max-age=' in hsts:
                try:
                    result['max_age'] = int(hsts.split('max-age=')[1].split(';')[0].strip())
                except (ValueError, IndexError):
                    pass
            result['include_subdomains'] = 'includeSubDomains' in hsts
            result['preload'] = 'preload' in hsts
            return result
        except Exception:
            return {'enabled': False, 'error': 'Unable to connect'}

    def _check_ocsp_stapling(self, hostname, port):
        """Check whether OCSP Stapling is enabled"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Try to use OCSP mode (Python 3.10+ may not support this method)
            if not hasattr(ssl.SSLContext, 'set_ocsp_client_mode'):
                return None  # Python version does not support detection

            ctx_ocsp = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_ocsp.check_hostname = False
            ctx_ocsp.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                ctx_ocsp.set_ocsp_client_mode()
                with ctx_ocsp.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ocsp_resp = ssock.get_channel_binding(b'exporter')
                    return ocsp_resp is not None
        except (AttributeError, TypeError):
            return None  # this detection is not supported
        except Exception:
            return None

    # ─── Vulnerability detection ──────────────────────────────────────

    def _check_vulnerabilities(self, hostname, port, protocols, server_ciphers, compression):
        """Detect known vulnerabilities based on protocol and cipher information"""
        vulns = []
        cipher_names = [c['name'] for c in server_ciphers]

        # SSLv3 / POODLE
        if protocols.get('SSLv3'):
            vulns.append({
                'id': 'POODLE',
                'name': 'POODLE (CVE-2014-3566)',
                'vulnerable': True,
                'severity': 'high',
                'description': 'Server supports SSLv3 and is vulnerable to POODLE; an attacker can decrypt encrypted traffic.',
                'remediation': 'Disable the SSLv3 protocol and keep only TLS 1.2 and above.',
            })
        else:
            vulns.append({
                'id': 'POODLE',
                'name': 'POODLE (CVE-2014-3566)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'SSLv3 is disabled; not affected by POODLE.',
                'remediation': '',
            })

        # BEAST — TLS 1.0 + CBC cipher
        has_tls10 = protocols.get('TLSv1.0', False)
        cbc_ciphers = [n for n in cipher_names if 'CBC' in n]
        if has_tls10 and cbc_ciphers:
            vulns.append({
                'id': 'BEAST',
                'name': 'BEAST (CVE-2011-3389)',
                'vulnerable': True,
                'severity': 'medium',
                'description': f'Supports TLS 1.0 and accepts CBC-mode ciphers ({len(cbc_ciphers)}); may be vulnerable to BEAST.',
                'remediation': 'Disable TLS 1.0, or prefer AEAD ciphers (e.g. AES-GCM).',
            })
        else:
            vulns.append({
                'id': 'BEAST',
                'name': 'BEAST (CVE-2011-3389)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'Not affected by BEAST (TLS 1.0 disabled or no CBC cipher).',
                'remediation': '',
            })

        # SWEET32 — 64-bit block cipher (3DES/DES)
        sweet32_ciphers = [n for n in cipher_names if 'DES' in n or '3DES' in n or 'DES-CBC3' in n]
        if sweet32_ciphers:
            vulns.append({
                'id': 'SWEET32',
                'name': 'SWEET32 (CVE-2016-2183)',
                'vulnerable': True,
                'severity': 'medium',
                'description': f'Supports 64-bit block ciphers ({", ".join(sweet32_ciphers[:3])}); long-lived connections may be attacked.',
                'remediation': 'Disable 3DES and DES ciphers; switch to AES-128 or AES-256.',
            })
        else:
            vulns.append({
                'id': 'SWEET32',
                'name': 'SWEET32 (CVE-2016-2183)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'No 64-bit block ciphers in use; not affected by SWEET32.',
                'remediation': '',
            })

        # FREAK — EXPORT cipher
        export_ciphers = [n for n in cipher_names if 'EXPORT' in n]
        if export_ciphers:
            vulns.append({
                'id': 'FREAK',
                'name': 'FREAK (CVE-2015-0204)',
                'vulnerable': True,
                'severity': 'high',
                'description': f'Supports EXPORT-grade weak ciphers ({", ".join(export_ciphers[:3])}); susceptible to downgrade attacks.',
                'remediation': 'Remove all EXPORT cipher suites.',
            })
        else:
            vulns.append({
                'id': 'FREAK',
                'name': 'FREAK (CVE-2015-0204)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'No EXPORT ciphers; not affected by FREAK.',
                'remediation': '',
            })

        # LOGJAM — DHE with weak DH params
        dhe_ciphers = [n for n in cipher_names if n.startswith('DHE') and 'ECDHE' not in n]
        if dhe_ciphers:
            # Cannot directly detect DH parameter size; flag for attention
            vulns.append({
                'id': 'LOGJAM',
                'name': 'LOGJAM (CVE-2015-4000)',
                'vulnerable': None,  # cannot be determined
                'severity': 'low',
                'description': f'Uses DHE key exchange ({len(dhe_ciphers)}); vulnerable if DH parameters are < 2048 bits.',
                'remediation': 'Ensure DH parameters are at least 2048 bits, or switch to ECDHE.',
            })
        else:
            vulns.append({
                'id': 'LOGJAM',
                'name': 'LOGJAM (CVE-2015-4000)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'No DHE key exchange in use; not affected by LOGJAM.',
                'remediation': '',
            })

        # CRIME — TLS compression
        if compression:
            vulns.append({
                'id': 'CRIME',
                'name': 'CRIME (CVE-2012-4929)',
                'vulnerable': True,
                'severity': 'high',
                'description': 'TLS compression is enabled; an attacker can use the compression-ratio side channel to steal secrets such as cookies.',
                'remediation': 'Disable TLS compression (set ssl_compression off on the server).',
            })
        else:
            vulns.append({
                'id': 'CRIME',
                'name': 'CRIME (CVE-2012-4929)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'TLS compression is not enabled; not affected by CRIME.',
                'remediation': '',
            })

        # RC4
        rc4_ciphers = [n for n in cipher_names if 'RC4' in n]
        if rc4_ciphers:
            vulns.append({
                'id': 'RC4',
                'name': 'RC4 weak cipher (CVE-2013-2566)',
                'vulnerable': True,
                'severity': 'medium',
                'description': f'Supports RC4 encryption ({", ".join(rc4_ciphers[:3])}); RC4 has proven statistical biases that can be exploited.',
                'remediation': 'Disable all RC4 cipher suites; switch to AES-GCM or ChaCha20.',
            })
        else:
            vulns.append({
                'id': 'RC4',
                'name': 'RC4 weak cipher (CVE-2013-2566)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'RC4 encryption is not in use.',
                'remediation': '',
            })

        # NULL cipher
        null_ciphers = [n for n in cipher_names if 'NULL' in n]
        if null_ciphers:
            vulns.append({
                'id': 'NULL_CIPHER',
                'name': 'NULL cipher (no encryption)',
                'vulnerable': True,
                'severity': 'critical',
                'description': f'Supports NULL ciphers ({", ".join(null_ciphers[:3])}); traffic is completely unencrypted.',
                'remediation': 'Immediately remove all NULL cipher suites.',
            })

        # Heartbleed — requires raw packets; cannot be detected by the stdlib
        vulns.append({
            'id': 'HEARTBLEED',
            'name': 'Heartbleed (CVE-2014-0160)',
            'vulnerable': None,
            'severity': 'info',
            'description': 'Requires a dedicated tool (e.g. nmap --script ssl-heartbleed) for accurate detection.',
            'remediation': 'Ensure the OpenSSL version is >= 1.0.1g.',
        })

        return vulns

    # ─── Findings ──────────────────────────────────────

    def _analyze_findings(self, result):
        """Analyze the results and generate security findings"""
        findings = result['findings']
        cert = result.get('certificate') or {}
        protocols = result.get('protocols', {})
        hsts = result.get('hsts') or {}
        chain_valid = result.get('chain_valid')
        vulns = result.get('vulnerabilities', [])

        # ── Certificate chain ──
        if chain_valid is False:
            findings.append({
                'severity': 'critical',
                'title': 'Certificate chain is not trusted',
                'description': result.get('chain_error', 'Certificate chain verification failed'),
                'remediation': 'Install the correct intermediate certificates, or use a certificate issued by a trusted CA.',
            })
        elif chain_valid is True:
            findings.append({
                'severity': 'info',
                'title': 'Certificate chain is trusted',
                'description': 'The certificate chain passed system CA verification.',
                'remediation': '',
            })

        # ── Certificate itself ──
        if cert:
            if cert.get('is_expired'):
                findings.append({
                    'severity': 'critical',
                    'title': 'SSL certificate has expired',
                    'description': f"Certificate expired {abs(cert.get('days_remaining', 0))} days ago",
                    'remediation': 'Renew the SSL certificate immediately. You can obtain one for free from Let\'s Encrypt.',
                })
            elif cert.get('days_remaining') is not None and cert['days_remaining'] < 30:
                findings.append({
                    'severity': 'high',
                    'title': 'SSL certificate is expiring soon',
                    'description': f"Certificate will expire within {cert['days_remaining']} days",
                    'remediation': 'Renew the certificate as soon as possible; consider configuring automatic renewal.',
                })

            if cert.get('is_self_signed'):
                findings.append({
                    'severity': 'high',
                    'title': 'Self-signed certificate',
                    'description': 'A self-signed certificate is in use; browsers will display a security warning',
                    'remediation': 'Use a certificate issued by a trusted CA (e.g. Let\'s Encrypt).',
                })

            key_bits = cert.get('key_bits')
            if key_bits and key_bits < 2048 and cert.get('key_algorithm') != 'ECDSA':
                findings.append({
                    'severity': 'high',
                    'title': 'Insufficient key length',
                    'description': f'Public key length is approximately {key_bits} bits; RSA should be at least 2048 bits',
                    'remediation': 'Regenerate an RSA key of at least 2048 bits, or use a 256-bit ECDSA key.',
                })

        # ── Protocols ──
        if protocols.get('SSLv3'):
            findings.append({
                'severity': 'critical',
                'title': 'Supports SSLv3',
                'description': 'SSLv3 has serious vulnerabilities such as POODLE and has been fully deprecated.',
                'remediation': 'Disable SSLv3 in the server configuration.',
            })
        if protocols.get('TLSv1.0'):
            findings.append({
                'severity': 'medium',
                'title': 'Supports TLS 1.0',
                'description': 'TLS 1.0 was deprecated in 2020 (RFC 8996) and should be disabled.',
                'remediation': 'Disable TLS 1.0 in the server configuration and keep only TLS 1.2+.',
            })
        if protocols.get('TLSv1.1'):
            findings.append({
                'severity': 'medium',
                'title': 'Supports TLS 1.1',
                'description': 'TLS 1.1 was deprecated in 2020 (RFC 8996) and should be disabled.',
                'remediation': 'Disable TLS 1.1 in the server configuration and keep only TLS 1.2+.',
            })
        if not protocols.get('TLSv1.2') and not protocols.get('TLSv1.3'):
            findings.append({
                'severity': 'critical',
                'title': 'Does not support TLS 1.2 or 1.3',
                'description': 'Lacks modern TLS support, posing a serious security risk',
                'remediation': 'Enable TLS 1.2 and TLS 1.3.',
            })
        if protocols.get('TLSv1.3'):
            findings.append({
                'severity': 'info',
                'title': 'Supports TLS 1.3',
                'description': 'Uses the latest TLS protocol; good security.',
                'remediation': '',
            })

        # ── Forward Secrecy ──
        if result.get('forward_secrecy') is False:
            findings.append({
                'severity': 'medium',
                'title': 'Does not support Forward Secrecy',
                'description': 'The server does not support ECDHE/DHE key exchange and cannot provide forward secrecy.',
                'remediation': 'Enable ECDHE cipher suites to support Perfect Forward Secrecy.',
            })
        elif result.get('forward_secrecy') is True:
            findings.append({
                'severity': 'info',
                'title': 'Supports Forward Secrecy',
                'description': 'The server supports ECDHE/DHE, providing forward secrecy protection.',
                'remediation': '',
            })

        # ── HSTS ──
        if not hsts.get('enabled'):
            findings.append({
                'severity': 'medium',
                'title': 'HSTS not enabled',
                'description': 'Enabling HTTP Strict Transport Security is recommended to prevent downgrade attacks.',
                'remediation': 'Add the response header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            })
        elif hsts.get('max_age', 0) < 31536000:
            findings.append({
                'severity': 'low',
                'title': 'HSTS max-age too short',
                'description': f"max-age={hsts.get('max_age', 0)}; at least 31536000 (1 year) is recommended",
                'remediation': 'Set max-age to at least 31536000 (one year).',
            })

        # ── Vulnerability summary ──
        active_vulns = [v for v in vulns if v.get('vulnerable') is True]
        if active_vulns:
            critical_vulns = [v for v in active_vulns if v['severity'] == 'critical']
            high_vulns = [v for v in active_vulns if v['severity'] == 'high']
            if critical_vulns:
                findings.append({
                    'severity': 'critical',
                    'title': f'Detected {len(critical_vulns)} critical vulnerabilities',
                    'description': ', '.join(v['id'] for v in critical_vulns),
                    'remediation': 'Fix the above vulnerabilities immediately; refer to the remediation advice for each.',
                })
            if high_vulns:
                findings.append({
                    'severity': 'high',
                    'title': f'Detected {len(high_vulns)} high-risk vulnerabilities',
                    'description': ', '.join(v['id'] for v in high_vulns),
                    'remediation': 'Fix the above vulnerabilities as soon as possible.',
                })

    # ─── Grading ──────────────────────────────────────────

    def _calculate_grade(self, result):
        """Calculate the SSL grade A+ ~ F"""
        cert = result.get('certificate') or {}
        protocols = result.get('protocols', {})
        hsts = result.get('hsts') or {}
        vulns = result.get('vulnerabilities', [])
        active_vulns = [v for v in vulns if v.get('vulnerable') is True]
        active_vuln_ids = {v['id'] for v in active_vulns}

        key_bits = cert.get('key_bits')
        key_algo = cert.get('key_algorithm', '')

        # F conditions
        if cert.get('is_expired'):
            return 'F'
        if result.get('chain_valid') is False:
            return 'F'
        if not protocols.get('TLSv1.2') and not protocols.get('TLSv1.3'):
            return 'F'
        if protocols.get('SSLv3'):
            return 'F'
        if 'NULL_CIPHER' in active_vuln_ids:
            return 'F'

        # D conditions
        if key_bits and key_bits < 2048 and key_algo != 'ECDSA':
            return 'D'
        if active_vuln_ids & {'SWEET32', 'FREAK'}:
            return 'D'

        # C conditions
        if protocols.get('TLSv1.0') or protocols.get('TLSv1.1'):
            return 'C'
        if 'RC4' in active_vuln_ids:
            return 'C'

        # B conditions
        if not result.get('forward_secrecy'):
            return 'B'
        if active_vuln_ids & {'CRIME', 'BEAST'}:
            return 'B'
        if not hsts.get('enabled'):
            return 'B'

        # A+ conditions
        has_tls13 = protocols.get('TLSv1.3', False)
        has_preload = hsts.get('preload', False)
        has_subdomain = hsts.get('include_subdomains', False)
        no_vulns = len(active_vulns) == 0

        key_ok = (key_algo == 'ECDSA') or (key_bits and key_bits >= 2048)
        if has_tls13 and has_preload and has_subdomain and no_vulns and key_ok:
            return 'A+'

        return 'A'
