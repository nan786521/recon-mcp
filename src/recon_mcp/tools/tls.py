"""SSL/TLS 深度分析引擎 — 憑證、協定、加密套件、漏洞、安全檢查"""

import ssl
import socket
import http.client
import concurrent.futures
from datetime import datetime


# 協定版本測試清單（含 SSLv3）
PROTOCOL_TESTS = [
    ('TLSv1.0', ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
    ('TLSv1.1', ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    ('TLSv1.2', ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ('TLSv1.3', ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
]

# 弱/不安全加密套件關鍵字
WEAK_CIPHER_KEYWORDS = ['RC4', 'DES', 'NULL', 'EXPORT', 'anon', 'MD5']
INSECURE_CIPHER_KEYWORDS = ['NULL', 'EXPORT', 'anon']


class SSLAnalyzer:
    """SSL/TLS 深度分析器"""

    def __init__(self, timeout=5.0):
        self.timeout = timeout

    def analyze(self, target, port=443):
        """完整 SSL/TLS 分析"""
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

        # 解析 IP
        try:
            result['ip'] = socket.gethostbyname(target)
        except socket.gaierror:
            result['findings'].append({
                'severity': 'critical',
                'title': 'DNS 解析失敗',
                'description': f'無法解析 {target}',
                'remediation': '請確認域名拼寫正確且 DNS 記錄已設定。',
            })
            result['grade'] = 'F'
            return result

        # 取得憑證
        cert_info = self._get_certificate(target, port)
        if cert_info:
            result['certificate'] = cert_info
            result['key_algorithm'] = cert_info.get('key_algorithm', '未知')
        else:
            result['findings'].append({
                'severity': 'critical',
                'title': '無法建立 SSL 連線',
                'description': f'目標 {target}:{port} 不支援 SSL/TLS 或連線被拒',
                'remediation': '請確認目標埠號正確且已啟用 SSL/TLS。',
            })
            result['grade'] = 'F'
            return result

        # 憑證鏈驗證
        chain_valid, chain_error = self._verify_chain(target, port)
        result['chain_valid'] = chain_valid
        result['chain_error'] = chain_error

        # 測試協定（含 SSLv3）
        result['protocols'] = self._test_protocols(target, port)

        # 伺服器端 cipher 列舉
        server_ciphers = self._enumerate_server_ciphers(target, port)
        result['server_ciphers'] = server_ciphers
        result['cipher_suites'] = server_ciphers  # 向下相容

        # 協商 cipher
        result['negotiated_cipher'] = self._get_negotiated_cipher(target, port)

        # Forward Secrecy
        result['forward_secrecy'] = any(
            c['name'].startswith(('ECDHE', 'DHE')) for c in server_ciphers
        )

        # TLS 壓縮
        result['compression'] = self._check_compression(target, port)

        # HSTS 檢查
        result['hsts'] = self._check_hsts(target, port)

        # OCSP Stapling
        result['ocsp_stapling'] = self._check_ocsp_stapling(target, port)

        # 已知漏洞檢測
        result['vulnerabilities'] = self._check_vulnerabilities(
            target, port, result['protocols'], server_ciphers, result['compression']
        )

        # 分析結果產生 findings
        self._analyze_findings(result)

        # 計算評等
        result['grade'] = self._calculate_grade(result)

        return result

    # ─── 憑證 ───────────────────────────────────────────

    def _get_certificate(self, hostname, port):
        """取得並解析憑證資訊（先嘗試驗證模式取 parsed cert，再 fallback 到 CERT_NONE）"""
        info = {}
        cipher = None

        # 第一步：嘗試用驗證模式取得完整 parsed cert
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
            if cert:
                self._parse_cert_dict(cert, info)
        except (ssl.SSLError, OSError):
            pass  # 驗證失敗（自簽、過期等），fallback 到下一步

        # 第二步：用 CERT_NONE 取得 DER cert（一定成功），補充缺失資訊
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
                # 從 DER 粗估 RSA 公鑰大小
                if 'key_bits' not in info:
                    info['key_bits'] = self._estimate_key_size_from_der(der_cert)

        except Exception:
            if not info:
                return None

        # 金鑰演算法偵測
        if cipher:
            info['cipher_name'] = cipher[0]
            info['symmetric_bits'] = cipher[2]
            info['protocol_version'] = cipher[1]

        if 'key_algorithm' not in info:
            info['key_algorithm'] = self._detect_key_algorithm(hostname, port)

        # 根據演算法修正 key_bits
        if info['key_algorithm'] == 'ECDSA' and info.get('key_bits', 0) > 512:
            info['key_bits'] = 256  # P-256 最常見
        elif info['key_algorithm'] == 'EdDSA':
            info['key_bits'] = 256

        # 確保基本欄位存在
        info.setdefault('is_self_signed', False)
        info.setdefault('is_expired', None)
        info.setdefault('days_remaining', None)

        return info

    def _parse_cert_dict(self, cert, info):
        """從 getpeercert() 回傳的 dict 解析憑證資訊"""
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

        # 有效期
        info['not_before'] = cert.get('notBefore', '')
        info['not_after'] = cert.get('notAfter', '')

        # 計算剩餘天數
        try:
            expire = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            info['days_remaining'] = (expire - datetime.utcnow()).days
            info['is_expired'] = info['days_remaining'] < 0
        except (ValueError, KeyError):
            info['days_remaining'] = None
            info['is_expired'] = None

        # 序號 & 版本
        info['serial_number'] = cert.get('serialNumber', '')
        info['version'] = cert.get('version', '')

        # 自簽偵測
        info['is_self_signed'] = (
            subject.get('commonName', '') == issuer.get('commonName', '')
            and subject.get('organizationName', '') == issuer.get('organizationName', '')
        )

    def _detect_key_algorithm(self, hostname, port):
        """用 TLS 1.2 連線偵測憑證金鑰演算法（TLS 1.2 cipher name 包含演算法資訊）"""
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
        return '未知'

    def _estimate_key_size_from_der(self, der_cert):
        """從 DER 憑證粗估公鑰大小（RSA key bits）"""
        # RSA 公鑰的 modulus 長度可從 DER 大小大致推估
        der_len = len(der_cert)
        if der_len > 1800:
            return 4096
        elif der_len > 1200:
            return 2048
        elif der_len > 800:
            return 1024
        return 512  # 極舊的金鑰

    def _verify_chain(self, hostname, port):
        """驗證憑證鏈是否受系統 CA 信任"""
        try:
            ctx = ssl.create_default_context()
            # 預設 check_hostname=True, verify_mode=CERT_REQUIRED
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.getpeercert()
            return True, None
        except ssl.SSLCertVerificationError as e:
            return False, str(e)
        except ssl.SSLError as e:
            return False, f'SSL 錯誤: {e}'
        except Exception as e:
            return None, f'連線錯誤: {e}'

    # ─── 協定 ───────────────────────────────────────────

    def _test_protocols(self, hostname, port):
        """測試各 TLS/SSL 協定版本"""
        results = {}

        # SSLv3 測試（特殊處理，Python 可能不支援）
        results['SSLv3'] = self._test_sslv3(hostname, port)

        # TLS 1.0 ~ 1.3
        for name, min_ver, max_ver in PROTOCOL_TESTS:
            results[name] = self._test_single_protocol(hostname, port, min_ver, max_ver)

        return results

    def _test_sslv3(self, hostname, port):
        """測試 SSLv3 支援"""
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
        """測試單一協定版本"""
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

    # ─── 加密套件 ──────────────────────────────────────

    def _enumerate_server_ciphers(self, hostname, port):
        """列舉伺服器實際接受的加密套件"""
        # 取得本機所有可用 cipher
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            all_ciphers = ctx.get_ciphers()
        except Exception:
            return []

        # 也嘗試加入較弱的 cipher 來測試
        try:
            ctx_all = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_all.check_hostname = False
            ctx_all.verify_mode = ssl.CERT_NONE
            ctx_all.set_ciphers('ALL:eNULL:aNULL:@SECLEVEL=0')
            weak_ciphers = ctx_all.get_ciphers()
            # 合併，以 name 去重
            seen = {c['name'] for c in all_ciphers}
            for c in weak_ciphers:
                if c['name'] not in seen:
                    all_ciphers.append(c)
                    seen.add(c['name'])
        except Exception:
            pass

        accepted = []

        # 另外收集 TLS 1.3 cipher（TLS 1.3 cipher 不受 set_ciphers 控制）
        tls13_ciphers = self._get_tls13_ciphers(hostname, port)

        def _test_cipher(cipher_info):
            name = cipher_info['name']
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # 關鍵：禁用 TLS 1.3 以免繞過 set_ciphers 限制
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                try:
                    ctx.set_ciphers(name)
                except ssl.SSLError:
                    return None
                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # 確認實際使用的就是指定的 cipher
                        actual = ssock.cipher()
                        if actual and actual[0] == name:
                            return cipher_info
                return None
            except (ssl.SSLError, OSError, ConnectionError):
                return None

        # 並行測試加速（限制執行緒數量避免過度連線）
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_test_cipher, c): c for c in all_ciphers}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        accepted.append(result)
                except Exception:
                    pass

        # 合併 TLS 1.3 cipher
        accepted_names = {c['name'] for c in accepted}
        for c in tls13_ciphers:
            if c['name'] not in accepted_names:
                accepted.append(c)
                accepted_names.add(c['name'])

        # 格式化結果
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

        # 按強度排序：strong > weak > insecure
        order = {'strong': 0, 'weak': 1, 'insecure': 2}
        server_ciphers.sort(key=lambda x: (order.get(x['strength'], 3), -x['bits']))
        return server_ciphers

    def _get_tls13_ciphers(self, hostname, port):
        """取得伺服器支援的 TLS 1.3 cipher（TLS 1.3 cipher 不受 set_ciphers 控制）"""
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
        """取得實際協商的加密套件"""
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

    # ─── 壓縮 / HSTS / OCSP ───────────────────────────

    def _check_compression(self, hostname, port):
        """檢查 TLS 壓縮是否啟用"""
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
        """檢查 HSTS 標頭"""
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
            return {'enabled': False, 'error': '無法連線'}

    def _check_ocsp_stapling(self, hostname, port):
        """檢查 OCSP Stapling 是否啟用"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # 嘗試使用 OCSP 模式（Python 3.10+ 可能不支援此方法）
            if not hasattr(ssl.SSLContext, 'set_ocsp_client_mode'):
                return None  # Python 版本不支援偵測

            ctx_ocsp = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_ocsp.check_hostname = False
            ctx_ocsp.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                ctx_ocsp.set_ocsp_client_mode()
                with ctx_ocsp.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ocsp_resp = ssock.get_channel_binding(b'exporter')
                    return ocsp_resp is not None
        except (AttributeError, TypeError):
            return None  # 不支援此偵測
        except Exception:
            return None

    # ─── 漏洞檢測 ──────────────────────────────────────

    def _check_vulnerabilities(self, hostname, port, protocols, server_ciphers, compression):
        """基於協定和 cipher 資訊檢測已知漏洞"""
        vulns = []
        cipher_names = [c['name'] for c in server_ciphers]

        # SSLv3 / POODLE
        if protocols.get('SSLv3'):
            vulns.append({
                'id': 'POODLE',
                'name': 'POODLE (CVE-2014-3566)',
                'vulnerable': True,
                'severity': 'high',
                'description': '伺服器支援 SSLv3，易受 POODLE 攻擊，攻擊者可解密加密流量。',
                'remediation': '停用 SSLv3 協定，僅保留 TLS 1.2 以上。',
            })
        else:
            vulns.append({
                'id': 'POODLE',
                'name': 'POODLE (CVE-2014-3566)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'SSLv3 已停用，不受 POODLE 影響。',
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
                'description': f'支援 TLS 1.0 且接受 CBC 模式 cipher ({len(cbc_ciphers)} 個)，可能受 BEAST 攻擊。',
                'remediation': '停用 TLS 1.0，或優先使用 AEAD cipher (如 AES-GCM)。',
            })
        else:
            vulns.append({
                'id': 'BEAST',
                'name': 'BEAST (CVE-2011-3389)',
                'vulnerable': False,
                'severity': 'info',
                'description': '不受 BEAST 影響（已停用 TLS 1.0 或無 CBC cipher）。',
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
                'description': f'支援 64-bit 區塊加密 ({", ".join(sweet32_ciphers[:3])})，長時間連線可能被攻擊。',
                'remediation': '停用 3DES 和 DES cipher，改用 AES-128 或 AES-256。',
            })
        else:
            vulns.append({
                'id': 'SWEET32',
                'name': 'SWEET32 (CVE-2016-2183)',
                'vulnerable': False,
                'severity': 'info',
                'description': '未使用 64-bit 區塊加密，不受 SWEET32 影響。',
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
                'description': f'支援 EXPORT 等級弱加密 ({", ".join(export_ciphers[:3])})，容易被降級攻擊。',
                'remediation': '移除所有 EXPORT cipher suite。',
            })
        else:
            vulns.append({
                'id': 'FREAK',
                'name': 'FREAK (CVE-2015-0204)',
                'vulnerable': False,
                'severity': 'info',
                'description': '無 EXPORT cipher，不受 FREAK 影響。',
                'remediation': '',
            })

        # LOGJAM — DHE with weak DH params
        dhe_ciphers = [n for n in cipher_names if n.startswith('DHE') and 'ECDHE' not in n]
        if dhe_ciphers:
            # 無法直接偵測 DH 參數大小，標記為需注意
            vulns.append({
                'id': 'LOGJAM',
                'name': 'LOGJAM (CVE-2015-4000)',
                'vulnerable': None,  # 無法確定
                'severity': 'low',
                'description': f'使用 DHE 金鑰交換 ({len(dhe_ciphers)} 個)，若 DH 參數 < 2048 bits 則易受攻擊。',
                'remediation': '確保 DH 參數至少 2048 bits，或改用 ECDHE。',
            })
        else:
            vulns.append({
                'id': 'LOGJAM',
                'name': 'LOGJAM (CVE-2015-4000)',
                'vulnerable': False,
                'severity': 'info',
                'description': '未使用 DHE 金鑰交換，不受 LOGJAM 影響。',
                'remediation': '',
            })

        # CRIME — TLS 壓縮
        if compression:
            vulns.append({
                'id': 'CRIME',
                'name': 'CRIME (CVE-2012-4929)',
                'vulnerable': True,
                'severity': 'high',
                'description': 'TLS 壓縮已啟用，攻擊者可利用壓縮比側信道竊取 Cookie 等機密資料。',
                'remediation': '停用 TLS 壓縮（伺服器端設定 ssl_compression off）。',
            })
        else:
            vulns.append({
                'id': 'CRIME',
                'name': 'CRIME (CVE-2012-4929)',
                'vulnerable': False,
                'severity': 'info',
                'description': 'TLS 壓縮未啟用，不受 CRIME 影響。',
                'remediation': '',
            })

        # RC4
        rc4_ciphers = [n for n in cipher_names if 'RC4' in n]
        if rc4_ciphers:
            vulns.append({
                'id': 'RC4',
                'name': 'RC4 弱加密 (CVE-2013-2566)',
                'vulnerable': True,
                'severity': 'medium',
                'description': f'支援 RC4 加密 ({", ".join(rc4_ciphers[:3])})，RC4 已被證實存在統計偏差可被利用。',
                'remediation': '停用所有 RC4 cipher suite，改用 AES-GCM 或 ChaCha20。',
            })
        else:
            vulns.append({
                'id': 'RC4',
                'name': 'RC4 弱加密 (CVE-2013-2566)',
                'vulnerable': False,
                'severity': 'info',
                'description': '未使用 RC4 加密。',
                'remediation': '',
            })

        # NULL cipher
        null_ciphers = [n for n in cipher_names if 'NULL' in n]
        if null_ciphers:
            vulns.append({
                'id': 'NULL_CIPHER',
                'name': 'NULL 加密（無加密）',
                'vulnerable': True,
                'severity': 'critical',
                'description': f'支援 NULL cipher ({", ".join(null_ciphers[:3])})，流量完全未加密。',
                'remediation': '立即移除所有 NULL cipher suite。',
            })

        # Heartbleed — 需要原始封包，stdlib 無法檢測
        vulns.append({
            'id': 'HEARTBLEED',
            'name': 'Heartbleed (CVE-2014-0160)',
            'vulnerable': None,
            'severity': 'info',
            'description': '需要專用工具（如 nmap --script ssl-heartbleed）才能準確檢測。',
            'remediation': '確保 OpenSSL 版本 >= 1.0.1g。',
        })

        return vulns

    # ─── Findings ──────────────────────────────────────

    def _analyze_findings(self, result):
        """分析結果，產生安全發現"""
        findings = result['findings']
        cert = result.get('certificate') or {}
        protocols = result.get('protocols', {})
        hsts = result.get('hsts') or {}
        chain_valid = result.get('chain_valid')
        vulns = result.get('vulnerabilities', [])

        # ── 憑證鏈 ──
        if chain_valid is False:
            findings.append({
                'severity': 'critical',
                'title': '憑證鏈不受信任',
                'description': result.get('chain_error', '憑證鏈驗證失敗'),
                'remediation': '安裝正確的中繼憑證，或使用受信任 CA 簽發的憑證。',
            })
        elif chain_valid is True:
            findings.append({
                'severity': 'info',
                'title': '憑證鏈受信任',
                'description': '憑證鏈已通過系統 CA 驗證。',
                'remediation': '',
            })

        # ── 憑證本身 ──
        if cert:
            if cert.get('is_expired'):
                findings.append({
                    'severity': 'critical',
                    'title': 'SSL 憑證已過期',
                    'description': f"憑證已過期 {abs(cert.get('days_remaining', 0))} 天",
                    'remediation': '立即更新 SSL 憑證。可使用 Let\'s Encrypt 免費取得。',
                })
            elif cert.get('days_remaining') is not None and cert['days_remaining'] < 30:
                findings.append({
                    'severity': 'high',
                    'title': 'SSL 憑證即將過期',
                    'description': f"憑證將在 {cert['days_remaining']} 天內過期",
                    'remediation': '盡快更新憑證，建議設定自動續期。',
                })

            if cert.get('is_self_signed'):
                findings.append({
                    'severity': 'high',
                    'title': '自簽憑證',
                    'description': '使用自簽憑證，瀏覽器會顯示安全警告',
                    'remediation': '使用受信任 CA 簽發的憑證（如 Let\'s Encrypt）。',
                })

            key_bits = cert.get('key_bits')
            if key_bits and key_bits < 2048 and cert.get('key_algorithm') != 'ECDSA':
                findings.append({
                    'severity': 'high',
                    'title': '金鑰長度不足',
                    'description': f'公鑰長度約 {key_bits} bits，建議 RSA 至少 2048 bits',
                    'remediation': '重新產生至少 2048 bits 的 RSA 金鑰，或使用 256 bits ECDSA。',
                })

        # ── 協定 ──
        if protocols.get('SSLv3'):
            findings.append({
                'severity': 'critical',
                'title': '支援 SSLv3',
                'description': 'SSLv3 存在 POODLE 等嚴重漏洞，已被全面棄用。',
                'remediation': '在伺服器設定中停用 SSLv3。',
            })
        if protocols.get('TLSv1.0'):
            findings.append({
                'severity': 'medium',
                'title': '支援 TLS 1.0',
                'description': 'TLS 1.0 已於 2020 年棄用（RFC 8996），應停用。',
                'remediation': '在伺服器設定中停用 TLS 1.0，僅保留 TLS 1.2+。',
            })
        if protocols.get('TLSv1.1'):
            findings.append({
                'severity': 'medium',
                'title': '支援 TLS 1.1',
                'description': 'TLS 1.1 已於 2020 年棄用（RFC 8996），應停用。',
                'remediation': '在伺服器設定中停用 TLS 1.1，僅保留 TLS 1.2+。',
            })
        if not protocols.get('TLSv1.2') and not protocols.get('TLSv1.3'):
            findings.append({
                'severity': 'critical',
                'title': '不支援 TLS 1.2 或 1.3',
                'description': '缺乏現代 TLS 支援，存在嚴重安全風險',
                'remediation': '啟用 TLS 1.2 和 TLS 1.3。',
            })
        if protocols.get('TLSv1.3'):
            findings.append({
                'severity': 'info',
                'title': '支援 TLS 1.3',
                'description': '使用最新 TLS 協定，安全性良好。',
                'remediation': '',
            })

        # ── Forward Secrecy ──
        if result.get('forward_secrecy') is False:
            findings.append({
                'severity': 'medium',
                'title': '不支援 Forward Secrecy',
                'description': '伺服器不支援 ECDHE/DHE 金鑰交換，無法提供前向保密。',
                'remediation': '啟用 ECDHE cipher suite 以支援 Perfect Forward Secrecy。',
            })
        elif result.get('forward_secrecy') is True:
            findings.append({
                'severity': 'info',
                'title': '支援 Forward Secrecy',
                'description': '伺服器支援 ECDHE/DHE，提供前向保密保護。',
                'remediation': '',
            })

        # ── HSTS ──
        if not hsts.get('enabled'):
            findings.append({
                'severity': 'medium',
                'title': '未啟用 HSTS',
                'description': '建議啟用 HTTP Strict Transport Security 防止降級攻擊。',
                'remediation': '加入回應標頭: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            })
        elif hsts.get('max_age', 0) < 31536000:
            findings.append({
                'severity': 'low',
                'title': 'HSTS max-age 過短',
                'description': f"max-age={hsts.get('max_age', 0)}，建議至少 31536000 (1 年)",
                'remediation': '將 max-age 設為至少 31536000（一年）。',
            })

        # ── 漏洞摘要 ──
        active_vulns = [v for v in vulns if v.get('vulnerable') is True]
        if active_vulns:
            critical_vulns = [v for v in active_vulns if v['severity'] == 'critical']
            high_vulns = [v for v in active_vulns if v['severity'] == 'high']
            if critical_vulns:
                findings.append({
                    'severity': 'critical',
                    'title': f'偵測到 {len(critical_vulns)} 個嚴重漏洞',
                    'description': '、'.join(v['id'] for v in critical_vulns),
                    'remediation': '請立即修復上述漏洞，參閱各漏洞的修復建議。',
                })
            if high_vulns:
                findings.append({
                    'severity': 'high',
                    'title': f'偵測到 {len(high_vulns)} 個高風險漏洞',
                    'description': '、'.join(v['id'] for v in high_vulns),
                    'remediation': '請儘速修復上述漏洞。',
                })

    # ─── 評等 ──────────────────────────────────────────

    def _calculate_grade(self, result):
        """計算 SSL 評等 A+ ~ F"""
        cert = result.get('certificate') or {}
        protocols = result.get('protocols', {})
        hsts = result.get('hsts') or {}
        vulns = result.get('vulnerabilities', [])
        active_vulns = [v for v in vulns if v.get('vulnerable') is True]
        active_vuln_ids = {v['id'] for v in active_vulns}

        key_bits = cert.get('key_bits')
        key_algo = cert.get('key_algorithm', '')

        # F 條件
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

        # D 條件
        if key_bits and key_bits < 2048 and key_algo != 'ECDSA':
            return 'D'
        if active_vuln_ids & {'SWEET32', 'FREAK'}:
            return 'D'

        # C 條件
        if protocols.get('TLSv1.0') or protocols.get('TLSv1.1'):
            return 'C'
        if 'RC4' in active_vuln_ids:
            return 'C'

        # B 條件
        if not result.get('forward_secrecy'):
            return 'B'
        if active_vuln_ids & {'CRIME', 'BEAST'}:
            return 'B'
        if not hsts.get('enabled'):
            return 'B'

        # A+ 條件
        has_tls13 = protocols.get('TLSv1.3', False)
        has_preload = hsts.get('preload', False)
        has_subdomain = hsts.get('include_subdomains', False)
        no_vulns = len(active_vulns) == 0

        key_ok = (key_algo == 'ECDSA') or (key_bits and key_bits >= 2048)
        if has_tls13 and has_preload and has_subdomain and no_vulns and key_ok:
            return 'A+'

        return 'A'
