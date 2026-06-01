"""HTTP 安全標頭深度分析引擎 — 12 項安全標頭檢測與評分"""

import http.client
import ssl
import socket


# 標頭檢查定義：(header, weight, severity, description_zh, remediation_zh, check_fn_name)
HEADER_CHECKS = [
    {
        'header': 'Content-Security-Policy',
        'weight': 15,
        'severity': 'high',
        'description': '限制腳本、樣式、圖片等資源的載入來源，有效防禦 XSS 攻擊',
        'remediation': "設定 Content-Security-Policy: default-src 'self'; script-src 'self'",
        'check_fn': '_check_csp',
    },
    {
        'header': 'Strict-Transport-Security',
        'weight': 15,
        'severity': 'high',
        'description': '強制瀏覽器僅透過 HTTPS 連線，防止降級攻擊',
        'remediation': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        'check_fn': '_check_hsts',
    },
    {
        'header': 'X-Frame-Options',
        'weight': 10,
        'severity': 'medium',
        'description': '防止頁面被嵌入 iframe，防禦點擊劫持 (Clickjacking)',
        'remediation': '設定 X-Frame-Options: DENY 或 SAMEORIGIN',
        'check_fn': '_check_x_frame_options',
    },
    {
        'header': 'X-Content-Type-Options',
        'weight': 10,
        'severity': 'medium',
        'description': '防止瀏覽器進行 MIME 類型猜測，降低 MIME 混淆攻擊風險',
        'remediation': '設定 X-Content-Type-Options: nosniff',
        'check_fn': '_check_x_content_type_options',
    },
    {
        'header': 'X-XSS-Protection',
        'weight': 5,
        'severity': 'low',
        'description': '啟用瀏覽器內建 XSS 過濾器（已棄用但部分瀏覽器仍支援）',
        'remediation': '設定 X-XSS-Protection: 1; mode=block',
        'check_fn': '_check_x_xss_protection',
    },
    {
        'header': 'Referrer-Policy',
        'weight': 8,
        'severity': 'medium',
        'description': '控制 HTTP Referer 標頭的發送規則，保護使用者隱私',
        'remediation': '設定 Referrer-Policy: strict-origin-when-cross-origin',
        'check_fn': '_check_referrer_policy',
    },
    {
        'header': 'Permissions-Policy',
        'weight': 8,
        'severity': 'medium',
        'description': '限制瀏覽器 API 的使用（攝影機、麥克風、地理位置等）',
        'remediation': '設定 Permissions-Policy: camera=(), microphone=(), geolocation=()',
        'check_fn': '_check_permissions_policy',
    },
    {
        'header': 'Cache-Control',
        'weight': 5,
        'severity': 'low',
        'description': '控制瀏覽器快取行為，防止敏感資料被快取',
        'remediation': '設定 Cache-Control: no-store, no-cache, must-revalidate',
        'check_fn': '_check_cache_control',
    },
    {
        'header': 'X-Permitted-Cross-Domain-Policies',
        'weight': 5,
        'severity': 'low',
        'description': '限制 Flash/PDF 的跨域策略載入',
        'remediation': '設定 X-Permitted-Cross-Domain-Policies: none',
        'check_fn': '_check_cross_domain_policies',
    },
    {
        'header': 'Cross-Origin-Embedder-Policy',
        'weight': 5,
        'severity': 'low',
        'description': '要求跨來源資源明確授權嵌入，提升隔離安全性',
        'remediation': '設定 Cross-Origin-Embedder-Policy: require-corp',
        'check_fn': '_check_coep',
    },
    {
        'header': 'Cross-Origin-Opener-Policy',
        'weight': 5,
        'severity': 'low',
        'description': '隔離瀏覽器上下文，防止跨來源視窗互動攻擊',
        'remediation': '設定 Cross-Origin-Opener-Policy: same-origin',
        'check_fn': '_check_coop',
    },
    {
        'header': 'Cross-Origin-Resource-Policy',
        'weight': 5,
        'severity': 'low',
        'description': '限制資源被跨來源載入，防止資料洩漏',
        'remediation': '設定 Cross-Origin-Resource-Policy: same-origin',
        'check_fn': '_check_corp',
    },
]

# 總權重
TOTAL_WEIGHT = sum(h['weight'] for h in HEADER_CHECKS)


class HTTPHeadersAnalyzer:
    """HTTP 安全標頭深度分析器"""

    def __init__(self, timeout=5.0):
        self.timeout = timeout

    def analyze(self, target, port=80, use_ssl=False):
        """分析目標的 HTTP 安全標頭"""
        result = {
            'target': target,
            'port': port,
            'use_ssl': use_ssl,
            'score': 0,
            'grade': 'F',
            'headers_raw': {},
            'checks': [],
            'summary': {'passed': 0, 'failed': 0, 'warned': 0, 'total': len(HEADER_CHECKS)},
            'findings': [],
            'server': '',
        }

        # 取得 headers
        headers = self._fetch_headers(target, port, use_ssl)
        if headers is None:
            result['error'] = f'無法連線至 {target}:{port}'
            return result

        result['headers_raw'] = headers
        result['server'] = headers.get('server', '')

        # 逐項檢查
        for check_def in HEADER_CHECKS:
            header_name = check_def['header']
            header_value = headers.get(header_name.lower())

            check_fn = getattr(self, check_def['check_fn'], None)
            if check_fn:
                check_result = check_fn(header_value)
            else:
                check_result = self._check_exists(header_value)

            result['checks'].append({
                'header': header_name,
                'status': check_result['status'],
                'severity': check_def['severity'],
                'weight': check_def['weight'],
                'value': header_value or '',
                'description': check_def['description'],
                'detail': check_result.get('detail', ''),
                'remediation': check_def['remediation'] if check_result['status'] != 'pass' else '',
            })

        # 統計
        for c in result['checks']:
            if c['status'] == 'pass':
                result['summary']['passed'] += 1
            elif c['status'] == 'warn':
                result['summary']['warned'] += 1
            else:
                result['summary']['failed'] += 1

        # 計算分數與評等
        result['score'] = self._calculate_score(result['checks'])
        result['grade'] = self._calculate_grade(result['score'])

        # 轉換為標準 findings
        result['findings'] = self._to_findings(result['checks'])

        return result

    # ==================== HTTP 連線 ====================

    def _fetch_headers(self, target, port, use_ssl):
        """取得 HTTP 回應標頭"""
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(target, port, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(target, port, timeout=self.timeout)

            conn.request('GET', '/', headers={'User-Agent': 'SecurityAudit/1.0'})
            resp = conn.getresponse()
            resp.read()

            # 收集所有 headers (小寫 key)
            headers = {}
            for key, val in resp.getheaders():
                headers[key.lower()] = val

            conn.close()
            return headers
        except Exception:
            return None

    # ==================== 個別標頭檢查 ====================

    def _check_exists(self, value):
        """基本存在性檢查"""
        if value:
            return {'status': 'pass', 'detail': '已設定'}
        return {'status': 'fail', 'detail': '未設定'}

    def _check_csp(self, value):
        """Content-Security-Policy 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定 CSP，無法限制資源載入來源'}

        issues = []
        if "'unsafe-inline'" in value:
            issues.append("含 'unsafe-inline'，允許內聯腳本")
        if "'unsafe-eval'" in value:
            issues.append("含 'unsafe-eval'，允許動態程式碼執行")
        if 'default-src *' in value or "default-src '*'" in value:
            issues.append("default-src 使用萬用字元 *")
        if 'script-src *' in value:
            issues.append("script-src 使用萬用字元 *")

        if issues:
            return {'status': 'warn', 'detail': '；'.join(issues)}
        return {'status': 'pass', 'detail': 'CSP 設定良好'}

    def _check_hsts(self, value):
        """Strict-Transport-Security 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定 HSTS，瀏覽器不會強制 HTTPS'}

        issues = []
        # 解析 max-age
        if 'max-age=' in value:
            try:
                max_age = int(value.split('max-age=')[1].split(';')[0].strip())
                if max_age < 31536000:
                    issues.append(f'max-age={max_age}，建議至少 31536000（1 年）')
            except (ValueError, IndexError):
                issues.append('max-age 無法解析')
        else:
            issues.append('缺少 max-age 指令')

        if 'includesubdomains' not in value.lower():
            issues.append('未包含 includeSubDomains')

        if issues:
            return {'status': 'warn', 'detail': '；'.join(issues)}
        return {'status': 'pass', 'detail': 'HSTS 設定完善'}

    def _check_x_frame_options(self, value):
        """X-Frame-Options 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定，頁面可能被嵌入惡意 iframe'}

        val = value.upper().strip()
        if val in ('DENY', 'SAMEORIGIN'):
            return {'status': 'pass', 'detail': f'設定為 {val}'}
        if 'ALLOW-FROM' in val:
            return {'status': 'warn', 'detail': 'ALLOW-FROM 已被多數瀏覽器棄用'}
        return {'status': 'warn', 'detail': f'非預期值: {value}'}

    def _check_x_content_type_options(self, value):
        """X-Content-Type-Options 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定，瀏覽器可能進行 MIME 猜測'}

        if value.strip().lower() == 'nosniff':
            return {'status': 'pass', 'detail': '已設定 nosniff'}
        return {'status': 'warn', 'detail': f'非預期值: {value}，應為 nosniff'}

    def _check_x_xss_protection(self, value):
        """X-XSS-Protection 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定（此標頭已棄用，但仍建議設定）'}

        if '1' in value and 'mode=block' in value:
            return {'status': 'pass', 'detail': '已啟用並設定 mode=block'}
        if value.strip() == '0':
            return {'status': 'warn', 'detail': '已明確停用 XSS 過濾器'}
        if '1' in value:
            return {'status': 'warn', 'detail': '已啟用但未設定 mode=block'}
        return {'status': 'warn', 'detail': f'非預期值: {value}'}

    def _check_referrer_policy(self, value):
        """Referrer-Policy 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定，瀏覽器將使用預設 Referrer 策略'}

        safe_policies = {
            'no-referrer', 'no-referrer-when-downgrade',
            'strict-origin', 'strict-origin-when-cross-origin',
            'same-origin', 'origin', 'origin-when-cross-origin',
        }
        val = value.strip().lower()
        if val in safe_policies:
            return {'status': 'pass', 'detail': f'策略: {val}'}
        if val == 'unsafe-url':
            return {'status': 'warn', 'detail': 'unsafe-url 會洩漏完整 URL'}
        return {'status': 'warn', 'detail': f'非預期值: {value}'}

    def _check_permissions_policy(self, value):
        """Permissions-Policy 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定，瀏覽器 API 未受限制'}

        restricted = []
        for feature in ('camera', 'microphone', 'geolocation', 'payment'):
            if feature in value:
                restricted.append(feature)

        if len(restricted) >= 2:
            return {'status': 'pass', 'detail': f"已限制: {', '.join(restricted)}"}
        return {'status': 'warn', 'detail': '已設定但限制項目較少，建議增加'}

    def _check_cache_control(self, value):
        """Cache-Control 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定快取控制'}

        val = value.lower()
        if 'no-store' in val or 'private' in val:
            return {'status': 'pass', 'detail': '已設定適當的快取控制'}
        if 'public' in val:
            return {'status': 'warn', 'detail': '設定為 public，敏感頁面不應被公開快取'}
        return {'status': 'pass', 'detail': f'快取策略: {value}'}

    def _check_cross_domain_policies(self, value):
        """X-Permitted-Cross-Domain-Policies 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定跨域策略限制'}

        val = value.strip().lower()
        if val in ('none', 'master-only'):
            return {'status': 'pass', 'detail': f'策略: {val}'}
        return {'status': 'warn', 'detail': f'策略 {val} 可能過於寬鬆'}

    def _check_coep(self, value):
        """Cross-Origin-Embedder-Policy 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定 COEP'}

        if 'require-corp' in value.lower():
            return {'status': 'pass', 'detail': '已設定 require-corp'}
        if 'credentialless' in value.lower():
            return {'status': 'pass', 'detail': '已設定 credentialless'}
        return {'status': 'warn', 'detail': f'值: {value}'}

    def _check_coop(self, value):
        """Cross-Origin-Opener-Policy 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定 COOP'}

        if 'same-origin' in value.lower():
            return {'status': 'pass', 'detail': '已設定 same-origin'}
        return {'status': 'warn', 'detail': f'值: {value}'}

    def _check_corp(self, value):
        """Cross-Origin-Resource-Policy 檢查"""
        if not value:
            return {'status': 'fail', 'detail': '未設定 CORP'}

        val = value.strip().lower()
        if val in ('same-origin', 'same-site'):
            return {'status': 'pass', 'detail': f'策略: {val}'}
        if val == 'cross-origin':
            return {'status': 'warn', 'detail': '設定為 cross-origin，允許跨域載入'}
        return {'status': 'warn', 'detail': f'值: {value}'}

    # ==================== 評分 ====================

    def _calculate_score(self, checks):
        """加權計分（0-100）"""
        earned = 0
        for c in checks:
            if c['status'] == 'pass':
                earned += c['weight']
            elif c['status'] == 'warn':
                earned += c['weight'] * 0.5

        return round(earned / TOTAL_WEIGHT * 100)

    def _calculate_grade(self, score):
        """分數轉評等"""
        if score >= 95:
            return 'A+'
        if score >= 85:
            return 'A'
        if score >= 70:
            return 'B'
        if score >= 50:
            return 'C'
        if score >= 30:
            return 'D'
        return 'F'

    # ==================== 轉換 ====================

    def _to_findings(self, checks):
        """轉換為標準 finding 格式"""
        findings = []
        for c in checks:
            if c['status'] == 'pass':
                continue
            findings.append({
                'id': f"http-header-{c['header'].lower().replace('-', '_')}",
                'category': 'http_headers',
                'severity': c['severity'] if c['status'] == 'fail' else 'low',
                'title': f"{'缺少' if c['status'] == 'fail' else '需改善'} {c['header']}",
                'description': c['detail'],
                'evidence': f"當前值: {c['value'] or '(未設定)'}",
                'remediation': c['remediation'],
            })
        return findings
