"""HTTP security header deep analysis engine — detection and scoring of 12 security headers"""

import http.client
import ssl


# Header check definitions: (header, weight, severity, description_zh, remediation_zh, check_fn_name)
HEADER_CHECKS = [
    {
        'header': 'Content-Security-Policy',
        'weight': 15,
        'severity': 'high',
        'description': 'Restricts the load sources for scripts, styles, images, and other resources, effectively mitigating XSS attacks',
        'remediation': "Set Content-Security-Policy: default-src 'self'; script-src 'self'",
        'check_fn': '_check_csp',
    },
    {
        'header': 'Strict-Transport-Security',
        'weight': 15,
        'severity': 'high',
        'description': 'Forces the browser to connect only over HTTPS, preventing downgrade attacks',
        'remediation': 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        'check_fn': '_check_hsts',
    },
    {
        'header': 'X-Frame-Options',
        'weight': 10,
        'severity': 'medium',
        'description': 'Prevents the page from being embedded in an iframe, mitigating clickjacking',
        'remediation': 'Set X-Frame-Options: DENY or SAMEORIGIN',
        'check_fn': '_check_x_frame_options',
    },
    {
        'header': 'X-Content-Type-Options',
        'weight': 10,
        'severity': 'medium',
        'description': 'Prevents the browser from MIME-type sniffing, reducing the risk of MIME confusion attacks',
        'remediation': 'Set X-Content-Type-Options: nosniff',
        'check_fn': '_check_x_content_type_options',
    },
    {
        'header': 'X-XSS-Protection',
        'weight': 5,
        'severity': 'low',
        'description': "Enables the browser's built-in XSS filter (deprecated, but still supported by some browsers)",
        'remediation': 'Set X-XSS-Protection: 1; mode=block',
        'check_fn': '_check_x_xss_protection',
    },
    {
        'header': 'Referrer-Policy',
        'weight': 8,
        'severity': 'medium',
        'description': 'Controls the rules for sending the HTTP Referer header, protecting user privacy',
        'remediation': 'Set Referrer-Policy: strict-origin-when-cross-origin',
        'check_fn': '_check_referrer_policy',
    },
    {
        'header': 'Permissions-Policy',
        'weight': 8,
        'severity': 'medium',
        'description': 'Restricts the use of browser APIs (camera, microphone, geolocation, etc.)',
        'remediation': 'Set Permissions-Policy: camera=(), microphone=(), geolocation=()',
        'check_fn': '_check_permissions_policy',
    },
    {
        'header': 'Cache-Control',
        'weight': 5,
        'severity': 'low',
        'description': 'Controls browser caching behavior, preventing sensitive data from being cached',
        'remediation': 'Set Cache-Control: no-store, no-cache, must-revalidate',
        'check_fn': '_check_cache_control',
    },
    {
        'header': 'X-Permitted-Cross-Domain-Policies',
        'weight': 5,
        'severity': 'low',
        'description': 'Restricts the cross-domain policy loading of Flash/PDF',
        'remediation': 'Set X-Permitted-Cross-Domain-Policies: none',
        'check_fn': '_check_cross_domain_policies',
    },
    {
        'header': 'Cross-Origin-Embedder-Policy',
        'weight': 5,
        'severity': 'low',
        'description': 'Requires cross-origin resources to be explicitly authorized for embedding, improving isolation security',
        'remediation': 'Set Cross-Origin-Embedder-Policy: require-corp',
        'check_fn': '_check_coep',
    },
    {
        'header': 'Cross-Origin-Opener-Policy',
        'weight': 5,
        'severity': 'low',
        'description': 'Isolates the browsing context, preventing cross-origin window interaction attacks',
        'remediation': 'Set Cross-Origin-Opener-Policy: same-origin',
        'check_fn': '_check_coop',
    },
    {
        'header': 'Cross-Origin-Resource-Policy',
        'weight': 5,
        'severity': 'low',
        'description': 'Restricts resources from being loaded cross-origin, preventing data leakage',
        'remediation': 'Set Cross-Origin-Resource-Policy: same-origin',
        'check_fn': '_check_corp',
    },
]

# Total weight
TOTAL_WEIGHT = sum(h['weight'] for h in HEADER_CHECKS)


class HTTPHeadersAnalyzer:
    """HTTP security header deep analyzer"""

    def __init__(self, timeout=5.0):
        self.timeout = timeout

    def analyze(self, target, port=80, use_ssl=False):
        """Analyze the target's HTTP security headers"""
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

        # Fetch headers
        headers = self._fetch_headers(target, port, use_ssl)
        if headers is None:
            result['error'] = f'Unable to connect to {target}:{port}'
            return result

        result['headers_raw'] = headers
        result['server'] = headers.get('server', '')

        # Check each item
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

        # Statistics
        for c in result['checks']:
            if c['status'] == 'pass':
                result['summary']['passed'] += 1
            elif c['status'] == 'warn':
                result['summary']['warned'] += 1
            else:
                result['summary']['failed'] += 1

        # Calculate score and grade
        result['score'] = self._calculate_score(result['checks'])
        result['grade'] = self._calculate_grade(result['score'])

        # Convert to standard findings
        result['findings'] = self._to_findings(result['checks'])

        return result

    # ==================== HTTP connection ====================

    def _fetch_headers(self, target, port, use_ssl):
        """Fetch the HTTP response headers"""
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

            # Collect all headers (lowercase key)
            headers = {}
            for key, val in resp.getheaders():
                headers[key.lower()] = val

            conn.close()
            return headers
        except Exception:
            return None

    # ==================== Individual header checks ====================

    def _check_exists(self, value):
        """Basic existence check"""
        if value:
            return {'status': 'pass', 'detail': 'Set'}
        return {'status': 'fail', 'detail': 'Not set'}

    def _check_csp(self, value):
        """Content-Security-Policy check"""
        if not value:
            return {'status': 'fail', 'detail': 'CSP not set; cannot restrict resource load sources'}

        issues = []
        if "'unsafe-inline'" in value:
            issues.append("Contains 'unsafe-inline', allowing inline scripts")
        if "'unsafe-eval'" in value:
            issues.append("Contains 'unsafe-eval', allowing dynamic code execution")
        if 'default-src *' in value or "default-src '*'" in value:
            issues.append("default-src uses the wildcard *")
        if 'script-src *' in value:
            issues.append("script-src uses the wildcard *")

        if issues:
            return {'status': 'warn', 'detail': '; '.join(issues)}
        return {'status': 'pass', 'detail': 'CSP is well configured'}

    def _check_hsts(self, value):
        """Strict-Transport-Security check"""
        if not value:
            return {'status': 'fail', 'detail': 'HSTS not set; the browser will not enforce HTTPS'}

        issues = []
        # Parse max-age
        if 'max-age=' in value:
            try:
                max_age = int(value.split('max-age=')[1].split(';')[0].strip())
                if max_age < 31536000:
                    issues.append(f'max-age={max_age}; recommend at least 31536000 (1 year)')
            except (ValueError, IndexError):
                issues.append('max-age could not be parsed')
        else:
            issues.append('Missing the max-age directive')

        if 'includesubdomains' not in value.lower():
            issues.append('Does not include includeSubDomains')

        if issues:
            return {'status': 'warn', 'detail': '; '.join(issues)}
        return {'status': 'pass', 'detail': 'HSTS is fully configured'}

    def _check_x_frame_options(self, value):
        """X-Frame-Options check"""
        if not value:
            return {'status': 'fail', 'detail': 'Not set; the page may be embedded in a malicious iframe'}

        val = value.upper().strip()
        if val in ('DENY', 'SAMEORIGIN'):
            return {'status': 'pass', 'detail': f'Set to {val}'}
        if 'ALLOW-FROM' in val:
            return {'status': 'warn', 'detail': 'ALLOW-FROM is deprecated in most browsers'}
        return {'status': 'warn', 'detail': f'Unexpected value: {value}'}

    def _check_x_content_type_options(self, value):
        """X-Content-Type-Options check"""
        if not value:
            return {'status': 'fail', 'detail': 'Not set; the browser may perform MIME sniffing'}

        if value.strip().lower() == 'nosniff':
            return {'status': 'pass', 'detail': 'nosniff is set'}
        return {'status': 'warn', 'detail': f'Unexpected value: {value}; should be nosniff'}

    def _check_x_xss_protection(self, value):
        """X-XSS-Protection check"""
        if not value:
            return {'status': 'fail', 'detail': 'Not set (this header is deprecated, but still recommended)'}

        if '1' in value and 'mode=block' in value:
            return {'status': 'pass', 'detail': 'Enabled with mode=block'}
        if value.strip() == '0':
            return {'status': 'warn', 'detail': 'XSS filter is explicitly disabled'}
        if '1' in value:
            return {'status': 'warn', 'detail': 'Enabled but mode=block is not set'}
        return {'status': 'warn', 'detail': f'Unexpected value: {value}'}

    def _check_referrer_policy(self, value):
        """Referrer-Policy check"""
        if not value:
            return {'status': 'fail', 'detail': 'Not set; the browser will use the default Referrer policy'}

        safe_policies = {
            'no-referrer', 'no-referrer-when-downgrade',
            'strict-origin', 'strict-origin-when-cross-origin',
            'same-origin', 'origin', 'origin-when-cross-origin',
        }
        val = value.strip().lower()
        if val in safe_policies:
            return {'status': 'pass', 'detail': f'Policy: {val}'}
        if val == 'unsafe-url':
            return {'status': 'warn', 'detail': 'unsafe-url leaks the full URL'}
        return {'status': 'warn', 'detail': f'Unexpected value: {value}'}

    def _check_permissions_policy(self, value):
        """Permissions-Policy check"""
        if not value:
            return {'status': 'fail', 'detail': 'Not set; browser APIs are unrestricted'}

        restricted = []
        for feature in ('camera', 'microphone', 'geolocation', 'payment'):
            if feature in value:
                restricted.append(feature)

        if len(restricted) >= 2:
            return {'status': 'pass', 'detail': f"Restricted: {', '.join(restricted)}"}
        return {'status': 'warn', 'detail': 'Set, but few items are restricted; recommend adding more'}

    def _check_cache_control(self, value):
        """Cache-Control check"""
        if not value:
            return {'status': 'fail', 'detail': 'Cache control not set'}

        val = value.lower()
        if 'no-store' in val or 'private' in val:
            return {'status': 'pass', 'detail': 'Appropriate cache control is set'}
        if 'public' in val:
            return {'status': 'warn', 'detail': 'Set to public; sensitive pages should not be publicly cached'}
        return {'status': 'pass', 'detail': f'Cache policy: {value}'}

    def _check_cross_domain_policies(self, value):
        """X-Permitted-Cross-Domain-Policies check"""
        if not value:
            return {'status': 'fail', 'detail': 'Cross-domain policy restriction not set'}

        val = value.strip().lower()
        if val in ('none', 'master-only'):
            return {'status': 'pass', 'detail': f'Policy: {val}'}
        return {'status': 'warn', 'detail': f'Policy {val} may be too permissive'}

    def _check_coep(self, value):
        """Cross-Origin-Embedder-Policy check"""
        if not value:
            return {'status': 'fail', 'detail': 'COEP not set'}

        if 'require-corp' in value.lower():
            return {'status': 'pass', 'detail': 'require-corp is set'}
        if 'credentialless' in value.lower():
            return {'status': 'pass', 'detail': 'credentialless is set'}
        return {'status': 'warn', 'detail': f'Value: {value}'}

    def _check_coop(self, value):
        """Cross-Origin-Opener-Policy check"""
        if not value:
            return {'status': 'fail', 'detail': 'COOP not set'}

        if 'same-origin' in value.lower():
            return {'status': 'pass', 'detail': 'same-origin is set'}
        return {'status': 'warn', 'detail': f'Value: {value}'}

    def _check_corp(self, value):
        """Cross-Origin-Resource-Policy check"""
        if not value:
            return {'status': 'fail', 'detail': 'CORP not set'}

        val = value.strip().lower()
        if val in ('same-origin', 'same-site'):
            return {'status': 'pass', 'detail': f'Policy: {val}'}
        if val == 'cross-origin':
            return {'status': 'warn', 'detail': 'Set to cross-origin, allowing cross-domain loading'}
        return {'status': 'warn', 'detail': f'Value: {value}'}

    # ==================== Scoring ====================

    def _calculate_score(self, checks):
        """Weighted scoring (0-100)"""
        earned = 0
        for c in checks:
            if c['status'] == 'pass':
                earned += c['weight']
            elif c['status'] == 'warn':
                earned += c['weight'] * 0.5

        return round(earned / TOTAL_WEIGHT * 100)

    def _calculate_grade(self, score):
        """Convert score to grade"""
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

    # ==================== Conversion ====================

    def _to_findings(self, checks):
        """Convert to the standard finding format"""
        findings = []
        for c in checks:
            if c['status'] == 'pass':
                continue
            findings.append({
                'id': f"http-header-{c['header'].lower().replace('-', '_')}",
                'category': 'http_headers',
                'severity': c['severity'] if c['status'] == 'fail' else 'low',
                'title': f"{'Missing' if c['status'] == 'fail' else 'Needs improvement'} {c['header']}",
                'description': c['detail'],
                'evidence': f"Current value: {c['value'] or '(not set)'}",
                'remediation': c['remediation'],
            })
        return findings
