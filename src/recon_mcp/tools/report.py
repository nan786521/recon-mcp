"""Aggregate recon report — combines DNS, TLS, and HTTP-header results into one
graded overview. Pure functions (no network) so they are easy to test.
"""

# Worst-to-best ordering; index 0 is best. A domain's overall posture is treated
# as only as strong as its weakest component.
_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5}


def worst_grade(grades):
    """Return the worst (lowest) letter grade from an iterable.

    Ignores falsy/unknown grades. Compares on the first character so "A+"/"B-"
    style grades still work. Returns None if nothing is comparable.
    """
    ranked = []
    for g in grades:
        if not g:
            continue
        rank = _GRADE_RANK.get(str(g)[0].upper())
        if rank is not None:
            ranked.append((rank, str(g)[0].upper()))
    if not ranked:
        return None
    return max(ranked, key=lambda r: r[0])[1]


def _normalize_findings(findings):
    """Reduce heterogeneous finding shapes to {severity, label, detail},
    keeping only actionable items (drops "ok" and "info")."""
    out = []
    for f in findings or []:
        sev = f.get("severity")
        if sev in (None, "ok", "info"):
            continue
        label = next((f[k] for k in ("check", "title", "name") if f.get(k)), "")
        detail = next((f[k] for k in ("message", "description") if f.get(k)), "")
        out.append({"severity": sev, "label": label, "detail": detail})
    return out


def _component(grade, issues, **extra):
    comp = {"grade": grade, "issues": issues}
    comp.update({k: v for k, v in extra.items() if v is not None})
    return comp


def build_report(domain, dns_result, tls_result, headers_result):
    """Combine the three component results into one graded report.

    Each component result may instead be `{"error": ...}`; that component is
    reported with grade None and surfaced as an error issue, but does not break
    the overall report.
    """
    # --- email (from dns_recon's assessment) ---
    email_assess = (dns_result or {}).get("email", {}).get("assessment", {}) or {}
    email = _component(
        email_assess.get("grade"),
        _normalize_findings(email_assess.get("findings")),
        summary=email_assess.get("summary"),
    )

    # --- TLS ---
    if tls_result and not tls_result.get("error"):
        tls_issues = _normalize_findings(tls_result.get("findings"))
        tls_issues += [
            {"severity": v.get("severity", "high"), "label": v.get("name", "vulnerability"),
             "detail": v.get("description", "")}
            for v in tls_result.get("vulnerabilities", [])
            if v.get("vulnerable") is True
        ]
        tls = _component(tls_result.get("grade"), tls_issues)
    else:
        tls = _component(None, [{"severity": "error", "label": "tls_check",
                                 "detail": (tls_result or {}).get("error", "no result")}])

    # --- HTTP headers ---
    if headers_result and not headers_result.get("error"):
        headers = _component(
            headers_result.get("grade"),
            _normalize_findings(headers_result.get("findings")),
            score=headers_result.get("score"),
        )
    else:
        headers = _component(None, [{"severity": "error", "label": "http_headers_audit",
                                     "detail": (headers_result or {}).get("error", "no result")}])

    # --- IP (best-effort, from DNS A record) ---
    ip = None
    a_records = (dns_result or {}).get("records", {}).get("A", []) if dns_result else []
    if a_records:
        ip = a_records[0].get("value")

    overall = worst_grade([email["grade"], tls["grade"], headers["grade"]])
    total_issues = len(email["issues"]) + len(tls["issues"]) + len(headers["issues"])

    if overall is None:
        summary = f"Could not assess {domain} — all checks failed or returned no grade."
    else:
        summary = (
            f"Overall posture {overall} for {domain}: "
            f"email {email['grade']}, TLS {tls['grade']}, headers {headers['grade']}; "
            f"{total_issues} actionable issue(s)."
        )

    return {
        "domain": domain,
        "ip": ip,
        "overall_grade": overall,
        "summary": summary,
        "components": {"email": email, "tls": tls, "headers": headers},
    }
