"""Small shared helpers."""

import ssl
import urllib.error
import urllib.request

from recon_mcp import __version__

USER_AGENT = f"recon-kit-mcp/{__version__} (+https://github.com/nan786521/recon-mcp)"


def http_get(url, timeout=5.0, headers=None, verify=True, max_bytes=2_000_000):
    """Fetch a URL over HTTP(S) with the standard library.

    Follows redirects (urllib's default). Returns a dict with `status`,
    `headers` (lowercase keys), and `body` (decoded text, truncated to
    `max_bytes`). On a transport error returns `{"error": ...}` with no status.
    HTTP error responses (4xx/5xx) are returned normally with their status and
    body, not as errors, so callers can inspect them.

    `verify=False` disables TLS certificate verification — use it only when
    probing a target whose certificate may be broken but whose content is still
    wanted (e.g. fetching /security.txt); keep it True for trusted APIs.
    """
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")

    ctx = None
    if url.lower().startswith("https"):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status, raw_headers, raw = resp.status, resp.getheaders(), resp.read(max_bytes + 1)
        resp.close()
    except urllib.error.HTTPError as e:  # 4xx/5xx still carry headers and a body
        status, raw_headers, raw = e.code, list(e.headers.items()), e.read(max_bytes + 1)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

    truncated = len(raw) > max_bytes
    body = raw[:max_bytes].decode("utf-8", errors="replace")
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in raw_headers},
        "body": body,
        "truncated": truncated,
    }


def normalize_host(value):
    """Reduce a user/agent-supplied target to a bare hostname or domain.

    Forgiving of common inputs: strips a URL scheme, any path/query, a trailing
    dot, and a `:port` suffix (only when it's clearly host:port, so IPv6
    literals with multiple colons are left intact). Returns lowercase.

        "https://Example.com/path?q=1" -> "example.com"
        "example.com:443"              -> "example.com"
        "example.com."                 -> "example.com"
    """
    v = str(value).strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]          # drop path
    v = v.split("?", 1)[0]          # drop query
    v = v.strip("[]")               # bare IPv6 brackets, if any
    if v.count(":") == 1:           # host:port — strip only a numeric port
        head, _, tail = v.partition(":")
        if tail.isdigit():
            v = head
    return v.strip().rstrip(".").lower()
