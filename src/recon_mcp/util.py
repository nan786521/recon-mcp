"""Small shared helpers."""


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
