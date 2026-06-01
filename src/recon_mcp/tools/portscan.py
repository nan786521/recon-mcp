"""TCP port scanning — pure standard library, single host, with built-in guardrails.

Performs a TCP connect scan against a single host. Deliberately scoped to one
target with a hard cap on the number of ports per call, so it cannot be used as
a mass scanner. For authorized testing, CTF, and education only.
"""

import socket
import concurrent.futures

# Hard limits (guardrails)
MAX_PORTS_PER_SCAN = 1024     # refuse to scan more ports than this in one call
MAX_CONCURRENCY = 100         # cap on parallel connections

# A small, well-known service map for labelling open ports.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

# Default port set when the caller does not specify ports.
DEFAULT_PORTS = sorted(COMMON_PORTS)


class PortScanError(ValueError):
    """Raised when a scan request violates the guardrails or is malformed."""


def parse_ports(spec):
    """Parse a port specification into a sorted, de-duplicated list of ints.

    Accepts a list of ints, or a string like "22,80,443" or "1-1024" or
    "1-100,443,8080". Enforces the 1..65535 range and the MAX_PORTS_PER_SCAN cap.
    """
    if spec is None:
        return list(DEFAULT_PORTS)

    ports = set()
    items = spec if isinstance(spec, list) else str(spec).split(",")
    for item in items:
        token = str(item).strip()
        if not token:
            continue
        if "-" in token:
            lo_s, hi_s = token.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, hi + 1):
                ports.add(p)
        else:
            ports.add(int(token))

    for p in ports:
        if not (1 <= p <= 65535):
            raise PortScanError(f"port {p} is out of range (1-65535)")

    if not ports:
        raise PortScanError("no valid ports specified")
    if len(ports) > MAX_PORTS_PER_SCAN:
        raise PortScanError(
            f"requested {len(ports)} ports; this tool scans at most "
            f"{MAX_PORTS_PER_SCAN} ports per call (single-host recon, not mass scanning)"
        )
    return sorted(ports)


class PortScanner:
    """A single-host TCP connect scanner with concurrency and port caps."""

    def __init__(self, timeout=1.0, max_concurrency=MAX_CONCURRENCY):
        self.timeout = timeout
        self.max_concurrency = max(1, min(int(max_concurrency), MAX_CONCURRENCY))

    def scan(self, host, ports=None):
        """Scan a single host. Returns a structured result dict."""
        port_list = parse_ports(ports)

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return {"host": host, "error": f"DNS resolution failed: {e}"}

        open_ports = []
        workers = min(self.max_concurrency, len(port_list))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._probe, ip, p): p for p in port_list}
            for fut in concurrent.futures.as_completed(futures):
                port = futures[fut]
                if fut.result():
                    open_ports.append({
                        "port": port,
                        "service": COMMON_PORTS.get(port, "unknown"),
                    })

        open_ports.sort(key=lambda r: r["port"])
        return {
            "host": host,
            "ip": ip,
            "scanned": len(port_list),
            "open_count": len(open_ports),
            "open_ports": open_ports,
        }

    def _probe(self, ip, port):
        """Return True if a TCP connection to (ip, port) succeeds."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                return sock.connect_ex((ip, port)) == 0
        except OSError:
            return False
