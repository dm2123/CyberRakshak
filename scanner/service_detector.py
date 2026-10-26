"""Service detection - identify services and versions on open ports.

Uses banner grabbing plus service-specific probes (HTTP, SMTP, FTP...)
to identify WHAT is running behind each open port. 100% original code.
"""

import re
import socket

# Common ports and their likely services (first guess only)
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Probes sent to elicit a banner from quiet services.
# (service name, bytes to send, wait for reply)
PROBES = {
    "HTTP": b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "SMTP": b"EHLO cyberrakshak\r\n",
    "FTP": b"",          # FTP servers greet first
    "SSH": b"",          # SSH servers greet first
    "POP3": b"",         # POP3 servers greet first
    "IMAP": b"",         # IMAP servers greet first
}

# Regexes to pull product + version out of banners.
VERSION_PATTERNS = [
    (r"OpenSSH[_\s]([\d.]+p?\d*)", "OpenSSH"),
    (r"SSH-2\.0-([\w.\-]+)", "SSH"),
    (r"Apache/([\d.]+)", "Apache"),
    (r"nginx/([\d.]+)", "nginx"),
    (r"Microsoft-IIS/([\d.]+)", "IIS"),
    (r"vsftpd ([\d.]+)", "vsftpd"),
    (r"ProFTPD ([\d.]+)", "ProFTPD"),
    (r"Postfix", "Postfix"),
    (r"Exim ([\d.]+)", "Exim"),
    (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB"),
    (r"(\d+\.\d+\.\d+)-MySQL", "MySQL"),
    (r"redis_version:([\d.]+)", "Redis"),
    (r"220[ -]([\w.\-]+).*FTP", "FTP"),
]


class ServiceDetector:
    def __init__(self, target, timeout=3):
        self.target = target
        self.timeout = timeout

    def detect(self, port):
        """Detect service + version on an open port. Returns dict."""
        guess = COMMON_SERVICES.get(port, "unknown")
        banner = self._grab_banner(port, guess)
        product, version = self._parse_version(banner)
        return {
            "port": port,
            "service": product or guess,
            "version": version or "",
            "banner": banner[:120],
        }

    def detect_all(self, ports):
        """Detect services on a list of open ports."""
        return [self.detect(p) for p in ports]

    def _grab_banner(self, port, guess):
        """Connect and try to get a banner, with service-specific probes."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            # First: listen for servers that greet immediately
            data = b""
            try:
                chunk = sock.recv(1024)
                data += chunk
            except socket.timeout:
                pass

            # If silent, try a probe suited to the guessed service
            if not data.strip():
                probe = PROBES.get(guess, b"\r\n")
                try:
                    sock.sendall(probe)
                    try:
                        data = sock.recv(2048)
                    except socket.timeout:
                        data = b""
                except Exception:
                    pass

            # Last resort: generic HTTP probe often reveals web servers
            if not data.strip() and guess not in PROBES:
                try:
                    sock.sendall(PROBES["HTTP"])
                    try:
                        data = sock.recv(2048)
                    except socket.timeout:
                        data = b""
                except Exception:
                    pass

            sock.close()
            return data.decode("utf-8", errors="ignore").strip().replace("\r", " ")
        except Exception:
            return ""

    def _parse_version(self, banner):
        """Extract (product, version) from a banner string."""
        for pattern, product in VERSION_PATTERNS:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                version = m.group(1) if m.groups() else ""
                return product, version
        # Fallback: "Server: X" HTTP header
        m = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
        if m:
            srv = m.group(1).strip()
            vm = re.search(r"([\d.]+)", srv)
            return srv.split("/")[0], vm.group(1) if vm else ""
        return None, None
