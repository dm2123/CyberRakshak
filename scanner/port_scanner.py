"""Multi-threaded TCP port scanner."""

import socket
from concurrent.futures import ThreadPoolExecutor


class PortScanner:
    def __init__(self, target, start_port=1, end_port=1000, threads=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.open_ports = []

    def _check_port(self, port):
        """Check if a single port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            if result == 0:
                self.open_ports.append(port)
                print(f"[+] Port {port} is OPEN")
        except Exception:
            pass

    def scan(self):
        """Run the port scan over the configured range."""
        return self.scan_ports(range(self.start_port, self.end_port + 1))

    def scan_ports(self, ports):
        """Scan an explicit list/iterable of ports. Returns sorted open ports."""
        ports = list(ports)
        self.open_ports = []
        print(f"[*] Scanning {len(ports)} TCP ports on {self.target}...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._check_port, ports)
        self.open_ports.sort()
        return self.open_ports
