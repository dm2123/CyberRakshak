"""Basic UDP port scanner.

UDP is connectionless, so results are heuristic:
  - a UDP reply  -> port is OPEN
  - no reply     -> port is OPEN|FILTERED (ambiguous; firewalls drop silently)

Runs with normal user privileges (no raw sockets needed).
"""

import socket
from concurrent.futures import ThreadPoolExecutor

# A tiny payload that sometimes provokes a reply from common UDP services
PROBE_PAYLOAD = b"\x00"


class UDPScanner:
    def __init__(self, target, start_port=1, end_port=1000, threads=100, timeout=1.5):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.results = []  # list of (port, state)

    def _check_port(self, port):
        """Probe one UDP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            # "connect" the UDP socket so ICMP errors surface as exceptions
            try:
                sock.connect((self.target, port))
                sock.send(PROBE_PAYLOAD)
                try:
                    sock.recv(1024)
                    state = "open"
                except socket.timeout:
                    state = "open|filtered"
            except ConnectionRefusedError:
                state = "closed"
            except OSError:
                # ICMP port-unreachable on some systems surfaces as ECONNREFUSED
                state = "closed"
            sock.close()
            if state != "closed":
                self.results.append((port, state))
                print(f"[+] Port {port}/udp  {state}")
        except Exception:
            pass

    def scan(self):
        """Run the UDP scan over the configured range."""
        return self.scan_ports(range(self.start_port, self.end_port + 1))

    def scan_ports(self, ports):
        """Scan an explicit list/iterable of UDP ports."""
        ports = list(ports)
        self.results = []
        print(f"[*] Scanning {len(ports)} UDP ports on {self.target}...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._check_port, ports)
        self.results.sort()
        return self.results
