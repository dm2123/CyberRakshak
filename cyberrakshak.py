#!/usr/bin/env python3
"""
CyberRakshak - Advanced Defensive Security Toolkit
"Hacker se pehle - CyberRakshak!"

Scan ONLY systems you own or have explicit written permission to test.

Author: Dinesh Singh
"""

import argparse
import sys
from datetime import datetime

from scanner.port_scanner import PortScanner
from scanner.udp_scanner import UDPScanner
from scanner.service_detector import ServiceDetector
from https.tls_auditor import HTTPSAuditor
from web.web_auditor import WebAuditor
from vuln.vuln_db import VulnChecker
from reports.reporter import Reporter
from utils.display import banner

VERSION = "0.3.0"

# Top ~50 most commonly open ports (quick scans)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
    20, 69, 123, 161, 162, 389, 636, 1433, 1521, 2049, 2375,
    2376, 27017, 5000, 5432, 5672, 6379, 8000, 8008, 8888,
    9000, 9090, 9200, 11211, 27018, 3388, 4848, 5985, 5986,
]

TLS_PORTS = {443, 8443}


def _speaks_tls(target, port, timeout=3):
    """Quick probe: does this open port complete a TLS handshake?"""
    import socket
    import ssl
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except Exception:
            pass
        sock = socket.create_connection((target, port), timeout=timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=target)
        ssock.close()
        return True
    except Exception:
        return False


def parse_ports(spec):
    """Parse '1-1000' or '22,80,443' into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-", 1))
            ports.update(range(max(1, start), min(65535, end) + 1))
        elif part:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="CyberRakshak v%s - Defensive Security Toolkit "
                    "(scan only your own systems)" % VERSION
    )
    parser.add_argument("--target", "-t", required=True,
                        help="Target host to scan (own systems only)")
    parser.add_argument("--ports", "-p", default="1-1000",
                        help="Port range '1-1000' or list '22,80,443' (default: 1-1000)")
    parser.add_argument("--top-ports", action="store_true",
                        help="Scan only the top ~50 common ports (fast)")
    parser.add_argument("--threads", default=100, type=int,
                        help="Number of threads (default: 100)")
    parser.add_argument("--udp", action="store_true",
                        help="Also run a basic UDP scan on the same ports")
    parser.add_argument("--service-detection", "-s", action="store_true",
                        help="Detect service + version on open ports (banner grabbing)")
    parser.add_argument("--tls-audit", action="store_true",
                        help="Deep TLS audit on every open port that speaks TLS")
    parser.add_argument("--web-audit", action="store_true",
                        help="Web-layer audit on open HTTP(S) ports (12 checks: "
                             "CSP, cookies, CORS, exposed files, TRACE, "
                             "clickjacking, mixed content, version disclosure, "
                             "HTTP->HTTPS redirect, HSTS over HTTP, security.txt)")
    parser.add_argument("--vuln-check", action="store_true",
                        help="Match detected versions against known-vulnerable list "
                             "(defensive hints only, no exploits)")
    parser.add_argument("--output", "-o", default=None,
                        help="Save report to file (.json, .txt, or .pdf)")
    parser.add_argument("--version", "-v", action="version",
                        version=f"CyberRakshak {VERSION}")

    args = parser.parse_args()

    banner(VERSION)
    print(f"[*] Target: {args.target}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[!] Defensive use only: scan systems you own or are authorized to test.")
    print()

    if args.top_ports:
        ports = TOP_PORTS
        print(f"[*] Top-ports mode: scanning {len(ports)} common ports")
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print("[!] Invalid port spec. Use '1-1000' or '22,80,443'.")
            sys.exit(1)
        print(f"[*] Ports: {len(ports)} ports")

    # ---- Stage 1: TCP scan ----
    tcp = PortScanner(args.target, threads=args.threads)
    open_tcp = tcp.scan_ports(ports)

    # ---- Stage 2: UDP scan (optional) ----
    udp_results = []
    if args.udp:
        print()
        udp = UDPScanner(args.target, threads=args.threads)
        udp_results = udp.scan_ports(ports)

    # ---- Stage 3: Service detection (optional) ----
    services = []
    if args.service_detection and open_tcp:
        print()
        print("[*] Detecting services on open ports...")
        detector = ServiceDetector(args.target)
        services = detector.detect_all(open_tcp)
        for s in services:
            ver = f" {s['version']}" if s["version"] else ""
            print(f"    Port {s['port']}: {s['service']}{ver}")

    # ---- Stage 4: TLS audit (optional) ----
    tls_findings, tls_info = [], {}
    if args.tls_audit:
        # probe every open port for TLS (not just 443/8443)
        tls_ports = [p for p in open_tcp if _speaks_tls(args.target, p)]
        for tp in tls_ports:
            print()
            print(f"[*] Auditing TLS on port {tp}...")
            auditor = HTTPSAuditor(args.target, port=tp)
            findings = auditor.audit()
            tls_findings.extend(findings)
            tls_info.update(auditor.info)
            for f in findings:
                print(f"    [{f['severity']}] {f['issue']}")
        if open_tcp and not tls_ports:
            print("[*] No open port spoke TLS - skipping TLS audit.")

    # ---- Stage 4b: Web audit (optional, v0.3 - 12 WEB checks) ----
    web_findings, web_info = [], {}
    if args.web_audit and open_tcp:
        for p in open_tcp:
            use_tls = _speaks_tls(args.target, p)
            auditor = WebAuditor(args.target, port=p, use_tls=use_tls)
            findings = auditor.audit()
            if auditor.info:
                web_info[str(p)] = auditor.info
            if findings or auditor.info:
                scheme = "HTTPS" if use_tls else "HTTP"
                print()
                print(f"[*] Web audit on port {p} ({scheme})...")
                for f in findings:
                    print(f"    [{f['severity']}] {f['issue']}")
            web_findings.extend(findings)

    # ---- Stage 5: Vulnerability hints (optional, defensive) ----
    vuln_hints = []
    if args.vuln_check and services:
        print()
        print("[*] Checking versions against known-vulnerable list...")
        checker = VulnChecker()
        vuln_hints = checker.check_all(services)
        for h in vuln_hints:
            print(f"    [{h['severity']}] Port {h['port']}: "
                  f"{h['product']} {h['detected_version']} - {h['guidance'][:70]}...")

    # ---- Summary ----
    print()
    print(f"[*] Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Open TCP ports: {len(open_tcp)} | "
          f"UDP interesting: {len(udp_results)} | "
          f"Services: {len(services)} | "
          f"TLS findings: {len(tls_findings)} | "
          f"Web findings: {len(web_findings)} | "
          f"Vuln hints: {len(vuln_hints)}")

    # ---- Report ----
    if args.output:
        reporter = Reporter(args.target)
        data = reporter.build_data(
            open_ports=open_tcp,
            udp_results=udp_results,
            services=services,
            tls_findings=tls_findings,
            tls_info=tls_info,
            vuln_hints=vuln_hints,
            web_findings=web_findings,
            web_info=web_info,
        )
        try:
            path = reporter.save(data, args.output)
            print(f"[+] Report saved: {path}")
        except RuntimeError as e:
            print(f"[!] Report failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
