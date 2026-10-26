#!/usr/bin/env python3
"""Intrusion Alert — CyberRakshak defensive module.

Jab koi tumhare APNE system par attack kare (jaise SSH brute-force),
ye module usko pakadta hai:

- Attacker ka IP address nikalta hai (auth logs se)
- Kitni baar try kiya, kab pehli/kab aakhri baar — sab ginta hai
- Threshold cross ho to HIGH alert deta hai
- Reverse-DNS (best-effort) se attacker ke host ka pata lagata hai
- Full incident report deta hai taaki tum action le sako

100% DEFENSIVE: ye sirf tumhare apne system ke logs padhta hai.
Kisi aur machine ko kabhi scan/touch nahi karta.

Usage:
    python3 intrusion/intrusion_alert.py --log /var/log/auth.log
    python3 intrusion/intrusion_alert.py --window 30 --threshold 5

Author: Dinesh Singh — "Hacker se pehle, CyberRakshak!"
"""

import argparse
import json
import re
import socket
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timedelta

# ---- Log sources (Linux standard locations) ----
DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",      # Debian/Ubuntu (Kali, phone-termux me nahi)
    "/var/log/secure",        # RHEL/CentOS/Fedora
    "/var/log/auth.log.1",
]

# ---- Patterns: failed-login lines in auth logs ----
PATTERNS = [
    # sshd: Failed password for invalid user root from 1.2.3.4 port 5555 ssh2
    re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
    ),
    # sshd: Invalid user admin from 1.2.3.4 port 4444
    re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    ),
    # sshd: Connection closed by authenticating user root 1.2.3.4 port 3333 [preauth]
    re.compile(
        r"Connection closed by (?:invalid user|authenticating user) \S+ (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port"
    ),
    # pam_unix: authentication failure; ... rhost=1.2.3.4
    re.compile(
        r"authentication failure;.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    ),
]


def reverse_dns(ip, timeout=3.0):
    """Best-effort reverse DNS lookup (attacker ka host name)."""
    def _lookup():
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_lookup)
        try:
            return fut.result(timeout=timeout)
        except TimeoutError:
            return None


def parse_line(line):
    """Ek log line se attacker IP nikaalo. Mila to (ip, user) warna None."""
    for pat in PATTERNS:
        m = pat.search(line)
        if m:
            gd = m.groupdict()
            return gd.get("ip"), gd.get("user")
    return None


def load_lines(log_path):
    """Log file ki lines lao (file na mile to khaali list)."""
    try:
        with open(log_path, "r", errors="ignore") as f:
            return f.readlines()
    except FileNotFoundError:
        return []
    except PermissionError:
        print(f"[!] Permission denied: {log_path} (sudo se chalao)", file=sys.stderr)
        return []


def detect(log_path, threshold=5, window_minutes=60):
    """Attack detect karo. Returns list of attacker dicts (count desc)."""
    attackers = defaultdict(lambda: {"attempts": 0, "users": set(),
                                     "first": None, "last": None})
    now = datetime.now()
    window_start = now - timedelta(minutes=window_minutes)

    for line in load_lines(log_path):
        parsed = parse_line(line)
        if not parsed:
            continue
        ip, user = parsed
        rec = attackers[ip]
        rec["attempts"] += 1
        if user:
            rec["users"].add(user)
        # Log line ke andar timestamp ho to use karo, warna 'now'
        ts = extract_time(line) or now
        if ts >= window_start:
            if rec["first"] is None or ts < rec["first"]:
                rec["first"] = ts
            if rec["last"] is None or ts > rec["last"]:
                rec["last"] = ts

    results = []
    for ip, rec in attackers.items():
        results.append({
            "ip": ip,
            "attempts": rec["attempts"],
            "targeted_users": sorted(rec["users"]),
            "first_seen": rec["first"].strftime("%Y-%m-%d %H:%M:%S") if rec["first"] else "unknown",
            "last_seen": rec["last"].strftime("%Y-%m-%d %H:%M:%S") if rec["last"] else "unknown",
            "severity": "HIGH" if rec["attempts"] >= threshold else "MEDIUM",
            "reverse_dns": None,  # niche bhara jayega
        })

    results.sort(key=lambda r: r["attempts"], reverse=True)

    # Reverse DNS sirf alert-worthy IPs ke liye (slow na ho)
    for r in results:
        if r["severity"] == "HIGH":
            r["reverse_dns"] = reverse_dns(r["ip"])

    return results


SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def extract_time(line):
    """Syslog-style timestamp se datetime nikalo (best-effort)."""
    m = SYSLOG_TS.match(line)
    if not m:
        return None
    try:
        year = datetime.now().year
        return datetime(year, MONTHS[m.group("mon")],
                        int(m.group("day")),
                        *[int(x) for x in m.group("time").split(":")])
    except Exception:
        return None


def print_report(results, log_path):
    """Terminal me sundar alert report."""
    print()
    print("=" * 60)
    print("  CYBERRAKSHAK — INTRUSION ALERT REPORT")
    print(f"  Log: {log_path}")
    print(f"  Checked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if not results:
        print("  [+] Koi failed-login attempt nahi mila. System saaf hai.")
        print("=" * 60)
        return

    highs = [r for r in results if r["severity"] == "HIGH"]
    print(f"  [!] {len(results)} suspicious IP(s) mile — {len(highs)} HIGH alert(s)")
    print()

    for r in results:
        tag = "🔴 HIGH" if r["severity"] == "HIGH" else "🟡 MEDIUM"
        print(f"  {tag}  {r['ip']}")
        print(f"       Attempts     : {r['attempts']}")
        print(f"       Target users : {', '.join(r['targeted_users']) or 'unknown'}")
        print(f"       First seen   : {r['first_seen']}")
        print(f"       Last seen    : {r['last_seen']}")
        if r["reverse_dns"]:
            print(f"       Reverse DNS  : {r['reverse_dns']}")
        if r["severity"] == "HIGH":
            print("       ACTION       : IP block karo (ufw deny), password badlo,")
            print("                      SSH key-only login lagao.")
        print()

    print("=" * 60)
    print("  Defensive note: ye sirf tumhare APNE system ke logs hain.")
    print("  Kisi aur ke system par kabhi mat chalana.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="CyberRakshak Intrusion Alert — apne system par hamlawar pakdo"
    )
    parser.add_argument("--log", default=None,
                        help="Auth log path (default: auto-detect)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="HIGH alert ke liye min attempts (default: 5)")
    parser.add_argument("--window", type=int, default=1440,
                        help="Time window in minutes (default: 1440 = 24h)")
    parser.add_argument("--json", action="store_true",
                        help="Report JSON me do")
    args = parser.parse_args()

    log_path = args.log
    if not log_path:
        for cand in DEFAULT_LOG_PATHS:
            try:
                with open(cand):
                    log_path = cand
                    break
            except (FileNotFoundError, PermissionError):
                continue
        if not log_path:
            print("[!] Koi auth log nahi mili. --log se path do.", file=sys.stderr)
            sys.exit(1)

    results = detect(log_path, threshold=args.threshold,
                     window_minutes=args.window)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results, log_path)


if __name__ == "__main__":
    main()
