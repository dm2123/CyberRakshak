# CyberRakshak 🛡️

**"Hacker se pehle — CyberRakshak!"**

An advanced defensive cybersecurity toolkit for Linux, built by Dinesh Singh.
Find vulnerabilities BEFORE hackers do — including the tiny TLS flaws that
Nmap, sslyze and testssl.sh users often miss.

## Philosophy

- **Defensive only**: scan systems you own or have explicit written permission to test.
- **Original code**: 100% own implementation, no copied scanner engines.
- **Linux terminal**: fast, scriptable command-line interface.
- **No AI**: pure code, pure skill.

## v0.3.0 "Deep Auditor" — What's New

- **TLS auditor grew from 14 to 33 checks** (`--tls-audit`): the original 14
  plus 19 deep checks — insecure renegotiation, FALLBACK_SCSV downgrade
  protection, DROWN/SSLv2, Logjam DH size, SWEET32, forward secrecy, the
  full certificate chain (order, weak links, must-staple, EKU, CA:TRUE
  leaves, validity windows) and more. See the table below.
- **New web-layer auditor** (`--web-audit`): 12 checks over plain HTTP(S)
  responses — CSP deep analysis, cookie flags, passive CORS, exposed
  sensitive files (fixed 6-path list, contents never copied into reports),
  TRACE, mixed content, clickjacking, technology/version disclosure,
  HTTP→HTTPS redirect and security.txt. See the table below.
- **Vulnerability hints now use an offline CVE snapshot** (`--vuln-check`):
  `vuln/cve_snapshot.json` (snapshot dated **2026-10-23**) covers
  **8 products, 12 version ranges, 10 well-known CVEs** with severities and
  fix guidance. Fully offline — the tool never fetches updates; refreshing
  the snapshot is a manual maintainer task (edit the JSON, validate with
  `tools/build_cve_snapshot.py`). Hints only — no exploits, no payloads.
- **Reports include the new findings**: JSON carries `tls_findings`,
  `web_findings`, `web_info` and CVE-tagged `vulnerability_hints`; text and
  PDF reports give Web findings their own section (only when the web audit
  found something, so plain-scan reports look exactly as before).

Everything from v0.2.0 is still there: service detection
(SSH/OpenSSH, Apache, nginx, FTP, SMTP, MySQL/MariaDB, Redis…), UDP
scanning (`--udp`), reports (`.json` / `.txt` / `.pdf`), `--top-ports`,
`--ports 22,80,443` (list or range) and `-s/--service-detection`.

## The Deep TLS Audit (`--tls-audit`)

For every port that speaks TLS, CyberRakshak checks:

| ID | Check | What it catches |
|----|-------|-----------------|
| TLS-001 | TLS versions 1.0–1.3 offered | Legacy TLS 1.0/1.1 (BEAST/POODLE) |
| TLS-002 | Cipher suite enumeration + weak-cipher rules | RC4, single-DES, 3DES, EXPORT, anonymous, NULL, MD5 suites |
| TLS-003 | Certificate expiry | Expired / expiring within 30 days |
| TLS-004 | Chain trust | Incomplete chain, untrusted root |
| TLS-005 | Hostname match (SAN → CN fallback) | Name-mismatch = phishing vector |
| TLS-006 | Self-signed certificate | Cert issued by its own subject |
| TLS-007 | Signature algorithm (leaf) | SHA-1 / MD5 signatures (forgeable) |
| TLS-008 | Public key size (leaf) | RSA < 2048, weak EC curves |
| TLS-009 | HSTS (parsed) | Missing, short max-age, no includeSubDomains |
| TLS-010 | Security headers | Missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| TLS-011 | TLS compression | CRIME attack surface |
| TLS-012 | Heartbleed | **Guidance only** — CyberRakshak deliberately does NOT send malformed heartbeat probes (that reads server memory = exploit code). It tells you the exact `nmap`/`testssl.sh` command to verify manually on your own systems. |
| TLS-013 | OCSP stapling | Missing stapling (privacy + speed) |
| TLS-014 | SNI handling + session resumption | SNI required? Wrong-SNI leaks? Ticket hygiene |
| TLS-015 | Insecure renegotiation (RFC 5746) | No `renegotiation_info` in the ServerHello |
| TLS-016 | Downgrade protection (TLS_FALLBACK_SCSV) | Server ignores the fallback signal instead of aborting |
| TLS-017 | No forward secrecy | No ECDHE/DHE/TLS 1.3 suite accepted — past traffic decryptable if the key leaks |
| TLS-018 | SSLv2 enabled (DROWN, CVE-2016-0800) | Server still answers SSLv2 handshakes |
| TLS-019 | RSA key exchange accepted | Static-RSA suites (ROBOT-class risk, no PFS) |
| TLS-020 | Weak DH parameters (Logjam, CVE-2015-4000) | DHE prime < 2048 bits in ServerKeyExchange |
| TLS-021 | 64-bit block ciphers (SWEET32, CVE-2016-2183) | Blowfish / IDEA accepted |
| TLS-022 | CBC suites with TLS 1.0/1.1 (Lucky13, CVE-2013-0169) | Padding-oracle timing risk combo |
| TLS-023 | ALPN negotiation | Which app protocols the server picks (`h2`, `http/1.1`) — INFO |
| TLS-024 | Session resumption detail | Tickets vs session IDs vs TLS 1.3 PSK — INFO |
| TLS-025 | Certificate chain order | Intermediates sent in the wrong order |
| TLS-026 | Weak signature / key in the chain | SHA-1 or small keys on intermediates (root noted as LOW) |
| TLS-027 | OCSP must-staple not delivered | Cert promises stapling (RFC 7633) but server doesn't staple |
| TLS-028 | Validity too long | Certificate lifetime > 825 days |
| TLS-029 | Expires within 7 days | Imminent outage — HIGH |
| TLS-030 | Missing serverAuth EKU | Cert not intended for server authentication |
| TLS-031 | CA:TRUE on a leaf | Mis-issued subordinate CA — major trust risk |
| TLS-032 | Overly broad scope | Multi-level wildcards, SAN lists > 50 names |
| TLS-033 | No TLS 1.3 | Modern hardening missing — INFO |

Every finding carries a severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), a
concrete fix, its check ID, and a CVE ID where one is verified.

## The Web Audit (`--web-audit`)

For every open port that serves HTTP or HTTPS, CyberRakshak reads plain
responses (sequential requests, small read caps) and checks:

| ID | Check | What it catches |
|----|-------|-----------------|
| WEB-001 | CSP deep analysis | Missing CSP, `unsafe-inline`/`unsafe-eval`, wildcard/`data:`/`blob:`/`http:` script sources, missing `object-src`/`base-uri`/`frame-ancestors` |
| WEB-002 | Cookie flags | Missing `Secure`/`HttpOnly`, `SameSite` problems, `__Host-`/`__Secure-` prefix violations — cookie *values* are never reported |
| WEB-003 | Passive CORS | Arbitrary `Origin` echoed back, especially combined with credentials |
| WEB-004 | Exposed sensitive files | Fixed list only: `/.git/HEAD`, `/.env`, `/server-status`, `/.DS_Store`, `/robots.txt` — report records exposed/not-exposed, never file contents |
| WEB-005 | Dangerous HTTP methods | TRACE / TRACK enabled (Cross-Site Tracing) |
| WEB-006 | Technology version disclosure | `Server`, `X-Powered-By` and similar headers leaking versions (also feeds `--vuln-check`) |
| WEB-007 | HTTP→HTTPS redirect | Port 80 serving content instead of redirecting, redirect chains starting over HTTP |
| WEB-008 | Mixed-content hints | HTTPS pages referencing `http://` subresources |
| WEB-009 | HSTS over plain HTTP | `Strict-Transport-Security` sent where browsers ignore it — INFO |
| WEB-010 | security.txt | `/.well-known/security.txt` published — positive INFO |
| WEB-011 | Clickjacking | Neither `X-Frame-Options` nor CSP `frame-ancestors` present |
| WEB-012 | Referrer-Policy | `unsafe-url` leaking full URLs to third parties |

No payloads are injected, no forms are submitted, no directories are
brute-forced — header and configuration observation only.

## Offline CVE Snapshot (`--vuln-check`)

Detected service versions (from banners and headers) are matched against
`vuln/cve_snapshot.json` — a hand-curated, fully offline snapshot dated
**2026-10-23** with 8 products (Apache httpd, Exim, IIS, OpenSSH, OpenSSL,
ProFTPD, Samba, vsftpd), 12 version ranges and 10 famous CVEs (Heartbleed,
regreSSHion, SambaCry, the Apache 2.4.49/2.4.50 traversals, the vsftpd
2.3.4 backdoor…). Each hint carries the CVE ID, a severity, a confidence
level and upgrade guidance. The tool **never** goes online to update it:
refreshing is a manual maintainer task — edit the JSON, then run
`python3 tools/build_cve_snapshot.py` to validate it. If the snapshot is
missing or corrupt, the built-in fallback list is used instead.

## Usage

```bash
# Fast scan of common ports with service detection
python3 cyberrakshak.py -t 127.0.0.1 --top-ports -s

# Full audit: services + TLS + web + vuln hints + JSON report
python3 cyberrakshak.py -t 127.0.0.1 -p 1-1000 -s --tls-audit --web-audit \
    --vuln-check -o report.json

# Same full audit, PDF report
python3 cyberrakshak.py -t 127.0.0.1 -p 1-1000 -s --tls-audit --web-audit \
    --vuln-check -o report.pdf

# Include UDP ports, save JSON
python3 cyberrakshak.py -t 127.0.0.1 --top-ports --udp -o report.json

# Specific ports
python3 cyberrakshak.py -t 192.168.1.1 -p 22,80,443 -s --tls-audit
```

> [!WARNING]
> Scan **only** systems you own or have explicit written permission to test.
> Unauthorized scanning is illegal under the IT Act, 2000 (India) and
> equivalent laws elsewhere.

## Project layout

```
cyberrakshak.py          # CLI entry point (v0.3.0)
scanner/
  port_scanner.py        # multi-threaded TCP connect scanner
  udp_scanner.py         # basic UDP prober
  service_detector.py    # banner grabbing + version parsing
https/
  tls_auditor.py         # deep TLS audit (33 checks, own DER parser)
web/
  web_auditor.py         # web-layer audit (12 checks, repeated-header fetch)
vuln/
  vuln_db.py             # CVE snapshot matching (hints only, no exploits)
  cve_snapshot.json      # offline CVE snapshot (dated 2026-10-23)
tools/
  build_cve_snapshot.py  # snapshot validator (manual refresh workflow)
reports/
  reporter.py            # JSON / text / PDF reports
intrusion/
  intrusion_alert.py     # SSH brute-force detection from own auth logs
tests/
  test_cyberrakshak.py   # core tests (localhost only)
  test_tls_auditor.py    # TLS auditor tests (113 assertions)
  test_web_auditor.py    # web auditor tests (61 assertions)
  test_vuln_db.py        # CVE snapshot tests (56 assertions)
  test_reporter.py       # report-integration tests (no network)
```

## Running tests

```bash
python3 tests/test_cyberrakshak.py   # core scanner tests
python3 tests/test_tls_auditor.py    # TLS auditor tests (fixtures self-heal in /tmp/tlstest)
python3 tests/test_web_auditor.py    # web auditor tests (local fixture servers)
python3 tests/test_vuln_db.py        # offline CVE snapshot tests
python3 tests/test_reporter.py     # report section tests
```

Note: the PDF report test needs the optional `fpdf2` package
(`pip install fpdf2`); without it that single check is reported as
environment-blocked while everything else runs.

## Roadmap

- OS fingerprinting, subdomain finder, directory checker (planned)
- Scheduled scans + diff mode (planned)
- Terminal dashboard (planned)

## Author

**Dinesh Singh** — BCA 2nd Year, WCTM Gurugram

## License

MIT License — see [LICENSE](LICENSE). Built for defenders.
