# CyberRakshak v0.3 "Deep Auditor" — Technical Specification (DRAFT)

**Status:** Draft spec only — no code written yet.
**Goal (user directive, 2026-10-12):** Make the tool powerful enough to find small
weaknesses even in "strong" security setups — the subtle misconfigurations that
older/simpler tools miss.
**Non-goals (standing):** 100% original code, terminal-based, ADVANCED, NO AI,
defensive motive only. **No exploit payloads, no active exploitation — detection
+ guidance only.** Scan only systems you own or have written permission to test.

---

## 1. Design principles (apply to every new check)

1. **Observe, don't exploit.** Every check is a normal handshake / normal HTTP
   request, or passive parsing of what the server voluntarily sends. Anything
   that requires malformed input crafted to read memory, or thousands of
   adaptive oracle queries, is OUT (see §6).
2. **stdlib only.** `socket`, `ssl`, `struct`, `re`, `datetime`, `http.client`
   allowed. No third-party packages, no shelling out to `openssl`/`nmap`.
3. **Reuse existing infra.** `build_client_hello()` / `parse_server_hello_extensions()`
   (raw TLS), `_DERReader` / `parse_cert_der()` / `hostname_matches()`
   (certificates), `_add(severity, issue, detail)` (findings). New checks are new
   `_check_*` methods on `HTTPSAuditor` or a new `WebAuditor` class — not rewrites.
4. **Every finding carries severity + fix recommendation.** Same dict shape as
   v0.2.0, extended (see §2).
5. **Fail soft.** Any check that errors (timeout, parse failure, unexpected
   bytes) records INFO or nothing — never crashes the audit.
6. **CVE IDs only when verified.** Spec §5 lists only CVE IDs the author is
   confident about; everything else is marked **"verify karna hai"**.

### Severity rubric (v0.3)

| Level | Meaning |
|---|---|
| CRITICAL | Actively exploitable misconfiguration (e.g. SSLv2/DROWN). Fix today. |
| HIGH | Real attack path, well-known technique (e.g. TLS 1.0, insecure renegotiation). |
| MEDIUM | Weakens posture / enables follow-on attacks (e.g. 3DES, missing HSTS). |
| LOW | Hardening gap (e.g. short HSTS max-age, verbose Server header). |
| INFO | Observation, positive note, or manual-verification guidance. |

---

## 2. Finding format v0.3 (backward compatible)

```python
{
    "severity": "HIGH",          # unchanged
    "issue":    "...",           # unchanged
    "detail":   "...",           # unchanged, always ends with fix guidance
    "check":    "TLS-015",       # NEW (optional): stable check ID
    "cve":      "CVE-2016-0800", # NEW (optional): only verified CVE IDs
}
```

`Reporter` ignores unknown keys, so old consumers keep working.

**Check-ID scheme:** `TLS-001…` for TLS-layer checks, `WEB-001…` for web-layer
checks. Existing v0.2.0 checks are retro-assigned IDs (no behavior change):

| ID | Existing check (v0.2.0) |
|---|---|
| TLS-001 | TLS versions offered (1.0–1.3) |
| TLS-002 | Cipher suite enumeration + weak-cipher rules |
| TLS-003 | Certificate expiry |
| TLS-004 | Certificate chain trust |
| TLS-005 | Certificate hostname match (SAN/CN, RFC-6125 style) |
| TLS-006 | Self-signed detection |
| TLS-007 | Weak signature algorithm (MD5/SHA-1) |
| TLS-008 | Weak key (RSA < 2048, EC < 256) |
| TLS-009 | HSTS header parse |
| TLS-010 | Security headers (CSP/XFO/XCTO/Referrer-Policy — basic) |
| TLS-011 | TLS compression (CRIME, CVE-2012-4929) |
| TLS-012 | Heartbeat/Heartbleed guidance only (CVE-2014-0160) |
| TLS-013 | OCSP stapling offered/not |
| TLS-014 | SNI handling + session resumption/tickets |

---

## 3. TLS layer: 14 → 33 checks

### 3.1 Protocol & handshake checks (new)

**TLS-015 — Insecure renegotiation (RFC 5746)** · Severity: HIGH · Complexity: LOW
- *Detects:* Server does not echo the `renegotiation_info` extension (0xFF01)
  → vulnerable to TLS renegotiation attacks (plaintext injection into the
  renegotiated session).
- *How:* Reuse `build_client_hello(with_empty_reneg_info=True)` +
  `parse_server_hello_extensions()`; check `0xFF01 in exts`. The infra already
  exists in `tls_auditor.py` — this is a ~15-line method.
- *Boundary:* Only observes the extension; does not attempt a renegotiation.

**TLS-016 — Missing downgrade protection (TLS_FALLBACK_SCSV, RFC 7507)** · MEDIUM · MEDIUM
- *Detects:* Server accepts a fallback handshake without aborting →
  protocol-downgrade attacks possible.
- *How:* Extend `build_client_hello()` with `fallback_scsv=True` to append
  suite `0x5600` and set ClientHello version to TLS 1.1 (0x0302). If the server
  completes the handshake (ServerHello) instead of sending
  `inappropriate_fallback` alert, flag MEDIUM.
- *Boundary:* One normal handshake attempt; no forced-downgrade exploitation.

**TLS-017 — No forward secrecy** · HIGH · LOW
- *Detects:* None of the accepted cipher suites provide PFS (no ECDHE/DHE).
- *How:* After `_enumerate_ciphers()`, check whether any accepted suite name
  contains `ECDHE`/`DHE`/`TLS_AES`/`TLS_CHACHA` (TLS 1.3 suites are
  implicitly FS). If none → HIGH: "past traffic decryptable if key leaks;
  also removes the main mitigation for Bleichenbacher/ROBOT-class attacks
  against RSA key exchange."
- *Note:* This is the **defensive answer to ROBOT** (see §6 — active ROBOT
  oracle testing is out of scope).

**TLS-018 — DROWN / SSLv2 enabled (CVE-2016-0800)** · CRITICAL · MEDIUM
- *Detects:* Server still speaks SSLv2 → DROWN cross-protocol attack
  decrypts modern TLS sessions using the same RSA key.
- *How:* Raw socket: send an SSLv2-format CLIENT-HELLO
  (2-byte length header with high bit set, msg-type `0x01`, version `0x0002`,
  cipher-spec list, challenge). If the server replies with an SSLv2
  SERVER-HELLO (msg-type `0x04`) → CRITICAL. Any other response / timeout /
  connection reset → not vulnerable, no finding.
- *Boundary:* Single normal SSLv2 handshake attempt — pure observation, no
  Bleichenbacher oracle queries, no decryption attempt. Also add guidance:
  "ensure the RSA key is not shared with any other SSLv2/weak service."

**TLS-019 — RSA (non-PFS) key exchange accepted** · MEDIUM · LOW
- *Detects:* Static-RSA key transport suites (`...RSA...` without ECDHE/DHE,
  e.g. `AES256-SHA`, `AES128-GCM-SHA256`) accepted.
- *How:* Rule on the enumerated suite list (same loop as `WEAK_CIPHER_RULES`).
  Detail text references ROBOT-class risk and mandates ECDHE.
- *Boundary:* Configuration observation only.

**TLS-020 — Logjam: weak DH parameters (CVE-2015-4000)** · HIGH · HIGH
- *Detects:* Server's DHE ServerKeyExchange uses a DH prime < 2048 bits →
  Logjam downgrade makes the handshake breakable.
- *How:* Raw handshake: ClientHello offering one DHE suite only; parse
  records until handshake type `0x0C` (ServerKeyExchange); read
  `dh_p` length-prefixed field → bit length. < 2048 → HIGH ("use 2048+ or
  prefer ECDHE"). Requires extending the raw-record parser to capture the
  ServerKeyExchange body.
- *Boundary:* Reads the parameter the server voluntarily sends; never attempts
  the discrete-log computation (that would be active cryptanalysis).

**TLS-021 — 64-bit block ciphers (SWEET32 class, CVE-2016-2183)** · MEDIUM · LOW
- *Detects:* Any 64-bit-block cipher accepted (3DES already flagged; add
  Blowfish/IDEA families).
- *How:* Add `BF128-SHA`, `BF-CBC` candidates to `CIPHER_CANDIDATES` and a
  `("BF", "MEDIUM", ...)` / `("IDEA", "MEDIUM", ...)` rule to
  `WEAK_CIPHER_RULES`. Detail cites SWEET32 (birthday attacks after ~32 GB).

**TLS-022 — CBC suites with TLS 1.0 (Lucky13, CVE-2013-0169)** · MEDIUM · LOW
- *Detects:* CBC-mode (non-AEAD) suites accepted **while** TLS 1.0/1.1 is
  offered → Lucky13 padding-oracle timing risk.
- *How:* Cross-check `info["ciphers_accepted"]` (CBC, no GCM/POLY1305/CCM)
  with `info["tls_versions_offered"]`. Guidance: disable TLS ≤ 1.1 or move to
  AEAD-only.

**TLS-023 — ALPN negotiation** · INFO · LOW
- *Detects/notes:* Which application protocols the server negotiates
  (`h2`, `http/1.1`, …).
- *How:* `ctx.set_alpn_protocols(["h2", "http/1.1"])`; read
  `ssock.selected_alpn_protocol()`. INFO with the negotiated value; note that
  `h2` without proper hardening has its own DoS history (guidance only).

**TLS-024 — Session resumption detail (tickets vs IDs, TLS 1.3 PSK)** · INFO · LOW
- *Detects/notes:* Extends TLS-014: report negotiated version alongside
  ticket/resumption state; in TLS 1.3, resumption is PSK-based (no classic
  session-ID) — record which mechanism was observed. INFO only, plus the
  existing ticket-key-rotation guidance.

### 3.2 Certificate deep-dive (new)

All of these reuse `_DERReader` / `parse_cert_der()`. The extension loop in
`parse_cert_der()` currently only extracts SAN (OID 2.5.29.17) — v0.3 extends
it to capture **all extension OIDs** into `cert_info["extensions"]`
(a dict OID → {critical, value}) so every check below is a small reader.

**TLS-025 — Certificate chain order** · MEDIUM · MEDIUM
- *Detects:* Intermediates sent in the wrong order (breaks strict clients).
- *How:* Extend the raw-record parser to capture handshake type `0x0B`
  (Certificate) → ordered list of DER certs → `parse_cert_der()` each →
  verify `issuer_raw[i] == subject_raw[i+1]` for the chain. Mismatch → MEDIUM.
- *Note:* `getpeercert()` only returns the leaf, which is why the raw
  Certificate message is needed.

**TLS-026 — Weak signature / weak key anywhere in the chain** · HIGH · MEDIUM
- *Detects:* SHA-1/MD5 signature or RSA < 2048 on any intermediate (root
  SHA-1 is legacy-tolerated → LOW note, not HIGH).
- *How:* Same parsed chain as TLS-025; apply existing `SIG_ALG_OIDS` and
  key-size logic per cert.

**TLS-027 — OCSP Must-Staple promised but not delivered** · HIGH · LOW
- *Detects:* Leaf has the TLS Feature extension (OID 1.3.6.1.5.5.7.1.24,
  RFC 7633) containing `status_request (5)`, but the server did not staple
  (TLS-013 = "not offered") → strict clients will hard-fail.
- *How:* Check `extensions` dict for the OID; cross-check `info["ocsp_stapling"]`.

**TLS-028 — Certificate validity too long (> 825 days)** · LOW · LOW
- *Detects:* `not_after - not_before > 825 days` → violates CA/Browser Forum
  baseline (Sept 2020); long-lived certs increase key-compromise window.
- *How:* Pure date arithmetic on already-parsed validity.

**TLS-029 — Certificate expires within 7 days** · HIGH · LOW
- *Detects:* Escalation of TLS-003's 30-day MEDIUM warning — ≤7 days is an
  imminent outage.
- *How:* Same `days` computation, extra threshold.

**TLS-030 — Missing serverAuth EKU** · MEDIUM · LOW
- *Detects:* Extended Key Usage present but without `serverAuth`
  (OID 1.3.6.1.5.5.7.3.1) → cert not intended for server authentication;
  mis-issuance indicator.
- *How:* Parse EKU extension (OID 2.5.29.37) value → list of OIDs.

**TLS-031 — CA:TRUE on a leaf certificate** · HIGH · LOW
- *Detects:* `basicConstraints` (OID 2.5.29.19) with `cA=TRUE` on the
  end-entity cert → mis-issued subordinate CA, major trust risk.
- *How:* Parse the extension's DER boolean.

**TLS-032 — Overly broad certificate scope** · INFO/LOW · LOW
- *Detects:* Wildcard covering multiple levels (`*.*.example.com` — invalid
  per RFC 6125, some clients accept), or SAN list > 50 names (sprawl →
  blast radius if key leaks).
- *How:* String analysis on `san_dns` (already parsed).

**TLS-033 — No TLS 1.3 support** · INFO · LOW
- *Detects:* Server offers ≤ TLS 1.2 only → missing modern hardening
  (AEAD-only, no static RSA, encrypted extensions).
- *How:* From `info["tls_versions_offered"]`; INFO with upgrade guidance
  (not HIGH — TLS 1.2 with good config is acceptable).

---

## 4. Web layer (NEW module: `web/`)

New package `web/web_auditor.py` with class `WebAuditor(target, port=80/443,
use_tls, timeout)`. Runs against every open port where service detection saw
HTTP/HTTPS (not just 80/443). New CLI flag `--web-audit`. Findings use the
same dict shape with `WEB-xxx` check IDs. Report gains `web_findings` /
`web_info` (see §7).

**Important implementation note:** `HTTPSAuditor._fetch_headers()` collapses
duplicate headers into a dict — `Set-Cookie` appears multiple times, so
`WebAuditor` must use its own fetch that preserves **repeated headers as a
list**. Requests: one `GET /` (and `HEAD` fallback), plus the small fixed
file list in WEB-004. Sequential with a 0.5 s pause between requests; no
parallelism, no retries storm.

### Checks

**WEB-001 — CSP deep analysis** · MEDIUM/LOW · Complexity: MEDIUM
- *Detects (beyond v0.2.0's missing/unsafe-inline):* `unsafe-eval`,
  `data:` / `blob:` / `*` / `http:` in `script-src`, missing `object-src`
  (→ plugin XSS), missing `base-uri` (→ base-tag hijack), missing
  `frame-ancestors` (→ clickjacking, cross-check with X-Frame-Options),
  `default-src` absent with no `script-src` fallback.
- *How:* Parse header into `{directive: [sources]}`; rule table per
  directive. Each violation is its own finding with the offending directive
  quoted. Guidance always concrete ("replace `unsafe-inline` with a nonce").
- *Boundary:* Header analysis only — no payload injection, no XSS attempt.

**WEB-002 — Cookie flag audit** · MEDIUM/LOW · MEDIUM
- *Detects:* Per `Set-Cookie`: missing `Secure` on an HTTPS site → MEDIUM
  (cookie leaks over HTTP); missing `HttpOnly` → MEDIUM (XSS theft);
  `SameSite` missing → LOW (CSRF), `SameSite=None` without `Secure` → MEDIUM
  (browsers reject; indicates confusion); `__Host-`/`__Secure-` prefix rules
  violated → MEDIUM.
- *How:* Case-insensitive parse of each Set-Cookie value. Only flags, never
  logs cookie *values* in the report (redact: report name + flags only).
- *Boundary:* Reads cookies the server sets on a plain GET; no session use,
  no login, no cookie tossing.

**WEB-003 — Passive CORS misconfiguration** · HIGH/MEDIUM/LOW · MEDIUM
- *Detects:* Send `GET /` with `Origin: https://cyberrakshak-probe.invalid`.
  `Access-Control-Allow-Origin` echoes the arbitrary origin **and**
  `Access-Control-Allow-Credentials: true` → HIGH (account takeover via
  victim's browser). Echo without credentials → MEDIUM. `*` with credentials
  → MEDIUM (spec-forbidden combo). `*` without credentials → LOW.
- *How:* Single request with one custom header; pure response-header
  inspection.
- *Boundary:* No cross-origin request is actually executed from a browser;
  no data exfiltration attempted.

**WEB-004 — Exposed sensitive files** · HIGH/MEDIUM/LOW · MEDIUM
- *Detects:* `GET` on a **fixed, small, well-known list** (no wordlist, no
  brute force):
  - `/.git/HEAD` → 200 and body starts with `ref:` → HIGH (repo disclosure)
  - `/.env` → 200 and looks like env assignments → HIGH
  - `/server-status` → 200 → MEDIUM (Apache mod_status internals)
  - `/.DS_Store` → 200 → LOW (path disclosure)
  - `/robots.txt` → 200 → INFO (may list sensitive paths — quote first lines)
  - `/.well-known/security.txt` → 200 → INFO *positive* ("good practice")
- *How:* Sequential GETs, 0.5 s apart, `Range`-free, small read cap (8 KB).
  **Redaction rule:** the report records only "exposed / not exposed" —
  never file contents (`.env` may hold live secrets; even on the user's own
  server we don't want secrets in a report file).
- *Boundary:* Fixed list of 6 paths. No directory enumeration, no fuzzing,
  no `../` traversal, no backup-file guessing (`.bak`, `.old`, `~`).

**WEB-005 — Dangerous HTTP methods (TRACE/TRACK)** · MEDIUM · LOW
- *Detects:* `TRACE` enabled → MEDIUM (Cross-Site Tracing, CVE-2003-1567 /
  CVE-2004-2320 class — old but still found on misconfigured servers).
- *How:* `OPTIONS /` → parse `Allow:`; if TRACE/TRACK listed (or ambiguous),
  send one `TRACE / HTTP/1.1` — a 200 echoing the request confirms. One
  request, standard method, no payload.
- *Boundary:* Standard HTTP method only; no request smuggling.

**WEB-006 — Technology version disclosure** · INFO · LOW
- *Detects:* `Server:`, `X-Powered-By:`, `X-AspNet-Version:`,
  `X-Generator:` with version numbers → feeds `VulnChecker` (structured
  `{service, version}` like `ServiceDetector` output).
- *How:* Header read + existing `VERSION_PATTERNS` regexes (import from
  `scanner.service_detector` — no duplication).
- *Boundary:* Passive banner read (already done by service detection).

**WEB-007 — Missing HTTP→HTTPS redirect** · MEDIUM · LOW
- *Detects:* Port 80 serves `200 OK` content instead of redirecting to HTTPS
  (HSTS alone doesn't protect the very first visit).
- *How:* Plain-HTTP `GET /`; expect 301/302/307/308 with
  `Location: https://…`. 200 → MEDIUM. Also flag redirect chains
  (http→http→https) as LOW.

**WEB-008 — Mixed-content hints** · LOW · LOW
- *Detects:* HTTPS page's HTML references `http://` resources
  (`src=`/`href=`).
- *How:* `GET /` over TLS, regex for `src="http://` / `href="http://`.
  Report count + first few matches. Detail notes: "confirm in a browser;
  active mixed content (scripts) is the real risk."
- *Boundary:* No rendering, no JS execution.

**WEB-009 — HSTS sent over plain HTTP** · INFO · LOW
- *Detects:* `Strict-Transport-Security` on the port-80 response → browsers
  ignore it; harmless but indicates copy-paste config.
- *How:* Trivial check in the port-80 fetch.

**WEB-010 — security.txt** · INFO (positive) · LOW
- Covered in WEB-004's list; listed separately for the report's "good
  practices" section.

**WEB-011 — Clickjacking: neither XFO nor frame-ancestors** · MEDIUM · LOW
- *Detects:* No `X-Frame-Options` **and** no CSP `frame-ancestors` → page is
  frameable.
- *How:* Cross-check of WEB-001's parsed CSP + header presence. (v0.2.0's
  TLS-010 XFO check stays as-is; this is the stricter combined rule.)

**WEB-012 — Referrer-Policy `unsafe-url`** · LOW · LOW
- *Detects:* `Referrer-Policy: unsafe-url` (or `no-referrer-when-downgrade`
  on sensitive pages) → full URL leaks to third parties.
- *How:* Header value match.

---

## 5. vuln_db expansion (offline CVE matching)

### Current state (v0.2.0)
Flat Python list `VULN_DB`: substring product match → single `max_vuln`
threshold → one hint per product. No CVE IDs, no ranges, no confidence.

### v0.3 design

**5.1 Snapshot file: `vuln/cve_snapshot.json`** (ships with the tool — works
fully offline)

```json
{
  "snapshot_date": "2026-10-12",
  "snapshot_version": 1,
  "generated_by": "tools/build_cve_snapshot.py",
  "entries": [
    {
      "product": "OpenSSH",
      "aliases": ["openssh"],
      "match": "substring",
      "ranges": [
        {
          "max_vuln": "9.8",
          "severity": "CRITICAL",
          "cve": "CVE-2024-6387",
          "title": "regreSSHion: race condition in sshd",
          "guidance": "Upgrade to OpenSSH 9.8+ immediately; this is remotely exploitable."
        },
        {
          "max_vuln": "7.8",
          "severity": "MEDIUM",
          "cve": "CVE-2018-15473",
          "title": "Username enumeration via auth timing",
          "guidance": "Upgrade to OpenSSH 7.9+."
        }
      ]
    }
  ]
}
```

- `match`: `substring` (default), `exact`, or `regex` (for odd banners).
- `ranges`: ordered list; **all** matching ranges produce hints (v0.2.0's
  "one hint per product" limit is removed — a very old version can carry
  multiple CVEs).
- Every hint gains `cve`, `title`, and `confidence`:
  `high` (exact product + clean version), `medium` (substring product match),
  `low` (version string had to be guessed/normalized).

**5.2 Version normalization (improved `_parse_version`)**
- Strip distro suffixes: `2.4.49-1ubuntu2` → `2.4.49`; `8.9p1` → `8.9`
  (keep the `p1` only for products where it matters — OpenSSH).
- Handle 2–4 numeric components; non-numeric → `low` confidence, still match.

**5.3 Product alias map**
`httpd`→Apache, `openbsd sshd`→OpenSSH, `microsoft-iis`→IIS, etc. — a small
dict in the snapshot, so banner variants match.

**5.4 Maintainer workflow (NOT automatic)**
- `tools/build_cve_snapshot.py` — validates `vuln/cve_snapshot.json` schema,
  sorts ranges, bumps `snapshot_version`. It does **not** scrape the web.
- Refresh process (documented in the script's docstring): maintainer reviews
  NVD/CISA KEV entries manually, edits the JSON, runs the validator, commits.
  The tool itself never needs the internet — this is a deliberate design
  choice (works on air-gapped labs, no API keys, no rate limits).
- `VulnChecker` loads the JSON at init; if missing/corrupt, falls back to the
  built-in `VULN_DB` list (backward compatible).

**5.5 Curated CVE seed list (verified IDs only)**
Only CVEs the author is confident about go in the seed snapshot; each entry
is marked, and uncertain ones are **not invented** — they wait for maintainer
verification:

| Product | CVE | Note |
|---|---|---|
| OpenSSL | CVE-2014-0160 | Heartbleed (already guidance-only in TLS-012) |
| OpenSSL | CVE-2016-0800 | DROWN (new TLS-018) |
| OpenSSL | CVE-2016-2183 | SWEET32 (new TLS-021) |
| TLS | CVE-2015-0204 | FREAK (covered by existing EXP-cipher rule) |
| TLS | CVE-2015-4000 | Logjam (new TLS-020) |
| TLS | CVE-2013-0169 | Lucky13 (new TLS-022) |
| TLS | CVE-2012-4929 | CRIME (existing TLS-011) |
| TLS | CVE-2014-3566 | POODLE (existing: TLS 1.0/SSL 3 rule) |
| TLS | CVE-2011-3389 | BEAST (existing: TLS 1.0 rule) |
| TLS | CVE-2015-2808 | Bar Mitzvah / RC4 (existing RC4 rule) |
| TLS | CVE-2016-9244 | Ticketbleed (existing session guidance) |
| HTTP | CVE-2003-1567 | TRACE/XST class (new WEB-005) — **verify karna hai** (old ID, confirm exact) |
| Apache httpd | CVE-2021-41773 | Path traversal (existing entry) |
| Apache httpd | CVE-2021-42013 | 2.4.50 incomplete fix (add) |
| OpenSSH | CVE-2024-6387 | regreSSHion (add, CRITICAL) |
| OpenSSH | CVE-2018-15473 | User enumeration (add) |
| vsftpd | CVE-2011-2523 | 2.3.4 backdoor (add, CRITICAL) |
| ROBOT | (candidate CVE-2017-13099) | **verify karna hai** — active oracle test stays out of scope regardless (§6) |

**5.6 What vuln_db will NOT do**
- No exploit code, no PoC snippets, no payload strings — "upgrade to X" only.
- No automatic internet fetching inside the tool.
- No version detection beyond what banners/headers voluntarily disclose.

---

## 6. Boundaries — "kya NAHI karega" (per section)

### TLS layer will NOT
- Send malformed heartbeat requests (Heartbleed) — reads server memory; stays
  guidance-only (TLS-012), unchanged in v0.3.
- Run Bleichenbacher/ROBOT adaptive oracle queries — thousands of crafted
  handshakes is an active attack; v0.3 mitigates via TLS-017/TLS-019
  configuration checks instead.
- Attempt to compute discrete logs (Logjam) — only reads the DH parameter
  size the server sends.
- Downgrade-forcing beyond one normal fallback handshake (TLS-016).
- Weaken the *client* beyond the existing observation context (`_obs_ctx`
  already documented; no change).

### Web layer will NOT
- Brute-force directories or fuzz paths — fixed 6-path list only (WEB-004).
- Submit forms, attempt logins, or use any credentials.
- Inject payloads (no XSS/SQLi/command-injection testing) — header and
  config analysis only.
- Execute JavaScript or render pages.
- Store or print response bodies that may contain secrets (redaction rule).
- Scan aggressively: sequential requests, 0.5 s spacing, small read caps.

### vuln_db will NOT
- Ship exploit code or PoCs.
- Phone home / require internet.
- Guess CVE IDs — unverified entries are omitted, marked "verify karna hai".

### Global (unchanged from v0.2.0)
Lab / own / explicitly-authorized targets only. CLI prints the defensive-use
warning before every run. Default timeouts stay short; no "aggressive mode".

---

## 7. Integration checklist

- [ ] `https/tls_auditor.py`: add TLS-015…TLS-033 as `_check_*` methods;
  extend `build_client_hello()` (`fallback_scsv` param); extend
  `parse_server_hello_extensions()` usage to capture Certificate (0x0B) and
  ServerKeyExchange (0x0C) bodies; extend `parse_cert_der()` extension loop
  to capture all OIDs.
- [ ] New package `web/` (`__init__.py`, `web_auditor.py`); WEB-001…WEB-012.
- [ ] `vuln/cve_snapshot.json` + `tools/build_cve_snapshot.py` validator;
  `VulnChecker` JSON-first with `VULN_DB` fallback; alias map; confidence.
- [ ] `cyberrakshak.py`: `--web-audit` flag (runs WebAuditor on HTTP(S)
  ports); bump `VERSION = "0.3.0"`; wire `web_findings`/`web_info` through.
- [ ] `reports/reporter.py`: `build_data()` gains `web_findings`,
  `web_info`; text report gains `[ * ] WEB FINDINGS` section; PDF likewise.
- [ ] Tests: `tests/test_web_auditor.py` (new), extend
  `tests/test_tls_auditor.py` (≥1 test per new check, mocked sockets where
  possible), `tests/test_vuln_db.py` (new: snapshot schema, alias +
  normalization, multi-range hints). Target: keep 100% pass, localhost only.
- [ ] Docs: README feature list + `--help` text; `BOOK.md` new chapter
  outline (what each check means, in Hinglish, learner-friendly).

---

## 8. Phased implementation order

**Phase 1 — Easy wins (stdlib `ssl` only, ~1–2 days)**
TLS-015 (renegotiation — infra exists), TLS-017 (forward secrecy),
TLS-019 (RSA kx rule), TLS-023 (ALPN), TLS-024 (session detail),
TLS-028/029 (validity windows), TLS-030 (EKU), TLS-031 (basicConstraints),
TLS-032 (wildcard/SAN scope), TLS-033 (no TLS 1.3 → INFO),
WEB-007 (redirect), WEB-009 (HSTS-over-HTTP), WEB-006 (disclosure),
WEB-010 (security.txt). *All LOW complexity.*

**Phase 2 — Raw-TLS parsing (~2–3 days)**
TLS-016 (FALLBACK_SCSV — extend ClientHello builder) [MEDIUM],
TLS-018 (DROWN SSLv2 probe) [MEDIUM],
TLS-025 (chain order via Certificate message) [MEDIUM],
TLS-026 (chain-wide weak sig/keys) [MEDIUM],
TLS-027 (must-staple cross-check — needs ext capture from Phase 1) [LOW],
TLS-020 (Logjam DH size via ServerKeyExchange) [HIGH],
TLS-021 (Blowfish/IDEA candidates + rules) [LOW],
TLS-022 (CBC+TLS1.0 cross-check) [LOW].

**Phase 3 — Web deep module (~2–3 days)**
Scaffold `web/` + repeated-header fetch [LOW],
WEB-001 (CSP parser) [MEDIUM], WEB-002 (cookies) [MEDIUM],
WEB-003 (CORS) [MEDIUM], WEB-004 (exposed files + redaction) [MEDIUM],
WEB-005 (TRACE) [LOW], WEB-008 (mixed content) [LOW],
WEB-011 (XFO/frame-ancestors) [LOW], WEB-012 (referrer) [LOW].

**Phase 4 — vuln_db expansion (~1–2 days)**
Snapshot schema + seed JSON [MEDIUM], validator script [LOW],
`VulnChecker` JSON-first + fallback [MEDIUM], alias map + version
normalization [MEDIUM], CVE curation pass (verified IDs only) [ongoing].

**Phase 5 — Integration & hardening (~1–2 days)**
`--web-audit` CLI wiring, reporter sections, full test suite per §7,
README/BOOK updates, version bump to 0.3.0, localhost end-to-end run.

*Estimated total: ~8–12 focused dev days. Each phase is independently
shippable (v0.3.x point releases possible after Phase 1).*

---

## 9. Open questions / verify-karna-hai

1. ROBOT CVE ID — candidate CVE-2017-13099, **verify before citing**.
2. TRACE/XST CVE IDs (CVE-2003-1567 / CVE-2004-2320) — **verify exact IDs**.
3. `SSLSocket` on the target Python version: confirm `selected_alpn_protocol()`
   and `session`/`session_reused` attributes exist (code already uses the
   latter; ALPN needs a check).
4. Whether to also probe port-80 `Server` header into `VulnChecker` when
   service detection was skipped — decide in Phase 3.
5. Full OCSP response freshness validation — deferred to v0.4 (needs an OCSP
   DER parser; "offered/not offered" + must-staple is enough for v0.3).

---

*End of v0.3 spec draft. Next step after user approval: implement Phase 1.*
