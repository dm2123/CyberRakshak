#!/usr/bin/env python3
"""CyberRakshak advanced TLS auditor tests - localhost only.

Spins up real local HTTPS servers with deliberately weak/strong configs
and verifies the auditor catches each issue.

Run: python3 tests/test_tls_auditor.py
"""

import http.server
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from https.tls_auditor import (
    HTTPSAuditor, parse_cert_der, build_client_hello,
    parse_server_hello_extensions, parse_handshake_messages,
    parse_certificate_message, parse_server_key_exchange_dh_bits,
    fallback_scsv_verdict, sslv2_verdict, build_sslv2_client_hello,
    CIPHER_CANDIDATES, WEAK_CIPHER_RULES,
)

CERTDIR = "/tmp/tlstest"
PASSED, FAILED = [], []


def check(name, cond, detail=""):
    if cond:
        PASSED.append(name)
        print(f"  [PASS] {name}")
    else:
        FAILED.append(name)
        print(f"  [FAIL] {name} {detail}")


def findings_by_issue(findings, substr):
    return [f for f in findings if substr.lower() in f["issue"].lower()]


def by_check(findings, check_id):
    """Findings carrying a specific v0.3 check ID (e.g. 'TLS-028')."""
    return [f for f in findings if f.get("check") == check_id]


# ---------- v0.3 Phase 1 fixture certs (generated on demand) ----------
def _openssl(*args):
    subprocess.run(["openssl"] + list(args), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _cert_path(name):
    return os.path.join(CERTDIR, name + ".crt")


def _make_selfsigned(name, days, *addexts, key_bits="2048"):
    args = ["req", "-x509", "-newkey", f"rsa:{key_bits}",
            "-keyout", os.path.join(CERTDIR, name + ".key"),
            "-out", _cert_path(name), "-days", str(days), "-nodes",
            "-subj", "/CN=localhost"]
    for ext in addexts:
        args += ["-addext", ext]
    _openssl(*args)


def ensure_fixtures():
    """Create the /tmp/tlstest certs the tests need, if missing.

    /tmp does not survive VM restarts on this machine, so the fixtures
    (including the original v0.2 base certs) are regenerated on demand.
    Idempotent: existing certs are reused (except the 3-day cert, which
    is regenerated when it has < 1 day of validity left). Test fixtures
    only - the auditor tool itself never shells out to openssl.
    """
    os.makedirs(CERTDIR, exist_ok=True)
    san = "subjectAltName=DNS:localhost,IP:127.0.0.1"
    # v0.2 base fixtures
    if not os.path.exists(_cert_path("good")):
        _make_selfsigned("good", 365, san)
    if not os.path.exists(_cert_path("weakkey")):
        _make_selfsigned("weakkey", 365, san, key_bits="1024")
    if not os.path.exists(_cert_path("weaksig")):
        _openssl("req", "-x509", "-newkey", "rsa:2048",
                 "-keyout", os.path.join(CERTDIR, "weaksig.key"),
                 "-out", _cert_path("weaksig"), "-days", "365", "-nodes",
                 "-subj", "/CN=localhost", "-sha1", "-addext", san)
    if not os.path.exists(_cert_path("longcert")):
        _make_selfsigned("longcert", 3000, san)          # TLS-028 (>825d)
    if os.path.exists(_cert_path("shortcert")):
        rc = subprocess.run(
            ["openssl", "x509", "-in", _cert_path("shortcert"),
             "-checkend", "86400", "-noout"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        if rc != 0:
            os.remove(_cert_path("shortcert"))
    if not os.path.exists(_cert_path("shortcert")):
        _make_selfsigned("shortcert", 3, san)            # TLS-029 (<=7d)
    if not os.path.exists(_cert_path("wildbad")):
        _make_selfsigned("wildbad", 365,
                         "subjectAltName=DNS:*.*.example.com,"
                         "DNS:localhost,IP:127.0.0.1")   # TLS-032
    if not os.path.exists(_cert_path("sprawl")):
        names = ",".join([f"DNS:host{i}.example.com" for i in range(55)]
                         + ["DNS:localhost", "IP:127.0.0.1"])
        _make_selfsigned("sprawl", 365, f"subjectAltName={names}")  # TLS-032
    if not os.path.exists(_cert_path("ca")):
        _openssl("req", "-x509", "-newkey", "rsa:2048",
                 "-keyout", os.path.join(CERTDIR, "ca.key"),
                 "-out", _cert_path("ca"), "-days", "3650", "-nodes",
                 "-subj", "/CN=CyberRakshak Test CA",
                 "-addext", "basicConstraints=critical,CA:TRUE")
    leaf_exts = {
        "serverauth": "basicConstraints=CA:FALSE\n"
                      "extendedKeyUsage=serverAuth\n"
                      "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        "clientauth": "basicConstraints=CA:FALSE\n"
                      "extendedKeyUsage=clientAuth\n"
                      "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        "catrue": "basicConstraints=CA:TRUE\n"
                  "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
    }
    for leaf, body in leaf_exts.items():
        name = f"leaf_{leaf}"
        if os.path.exists(_cert_path(name)):
            continue
        ext_file = os.path.join(CERTDIR, name + ".ext")
        with open(ext_file, "w") as fh:
            fh.write(body)
        _openssl("req", "-newkey", "rsa:2048",
                 "-keyout", os.path.join(CERTDIR, name + ".key"),
                 "-out", os.path.join(CERTDIR, name + ".csr"),
                 "-nodes", "-subj", "/CN=localhost")
        _openssl("x509", "-req", "-in", os.path.join(CERTDIR, name + ".csr"),
                 "-CA", _cert_path("ca"),
                 "-CAkey", os.path.join(CERTDIR, "ca.key"),
                 "-CAcreateserial", "-out", _cert_path(name),
                 "-days", "365", "-extfile", ext_file)
    _phase2_fixtures()


# ---------- v0.3 Phase 2 fixture certs (chains, DH, must-staple) ----------
_LEAF_EXT = ("basicConstraints=CA:FALSE\n"
             "extendedKeyUsage=serverAuth\n"
             "subjectAltName=DNS:localhost,IP:127.0.0.1\n")
_INTER_EXT = ("basicConstraints=critical,CA:TRUE,pathlen:0\n"
              "keyUsage=critical,keyCertSign,cRLSign\n")


def _issue(name, ca_name, ext_body, digest=None):
    """Create a key + cert for `name`, signed by CA cert `ca_name`."""
    if os.path.exists(_cert_path(name)):
        return
    ext_file = os.path.join(CERTDIR, name + ".ext")
    with open(ext_file, "w") as fh:
        fh.write(ext_body)
    _openssl("req", "-newkey", "rsa:2048",
             "-keyout", os.path.join(CERTDIR, name + ".key"),
             "-out", os.path.join(CERTDIR, name + ".csr"),
             "-nodes", "-subj", "/CN=localhost")
    args = ["x509", "-req", "-in", os.path.join(CERTDIR, name + ".csr"),
            "-CA", _cert_path(ca_name),
            "-CAkey", os.path.join(CERTDIR, ca_name + ".key"),
            "-CAcreateserial", "-out", _cert_path(name),
            "-days", "365", "-extfile", ext_file]
    if digest:
        args.append(digest)
    _openssl(*args)


def _bundle(name, cert_names, key_name):
    """Server cert file = concatenated PEMs (in presentation order)."""
    if os.path.exists(_cert_path(name)):
        return
    with open(_cert_path(name), "wb") as out:
        for cn in cert_names:
            with open(_cert_path(cn), "rb") as fh:
                out.write(fh.read())
    with open(os.path.join(CERTDIR, key_name + ".key"), "rb") as fh:
        key = fh.read()
    with open(os.path.join(CERTDIR, name + ".key"), "wb") as fh:
        fh.write(key)


def _phase2_fixtures():
    # Weak-but-loadable DH params for the Logjam server (1024 < 2048).
    # 512-bit params are refused by OpenSSL 3 even at SECLEVEL=0 when
    # loading, hence 1024 (generation ~6 s, cached in /tmp).
    if not os.path.exists(os.path.join(CERTDIR, "dh1024.pem")):
        _openssl("dhparam", "-out", os.path.join(CERTDIR, "dh1024.pem"),
                 "1024")
    # TLS-027: CA-signed leaf whose TLS Feature ext promises status_request
    _issue("leaf_staple", "ca",
           _LEAF_EXT + "1.3.6.1.5.5.7.1.24=DER:30:03:02:01:05\n")
    # TLS-025/026 chains: leaf <- inter <- ca (test root)
    _issue("inter", "ca", _INTER_EXT)
    _issue("leaf_chain", "inter", _LEAF_EXT)
    _bundle("chaingood", ["leaf_chain", "inter"], "leaf_chain")
    # same certs, root wrongly placed between leaf and intermediate
    _bundle("chainbad", ["leaf_chain", "ca", "inter"], "leaf_chain")
    # intermediate signed with SHA-1 -> TLS-026 HIGH
    _issue("inter_weak", "ca", _INTER_EXT, digest="-sha1")
    _issue("leaf_wchain", "inter_weak", _LEAF_EXT)
    _bundle("chainweak", ["leaf_wchain", "inter_weak"], "leaf_wchain")
    # SHA-1 self-signed root at the end of the chain -> TLS-026 LOW only
    if not os.path.exists(_cert_path("ca_sha1")):
        _openssl("req", "-x509", "-newkey", "rsa:2048",
                 "-keyout", os.path.join(CERTDIR, "ca_sha1.key"),
                 "-out", _cert_path("ca_sha1"), "-days", "3650", "-nodes",
                 "-subj", "/CN=CyberRakshak SHA1 Root", "-sha1",
                 "-addext", "basicConstraints=critical,CA:TRUE")
    _issue("inter_r", "ca_sha1", _INTER_EXT)
    _issue("leaf_r", "inter_r", _LEAF_EXT)
    _bundle("chainroot", ["leaf_r", "inter_r", "ca_sha1"], "leaf_r")


class Handler(http.server.BaseHTTPRequestHandler):
    extra_headers = {}

    def _send(self):
        self.send_response(200)
        for k, v in self.extra_headers.items():
            self.send_header(k, v)
        self.end_headers()

    def do_HEAD(self):
        self._send()

    def do_GET(self):
        self._send()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class ThreadedHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def start_https(cert="good", min_ver=None, max_ver=None, ciphers=None,
                headers=None, low_security=False, alpn=None, dh=None):
    """Start a local HTTPS server. Returns (port, server)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if low_security:
        # allow serving weak certs (e.g. 1024-bit RSA) for testing;
        # must come BEFORE load_cert_chain
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    ctx.load_cert_chain(os.path.join(CERTDIR, cert + ".crt"),
                        os.path.join(CERTDIR, cert + ".key"))
    if dh:
        # DH params must load while the security level is lowered
        # (low_security=True) - OpenSSL refuses sub-2048 DH otherwise
        ctx.load_dh_params(os.path.join(CERTDIR, dh + ".pem"))
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if min_ver:
        ctx.minimum_version = min_ver
    if max_ver:
        ctx.maximum_version = max_ver
    if ciphers:
        ctx.set_ciphers(ciphers)
    Handler.extra_headers = headers or {}
    srv = ThreadedHTTP(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.socket.getsockname()[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    return port, srv


FULL_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def audit(port):
    a = HTTPSAuditor("127.0.0.1", port=port, timeout=5)
    findings = a.audit()
    return a, findings


# ---------------- tests ----------------
def test_good_server():
    port, srv = start_https(headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("good_no_weak_protocol", not findings_by_issue(f, "weak protocol"))
        check("good_no_weak_cipher", not findings_by_issue(f, "weak cipher"))
        check("good_hsts_parsed", a.info.get("hsts", {}).get("max_age") == 31536000,
              f"got {a.info.get('hsts')}")
        check("good_no_hsts_finding", not findings_by_issue(f, "HSTS"))
        check("good_no_csp_finding", not findings_by_issue(f, "Content-Security-Policy"))
        check("good_no_frame_finding", not findings_by_issue(f, "X-Frame-Options"))
        check("good_no_sniff_finding", not findings_by_issue(f, "X-Content-Type-Options"))
        check("good_cert_key", a.info.get("cert_key") == "RSA-2048",
              f"got {a.info.get('cert_key')}")
        check("good_sig_alg", a.info.get("cert_sig_alg") == "sha256WithRSAEncryption",
              f"got {a.info.get('cert_sig_alg')}")
        check("good_selfsigned_noted", bool(findings_by_issue(f, "Self-signed")),
              "expected: our test certs are self-signed")
        check("good_no_compression", not findings_by_issue(f, "compression"))
        check("good_heartbeat_guidance", bool(findings_by_issue(f, "Heartbleed")),
              "guidance finding should always be present")
        check("good_tls13_or_12", a.info.get("tls_versions_offered") and
              ("TLS 1.3" in a.info["tls_versions_offered"] or
               "TLS 1.2" in a.info["tls_versions_offered"]),
              f"got {a.info.get('tls_versions_offered')}")
    finally:
        srv.shutdown()


def test_weak_cipher_server():
    try:
        port, srv = start_https(ciphers="DES-CBC3-SHA", headers=FULL_HEADERS,
                                max_ver=ssl.TLSVersion.TLSv1_2,
                                low_security=True)
    except ssl.SSLError as e:
        print(f"  [SKIP] weak cipher server not supported by OpenSSL: {e}")
        PASSED.append("weak_cipher_server (skipped)")
        return
    try:
        a, f = audit(port)
        weak = findings_by_issue(f, "weak cipher")
        check("weakcipher_detected", len(weak) >= 1, f"findings={[x['issue'] for x in f]}")
        check("weakcipher_3des", any("3DES" in w["issue"] or "DES-CBC3" in w["issue"]
                                     for w in weak), f"got {[w['issue'] for w in weak]}")
    finally:
        srv.shutdown()


def test_tls10_server():
    try:
        port, srv = start_https(headers=FULL_HEADERS,
                                min_ver=ssl.TLSVersion.TLSv1,
                                max_ver=ssl.TLSVersion.TLSv1)
    except Exception as e:
        print(f"  [SKIP] TLS1.0 server not supported: {e}")
        PASSED.append("tls10_server (skipped)")
        return
    try:
        a, f = audit(port)
        # server may fail to handshake at all on OpenSSL 3.0 - either way, no crash
        offered = a.info.get("tls_versions_offered", [])
        if "TLS 1.0" in offered:
            check("tls10_flagged", bool(findings_by_issue(f, "TLS 1.0")),
                  f"findings={[x['issue'] for x in f]}")
        else:
            print("  [SKIP] TLS1.0 handshake blocked by local OpenSSL")
            PASSED.append("tls10_flagged (skipped)")
    finally:
        srv.shutdown()


def test_weak_key():
    port, srv = start_https(cert="weakkey", headers=FULL_HEADERS,
                            low_security=True)
    try:
        a, f = audit(port)
        check("weakkey_detected", bool(findings_by_issue(f, "Weak RSA key")),
              f"info={a.info.get('cert_key')}")
    finally:
        srv.shutdown()


def test_weak_sig():
    port, srv = start_https(cert="weaksig", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("weaksig_detected", bool(findings_by_issue(f, "Weak certificate signature")),
              f"sig={a.info.get('cert_sig_alg')}")
    finally:
        srv.shutdown()


def test_short_hsts():
    port, srv = start_https(headers={"Strict-Transport-Security": "max-age=60"})
    try:
        a, f = audit(port)
        check("short_hsts_flagged", bool(findings_by_issue(f, "max-age too short")))
        check("hsts_no_subdomains", bool(findings_by_issue(f, "includeSubDomains")))
    finally:
        srv.shutdown()


def test_missing_headers():
    port, srv = start_https(headers={})
    try:
        a, f = audit(port)
        check("missing_hsts", bool(findings_by_issue(f, "HSTS header missing")))
        check("missing_csp", bool(findings_by_issue(f, "Content-Security-Policy missing")))
        check("missing_xfo", bool(findings_by_issue(f, "X-Frame-Options missing")))
        check("missing_nosniff", bool(findings_by_issue(f, "X-Content-Type-Options")))
    finally:
        srv.shutdown()


def test_expiry_logic():
    from datetime import datetime, timedelta

    def _fmt(dt):
        # real cert dicts look like "Oct  9 19:22:50 2026 GMT"
        return dt.strftime("%b %d %H:%M:%S %Y") + " GMT"

    past = _fmt(datetime.utcnow() - timedelta(days=10))
    soon = _fmt(datetime.utcnow() + timedelta(days=5))
    far = _fmt(datetime.utcnow() + timedelta(days=400))
    check("expiry_past", HTTPSAuditor._cert_days_left({"notAfter": past}) < 0)
    d = HTTPSAuditor._cert_days_left({"notAfter": soon})
    check("expiry_soon", d is not None and 0 <= d <= 6, f"got {d}")
    d2 = HTTPSAuditor._cert_days_left({"notAfter": far})
    check("expiry_far", d2 is not None and d2 > 300, f"got {d2}")
    check("expiry_bad", HTTPSAuditor._cert_days_left({}) is None)


def test_der_parser():
    with open(os.path.join(CERTDIR, "good.crt"), "rb") as fh:
        # PEM -> DER
        import base64
        pem = fh.read().decode()
        b64 = "".join(l for l in pem.splitlines() if "-----" not in l)
        der = base64.b64decode(b64)
    p = parse_cert_der(der)
    check("der_rsa2048", p["key_type"] == "RSA" and p["key_bits"] == 2048, f"got {p}")
    check("der_sha256", p["sig_oid"] == "1.2.840.113549.1.1.11", f"got {p['sig_oid']}")
    with open(os.path.join(CERTDIR, "weaksig.crt"), "rb") as fh:
        pem = fh.read().decode()
        b64 = "".join(l for l in pem.splitlines() if "-----" not in l)
        der = base64.b64decode(b64)
    p2 = parse_cert_der(der)
    check("der_sha1", p2["sig_oid"] == "1.2.840.113549.1.1.5", f"got {p2['sig_oid']}")


def test_raw_hello():
    port, srv = start_https(headers=FULL_HEADERS)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(build_client_hello(hostname="127.0.0.1", with_status_request=True))
        data = s.recv(8192)
        s.close()
        exts = parse_server_hello_extensions(data)
        check("raw_hello_parses", isinstance(exts, set), f"got {exts}")
        # also via auditor (should not crash)
        a = HTTPSAuditor("127.0.0.1", port=port, timeout=5)
        a._check_ocsp_stapling()
        check("ocsp_check_runs", "ocsp_stapling" in a.info, f"info={a.info}")
    finally:
        srv.shutdown()


# ---------------- v0.3 Phase 1 tests ----------------
def test_renegotiation():
    # TLS 1.2 server: OpenSSL echoes renegotiation_info -> observed secure
    port, srv = start_https(headers=FULL_HEADERS,
                            max_ver=ssl.TLSVersion.TLSv1_2)
    try:
        a, f = audit(port)
        check("reneg_secure_observed", a.info.get("secure_renegotiation") is True,
              f"info={a.info.get('secure_renegotiation')}")
        check("reneg_no_tls015", not by_check(f, "TLS-015"))
    finally:
        srv.shutdown()


def test_forward_secrecy_present():
    port, srv = start_https(headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("fs_present", a.info.get("forward_secrecy") is True,
              f"ciphers={a.info.get('ciphers_accepted')}")
        check("fs_no_tls017", not by_check(f, "TLS-017"))
    finally:
        srv.shutdown()


def test_static_rsa_only_server():
    # server offering ONLY a static-RSA suite -> TLS-017 + TLS-019 fire
    try:
        port, srv = start_https(ciphers="AES128-SHA", headers=FULL_HEADERS,
                                max_ver=ssl.TLSVersion.TLSv1_2,
                                low_security=True)
    except ssl.SSLError as e:
        print(f"  [SKIP] static-RSA server not supported by OpenSSL: {e}")
        PASSED.append("static_rsa_server (skipped)")
        return
    try:
        a, f = audit(port)
        check("fs_absent_flagged", bool(by_check(f, "TLS-017")),
              f"ciphers={a.info.get('ciphers_accepted')}")
        check("fs_info_false", a.info.get("forward_secrecy") is False,
              f"info={a.info.get('forward_secrecy')}")
        check("rsa_kx_flagged", bool(by_check(f, "TLS-019")),
              f"findings={[x['issue'] for x in f]}")
        check("rsa_kx_listed", "AES128-SHA" in (a.info.get("rsa_kx_suites") or []),
              f"info={a.info.get('rsa_kx_suites')}")
    finally:
        srv.shutdown()


def test_alpn():
    port, srv = start_https(headers=FULL_HEADERS, alpn=["h2", "http/1.1"])
    try:
        a, f = audit(port)
        check("alpn_h2_negotiated", a.info.get("alpn") == "h2",
              f"info={a.info.get('alpn')}")
        check("alpn_finding", bool(by_check(f, "TLS-023")))
    finally:
        srv.shutdown()


def test_session_detail():
    port, srv = start_https(headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("session_version_recorded", bool(a.info.get("session_version")),
              f"info keys={sorted(a.info)}")
        check("session_mechanism_recorded",
              bool(a.info.get("session_mechanism")),
              f"info={a.info.get('session_mechanism')}")
        if a.info.get("session_version") == "TLSv1.3":
            check("session_mechanism_psk",
                  a.info.get("session_mechanism") == "PSK (TLS 1.3)",
                  f"info={a.info.get('session_mechanism')}")
    finally:
        srv.shutdown()


def test_cert_validity_windows():
    port, srv = start_https(cert="longcert", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("long_validity_flagged", bool(by_check(f, "TLS-028")),
              f"validity_days={a.info.get('cert_validity_days')}")
    finally:
        srv.shutdown()
    port, srv = start_https(cert="shortcert", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        hits = by_check(f, "TLS-029")
        check("expiry_7day_escalated",
              bool(hits) and hits[0]["severity"] == "HIGH",
              f"hits={hits} days={a.info.get('cert_expires_in_days')}")
    finally:
        srv.shutdown()


def _der_of(name):
    import base64
    with open(os.path.join(CERTDIR, name + ".crt"), "rb") as fh:
        pem = fh.read().decode()
    b64 = "".join(l for l in pem.splitlines() if "-----" not in l)
    return base64.b64decode(b64)


def test_cert_extensions_der():
    p = parse_cert_der(_der_of("leaf_serverauth"))
    check("der_eku_parsed", p["eku_oids"] == ["1.3.6.1.5.5.7.3.1"],
          f"got {p['eku_oids']}")
    check("der_bc_false_parsed", p["basic_constraints_ca"] is False,
          f"got {p['basic_constraints_ca']}")
    check("der_extensions_captured",
          "2.5.29.37" in p["extensions"] and "2.5.29.19" in p["extensions"],
          f"got {sorted(p['extensions'])}")
    p2 = parse_cert_der(_der_of("good"))
    check("der_bc_selfsigned_true", p2["basic_constraints_ca"] is True,
          f"got {p2['basic_constraints_ca']}")
    check("der_eku_absent_none", p2["eku_oids"] is None,
          f"got {p2['eku_oids']}")


def test_cert_eku_and_basic_constraints():
    # CA-issued leaf WITH serverAuth EKU and CA:FALSE -> clean
    port, srv = start_https(cert="leaf_serverauth", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("eku_serverauth_ok", not by_check(f, "TLS-030"),
              f"eku={a.info.get('cert_eku')}")
        check("leaf_bc_false_ok", not by_check(f, "TLS-031"))
    finally:
        srv.shutdown()
    # CA-issued leaf with clientAuth-only EKU -> TLS-030 fires
    port, srv = start_https(cert="leaf_clientauth", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("eku_missing_serverauth", bool(by_check(f, "TLS-030")),
              f"eku={a.info.get('cert_eku')}")
    finally:
        srv.shutdown()
    # CA-issued leaf asserting CA:TRUE -> TLS-031 fires
    port, srv = start_https(cert="leaf_catrue", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("leaf_ca_true_flagged", bool(by_check(f, "TLS-031")),
              f"findings={[x['issue'] for x in f]}")
    finally:
        srv.shutdown()
    # self-signed cert is its own CA -> TLS-031 must NOT fire on it
    port, srv = start_https(headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("selfsigned_no_tls031", not by_check(f, "TLS-031"))
        check("no_eku_no_tls030", not by_check(f, "TLS-030"))
    finally:
        srv.shutdown()


def test_cert_scope():
    port, srv = start_https(cert="wildbad", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("multilevel_wildcard_flagged", bool(by_check(f, "TLS-032")),
              f"san={a.info.get('cert_san_dns')}")
    finally:
        srv.shutdown()
    port, srv = start_https(cert="sprawl", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("san_sprawl_flagged", bool(by_check(f, "TLS-032")),
              f"san_count={len(a.info.get('cert_san_dns') or [])}")
    finally:
        srv.shutdown()


def test_no_tls13():
    port, srv = start_https(headers=FULL_HEADERS,
                            max_ver=ssl.TLSVersion.TLSv1_2)
    try:
        a, f = audit(port)
        check("no_tls13_noted", bool(by_check(f, "TLS-033")),
              f"offered={a.info.get('tls_versions_offered')}")
    finally:
        srv.shutdown()
    port, srv = start_https(headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("tls13_present_no_note", not by_check(f, "TLS-033"),
              f"offered={a.info.get('tls_versions_offered')}")
    finally:
        srv.shutdown()


# ---------------- v0.3 Phase 2 tests ----------------
def test_handshake_parsers():
    ders = [b"\x30\x03\x02\x01\x05", b"\x30\x03\x02\x01\x06"]
    blob = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    body = len(blob).to_bytes(3, "big") + blob
    hs = b"\x0b" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    msgs = parse_handshake_messages(rec)
    check("hs_parser_cert_msg", len(msgs) == 1 and msgs[0][0] == 0x0B,
          f"msgs={msgs}")
    got = parse_certificate_message(msgs[0][1]) if msgs else []
    check("cert_msg_ders_in_order", got == ders, f"got={got}")
    check("cert_msg_empty", parse_certificate_message(b"") == [])
    # alert records are not handshake messages
    check("hs_parser_skips_alerts",
          parse_handshake_messages(b"\x15\x03\x03\x00\x02\x02\x56") == [])


def test_fallback_scsv_unit():
    sh_body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" +
               struct.pack("!H", 0x002F) + b"\x00" + struct.pack("!H", 0))
    hs = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    rec = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    check("fallback_verdict_vulnerable",
          fallback_scsv_verdict(rec) == "vulnerable")
    check("fallback_verdict_protected",
          fallback_scsv_verdict(b"\x15\x03\x03\x00\x02\x02\x56") == "protected")
    check("fallback_verdict_other_alert",
          fallback_scsv_verdict(b"\x15\x03\x03\x00\x02\x02\x46") == "inconclusive")
    check("fallback_verdict_empty", fallback_scsv_verdict(b"") == "inconclusive")


def test_fallback_scsv_live():
    # Server whose minimum is TLS 1.0 and maximum is 1.3: a TLS 1.1
    # fallback hello carrying the SCSV must be aborted with alert 86.
    try:
        port, srv = start_https(headers=FULL_HEADERS,
                                min_ver=ssl.TLSVersion.TLSv1,
                                low_security=True)
    except Exception as e:
        print(f"  [SKIP] legacy-TLS server not supported: {e}")
        PASSED.append("fallback_live (skipped)")
        return
    try:
        a, f = audit(port)
        check("fallback_protected_live", a.info.get("fallback_scsv") is True,
              f"info={a.info.get('fallback_scsv')}")
        check("fallback_no_tls016", not by_check(f, "TLS-016"))
    finally:
        srv.shutdown()


def test_sslv2():
    hello_resp = struct.pack("!H", 11 | 0x8000) + b"\x04" + b"\x00" * 10
    check("sslv2_verdict_serverhello", sslv2_verdict(hello_resp) is True)
    err = struct.pack("!H", 2 | 0x8000) + b"\x0f\x00"  # SSLv2 error message
    check("sslv2_verdict_error", sslv2_verdict(err) is False)
    check("sslv2_verdict_tls_record",
          sslv2_verdict(b"\x16\x03\x03\x00\x00") is False)
    check("sslv2_verdict_empty", sslv2_verdict(b"") is False)
    check("sslv2_hello_shape",
          build_sslv2_client_hello()[2] == 0x01)  # CLIENT-HELLO msg type
    port, srv = start_https(headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("sslv2_not_offered_live", a.info.get("sslv2") is False,
              f"info={a.info.get('sslv2')}")
        check("sslv2_no_tls018", not by_check(f, "TLS-018"))
    finally:
        srv.shutdown()


def test_logjam_parser():
    p = (1 << 2047) | 0x12345
    pb = p.to_bytes(256, "big")
    body = (struct.pack("!H", len(pb)) + pb + struct.pack("!H", 1) + b"\x02"
            + struct.pack("!H", 1) + b"\x03")
    check("logjam_parser_2048",
          parse_server_key_exchange_dh_bits(body) == 2048,
          f"got {parse_server_key_exchange_dh_bits(body)}")
    check("logjam_parser_empty", parse_server_key_exchange_dh_bits(b"") is None)
    check("logjam_parser_truncated",
          parse_server_key_exchange_dh_bits(b"\x00\x10\x01") is None)


def test_logjam_weak_dh():
    try:
        port, srv = start_https(
            headers=FULL_HEADERS, max_ver=ssl.TLSVersion.TLSv1_2,
            ciphers="DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA",
            low_security=True, dh="dh1024")
    except Exception as e:
        print(f"  [SKIP] DHE server not supported: {e}")
        PASSED.append("logjam_server (skipped)")
        return
    try:
        a, f = audit(port)
        check("logjam_bits_1024", a.info.get("dh_param_bits") == 1024,
              f"info={a.info.get('dh_param_bits')}")
        hits = by_check(f, "TLS-020")
        check("logjam_flagged_high",
              bool(hits) and hits[0]["severity"] == "HIGH", f"hits={hits}")
        check("logjam_cve", bool(hits) and hits[0].get("cve") == "CVE-2015-4000",
              f"hits={hits}")
    finally:
        srv.shutdown()
    # a default (ECDHE) server must not produce a Logjam finding
    port, srv = start_https(headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("logjam_absent_on_ecdhe", not by_check(f, "TLS-020"),
              f"dh_bits={a.info.get('dh_param_bits')}")
    finally:
        srv.shutdown()


def test_tls021_candidates_rules():
    check("bf_candidate_present", "BF-CBC" in CIPHER_CANDIDATES)
    check("idea_candidate_present", "IDEA-CBC-SHA" in CIPHER_CANDIDATES)
    rules = {r[0]: r for r in WEAK_CIPHER_RULES}
    check("bf_rule_tls021",
          rules.get("BF", (None,) * 4)[1] == "MEDIUM" and
          len(rules.get("BF", ())) > 3 and rules["BF"][3] == "TLS-021",
          f"rule={rules.get('BF')}")
    check("idea_rule_tls021",
          rules.get("IDEA", (None,) * 4)[1] == "MEDIUM" and
          len(rules.get("IDEA", ())) > 3 and rules["IDEA"][3] == "TLS-021",
          f"rule={rules.get('IDEA')}")
    # stock OpenSSL cannot serve BF/IDEA, so simulate a negotiated suite
    # to prove the rule fires end-to-end through enumeration
    a = HTTPSAuditor("127.0.0.1", port=1)
    a._check_one_cipher = lambda name: \
        (name, "TLSv1.2", 168) if name == "IDEA-CBC-SHA" else None
    a._enumerate_ciphers()
    hits = by_check(a.findings, "TLS-021")
    check("idea_rule_applied",
          bool(hits) and hits[0]["severity"] == "MEDIUM",
          f"findings={a.findings}")


def test_cbc_legacy_tls():
    def _mk(ciphers, versions):
        a = HTTPSAuditor("127.0.0.1", port=1)
        a.info["ciphers_accepted"] = ciphers
        a.info["tls_versions_offered"] = versions
        a._check_cbc_legacy_tls()
        return a

    a = _mk(["AES128-SHA"], ["TLS 1.0", "TLS 1.2"])
    check("cbc_tls10_flagged", bool(by_check(a.findings, "TLS-022")),
          f"findings={a.findings}")
    a = _mk(["ECDHE-RSA-AES128-SHA"], ["TLS 1.1"])
    check("cbc_tls11_flagged", bool(by_check(a.findings, "TLS-022")))
    a = _mk(["ECDHE-RSA-AES128-GCM-SHA256"], ["TLS 1.0", "TLS 1.2"])
    check("aead_only_no_tls022", not by_check(a.findings, "TLS-022"))
    a = _mk(["AES128-SHA"], ["TLS 1.2", "TLS 1.3"])
    check("cbc_modern_tls_no_tls022", not by_check(a.findings, "TLS-022"))
    a = _mk([], ["TLS 1.0"])
    check("no_ciphers_no_tls022", not by_check(a.findings, "TLS-022"))


def test_must_staple():
    p = parse_cert_der(_der_of("leaf_staple"))
    check("tls_feature_ext_captured",
          "1.3.6.1.5.5.7.1.24" in p["extensions"],
          f"exts={sorted(p['extensions'])}")
    # local Python servers cannot staple -> promise unfulfilled -> HIGH
    port, srv = start_https(cert="leaf_staple", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("muststaple_promised_seen",
              a.info.get("ocsp_must_staple_promised") is True,
              f"features={a.info.get('cert_tls_features')}")
        hits = by_check(f, "TLS-027")
        check("muststaple_flagged_high",
              bool(hits) and hits[0]["severity"] == "HIGH", f"hits={hits}")
    finally:
        srv.shutdown()
    # cross-check logic: promised + stapling offered -> clean
    a2 = HTTPSAuditor("127.0.0.1", port=1)
    a2.info["ocsp_must_staple_promised"] = True
    a2.info["ocsp_stapling"] = "offered"
    a2._check_must_staple()
    check("muststaple_delivered_ok", not by_check(a2.findings, "TLS-027"))
    check("muststaple_info_true", a2.info.get("ocsp_must_staple") is True)
    # no promise -> never fires
    a3 = HTTPSAuditor("127.0.0.1", port=1)
    a3.info["ocsp_stapling"] = "not offered"
    a3._check_must_staple()
    check("muststaple_no_promise_ok", not by_check(a3.findings, "TLS-027"))
    # leaf without the extension -> no TLS-027 in a full audit
    port, srv = start_https(cert="leaf_serverauth", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("no_feature_no_tls027", not by_check(f, "TLS-027"))
    finally:
        srv.shutdown()


def test_chain_good_order():
    port, srv = start_https(cert="chaingood", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("chain_len_2", a.info.get("chain_length") == 2,
              f"info={a.info.get('chain_length')}")
        check("chain_order_ok", a.info.get("chain_order_ok") is True,
              f"info={a.info.get('chain_order_ok')}")
        check("chain_good_no_tls025", not by_check(f, "TLS-025"))
        check("chain_good_no_tls026", not by_check(f, "TLS-026"),
              f"hits={by_check(f, 'TLS-026')}")
    finally:
        srv.shutdown()


def test_chain_bad_order():
    port, srv = start_https(cert="chainbad", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        check("chainbad_len_3", a.info.get("chain_length") == 3,
              f"info={a.info.get('chain_length')}")
        check("chainbad_order_flag", a.info.get("chain_order_ok") is False,
              f"info={a.info.get('chain_order_ok')}")
        check("chainbad_tls025", bool(by_check(f, "TLS-025")),
              f"findings={[x['issue'] for x in f]}")
    finally:
        srv.shutdown()


def test_chain_weak_intermediate():
    # low_security: OpenSSL refuses to even load a SHA-1-signed chain at
    # the default security level (CA_MD_TOO_WEAK)
    port, srv = start_https(cert="chainweak", headers=FULL_HEADERS,
                            low_security=True)
    try:
        a, f = audit(port)
        hits = by_check(f, "TLS-026")
        check("chainweak_tls026_high",
              bool(hits) and any(h["severity"] == "HIGH" for h in hits),
              f"hits={hits}")
        check("chainweak_order_still_ok", a.info.get("chain_order_ok") is True,
              f"info={a.info.get('chain_order_ok')}")
    finally:
        srv.shutdown()


def test_chain_weak_root():
    port, srv = start_https(cert="chainroot", headers=FULL_HEADERS)
    try:
        a, f = audit(port)
        hits = by_check(f, "TLS-026")
        check("chainroot_tls026_low_only",
              bool(hits) and all(h["severity"] == "LOW" for h in hits),
              f"hits={hits}")
    finally:
        srv.shutdown()


def main():
    print("=" * 55)
    print("  CyberRakshak advanced TLS auditor tests (localhost only)")
    print("=" * 55)
    ensure_fixtures()
    tests = [test_good_server, test_weak_cipher_server, test_tls10_server,
             test_weak_key, test_weak_sig, test_short_hsts,
             test_missing_headers, test_expiry_logic, test_der_parser,
             test_raw_hello,
             test_renegotiation, test_forward_secrecy_present,
             test_static_rsa_only_server, test_alpn, test_session_detail,
             test_cert_validity_windows, test_cert_extensions_der,
             test_cert_eku_and_basic_constraints, test_cert_scope,
             test_no_tls13,
             test_handshake_parsers, test_fallback_scsv_unit,
             test_fallback_scsv_live, test_sslv2, test_logjam_parser,
             test_logjam_weak_dh, test_tls021_candidates_rules,
             test_cbc_legacy_tls, test_must_staple, test_chain_good_order,
             test_chain_bad_order, test_chain_weak_intermediate,
             test_chain_weak_root]
    for fn in tests:
        print(f"\n* {fn.__name__}")
        try:
            fn()
        except Exception as e:
            FAILED.append(fn.__name__)
            import traceback
            traceback.print_exc()
            print(f"  [ERROR] {fn.__name__}: {e}")
    print()
    print("=" * 55)
    print(f"  PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    if FAILED:
        print(f"  failed: {FAILED}")
    print("=" * 55)
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
