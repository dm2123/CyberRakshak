#!/usr/bin/env python3
"""CyberRakshak web auditor tests (v0.3 Phase 1 + Phase 3) - localhost only.

Spins up tiny local HTTP/HTTPS servers and verifies the Phase 1 web
checks (WEB-006 disclosure, WEB-007 redirect, WEB-009 HSTS over HTTP,
WEB-010 security.txt, repeated-header fetch scaffold) and the Phase 3
deep checks: WEB-001 (CSP), WEB-002 (cookies), WEB-003 (CORS),
WEB-004 (exposed files), WEB-005 (TRACE/TRACK), WEB-008 (mixed
content), WEB-011 (clickjacking), WEB-012 (referrer-policy).

Run: python3 tests/test_web_auditor.py
"""

import http.server
import os
import socketserver
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from web.web_auditor import WebAuditor

CERTDIR = "/tmp/tlstest"
PASSED, FAILED = [], []


def check(name, cond, detail=""):
    if cond:
        PASSED.append(name)
        print(f"  [PASS] {name}")
    else:
        FAILED.append(name)
        print(f"  [FAIL] {name} {detail}")


def by_check(findings, check_id):
    return [f for f in findings if f.get("check") == check_id]


class WebHandler(http.server.BaseHTTPRequestHandler):
    # configured per test via class attributes (same pattern as TLS tests)
    response_headers = []   # list of (name, value) - duplicates allowed
    routes = {}             # path -> (status, body bytes)
    trace_echo = False      # True -> TRACE returns a 200 header echo

    def _respond(self):
        status, body = self.routes.get(self.path, (404, b""))
        self.send_response_only(status)
        for k, v in self.response_headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _respond
    do_HEAD = _respond
    do_OPTIONS = _respond

    def do_TRACE(self):
        if self.trace_echo:
            body = (self.requestline + "\r\n"
                    + str(self.headers)).encode("utf-8", "ignore")
            self.send_response_only(200)
            self.send_header("Content-Type", "message/http")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(501)

    def log_message(self, *a):
        pass


class ThreadedHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def _serve(headers, routes, trace_echo=False):
    WebHandler.response_headers = headers or []
    WebHandler.routes = routes or {}
    WebHandler.trace_echo = trace_echo
    srv = ThreadedHTTP(("127.0.0.1", 0), WebHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    return port, srv


def start_http(headers=None, routes=None, trace_echo=False):
    return _serve(headers, routes, trace_echo)


def start_https_web(headers=None, routes=None, cert="good",
                    trace_echo=False):
    WebHandler.response_headers = headers or []
    WebHandler.routes = routes or {}
    WebHandler.trace_echo = trace_echo
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERTDIR, cert + ".crt"),
                        os.path.join(CERTDIR, cert + ".key"))
    srv = ThreadedHTTP(("127.0.0.1", 0), WebHandler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.socket.getsockname()[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    return port, srv


def audit_http(port):
    a = WebAuditor("127.0.0.1", port=port, use_tls=False, timeout=5)
    return a, a.audit()


def audit_https(port):
    a = WebAuditor("127.0.0.1", port=port, use_tls=True, timeout=5)
    return a, a.audit()


# ---------------- tests ----------------
def test_redirect_missing():
    port, srv = start_http(routes={"/": (200, b"hello")})
    try:
        a, f = audit_http(port)
        hits = by_check(f, "WEB-007")
        check("redirect_missing_flagged",
              bool(hits) and hits[0]["severity"] == "MEDIUM", f"hits={hits}")
        check("redirect_info_false", a.info.get("http_redirects_to_https") is False)
    finally:
        srv.shutdown()


def test_redirect_ok():
    port, srv = start_http(
        headers=[("Location", "https://127.0.0.1/")],
        routes={"/": (301, b"")})
    try:
        a, f = audit_http(port)
        check("redirect_ok_no_finding", not by_check(f, "WEB-007"),
              f"findings={f}")
        check("redirect_info_true", a.info.get("http_redirects_to_https") is True)
    finally:
        srv.shutdown()


def test_redirect_chain_http():
    port, srv = start_http(
        headers=[("Location", "http://127.0.0.1/landing")],
        routes={"/": (302, b"")})
    try:
        a, f = audit_http(port)
        hits = by_check(f, "WEB-007")
        check("redirect_chain_flagged",
              bool(hits) and hits[0]["severity"] == "LOW", f"hits={hits}")
    finally:
        srv.shutdown()


def test_hsts_over_http():
    port, srv = start_http(
        headers=[("Strict-Transport-Security", "max-age=31536000")],
        routes={"/": (200, b"hello")})
    try:
        a, f = audit_http(port)
        check("hsts_over_http_flagged", bool(by_check(f, "WEB-009")),
              f"findings={f}")
        check("hsts_over_http_no_finding_on_https_path",
              a.info.get("hsts_over_http") is True)
    finally:
        srv.shutdown()


def test_disclosure():
    port, srv = start_https_web(
        headers=[("Server", "Apache/2.4.49 (Unix)"),
                 ("X-Powered-By", "PHP/8.1.2")],
        routes={"/": (200, b"ok"),
                "/.well-known/security.txt": (404, b"")})
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-006")
        check("disclosure_two_headers", len(hits) == 2,
              f"hits={[h['issue'] for h in hits]}")
        tech = {(d["service"], d["version"])
                for d in a.info.get("disclosed_tech", [])}
        check("disclosure_apache_parsed", ("Apache", "2.4.49") in tech,
              f"tech={tech}")
        check("disclosure_php_parsed", ("PHP", "8.1.2") in tech,
              f"tech={tech}")
    finally:
        srv.shutdown()


def test_no_disclosure():
    port, srv = start_https_web(
        headers=[("Server", "Apache")],
        routes={"/": (200, b"ok"),
                "/.well-known/security.txt": (404, b"")})
    try:
        a, f = audit_https(port)
        check("no_version_no_finding", not by_check(f, "WEB-006"),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_security_txt():
    port, srv = start_https_web(
        routes={"/": (200, b"ok"),
                "/.well-known/security.txt":
                    (200, b"Contact: mailto:sec@example.invalid\n")})
    try:
        a, f = audit_https(port)
        check("security_txt_flagged", bool(by_check(f, "WEB-010")),
              f"findings={f}")
        check("security_txt_info", a.info.get("security_txt") is True)
        # redaction rule: response body must never leak into findings
        check("security_txt_body_not_in_findings",
              "mailto:" not in str(f), f"findings={f}")
    finally:
        srv.shutdown()
    port, srv = start_https_web(
        routes={"/": (200, b"ok"),
                "/.well-known/security.txt": (404, b"")})
    try:
        a, f = audit_https(port)
        check("security_txt_absent_quiet", not by_check(f, "WEB-010"))
        check("security_txt_absent_info", a.info.get("security_txt") is False)
    finally:
        srv.shutdown()


def test_repeated_headers_preserved():
    port, srv = start_https_web(
        headers=[("Set-Cookie", "a=1; HttpOnly"),
                 ("Set-Cookie", "b=2; Secure")],
        routes={"/": (200, b"ok")})
    try:
        a = WebAuditor("127.0.0.1", port=port, use_tls=True, timeout=5)
        status, headers, _body = a._fetch("/")
        cookies = [v for k, v in headers if k == "set-cookie"]
        check("repeated_headers_preserved", len(cookies) == 2,
              f"cookies={cookies}")
    finally:
        srv.shutdown()


# ---------------- Phase 3 tests ----------------
def issues(findings, check_id):
    return [f["issue"] for f in by_check(findings, check_id)]


def test_csp_weak():
    csp = ("default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' "
           "data: https://cdn.example.invalid")
    port, srv = start_https_web(
        headers=[("Content-Security-Policy", csp),
                 ("X-Frame-Options", "DENY")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-001")
        texts = [h["issue"] for h in hits]
        check("csp_unsafe_inline_medium",
              any("unsafe-inline" in t and h["severity"] == "MEDIUM"
                  for t, h in zip(texts, hits)), f"hits={texts}")
        check("csp_unsafe_eval_flagged",
              any("unsafe-eval" in t for t in texts), f"hits={texts}")
        check("csp_data_flagged", any("data:" in t for t in texts),
              f"hits={texts}")
        check("csp_object_src_missing_flagged",
              any("object-src" in t for t in texts), f"hits={texts}")
        check("csp_base_uri_missing_flagged",
              any("base-uri" in t for t in texts), f"hits={texts}")
        check("csp_frame_ancestors_missing_flagged",
              any("frame-ancestors" in t for t in texts), f"hits={texts}")
        # XFO present -> the WEB-011 combined rule must stay quiet
        check("csp_weak_xfo_saves_clickjacking",
              not by_check(f, "WEB-011"), f"findings={f}")
    finally:
        srv.shutdown()


def test_csp_missing():
    port, srv = start_https_web(routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-001")
        check("csp_missing_medium",
              bool(hits) and hits[0]["severity"] == "MEDIUM"
              and "missing" in hits[0]["issue"], f"hits={hits}")
        hits11 = by_check(f, "WEB-011")
        check("clickjacking_flagged_when_bare",
              bool(hits11) and hits11[0]["severity"] == "MEDIUM",
              f"hits={hits11}")
    finally:
        srv.shutdown()


def test_csp_strong():
    csp = ("default-src 'none'; script-src 'self'; object-src 'none'; "
           "base-uri 'self'; frame-ancestors 'none'")
    port, srv = start_https_web(
        headers=[("Content-Security-Policy", csp)],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        check("csp_strong_no_web001", not by_check(f, "WEB-001"),
              f"findings={f}")
        check("csp_strong_no_web011", not by_check(f, "WEB-011"),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_cookies_bad():
    port, srv = start_https_web(
        headers=[("Set-Cookie", "sessionid=SECRETVALUE123; Path=/")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        texts = issues(f, "WEB-002")
        check("cookie_missing_secure",
              any("Secure" in t for t in texts), f"hits={texts}")
        check("cookie_missing_httponly",
              any("HttpOnly" in t for t in texts), f"hits={texts}")
        check("cookie_missing_samesite",
              any("SameSite" in t for t in texts), f"hits={texts}")
        check("cookie_name_reported", any("sessionid" in t for t in texts),
              f"hits={texts}")
        # redaction: the cookie VALUE must never appear in findings
        check("cookie_value_redacted", "SECRETVALUE123" not in str(f),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_cookie_samesite_none():
    port, srv = start_https_web(
        headers=[("Set-Cookie", "pref=1; HttpOnly; SameSite=None")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        texts = issues(f, "WEB-002")
        check("cookie_samesite_none_no_secure",
              any("SameSite=None" in t for t in texts), f"hits={texts}")
    finally:
        srv.shutdown()


def test_cookie_host_prefix():
    port, srv = start_https_web(
        headers=[("Set-Cookie",
                  "__Host-id=abc; Path=/; HttpOnly; SameSite=Lax")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        texts = issues(f, "WEB-002")
        check("cookie_host_prefix_violation",
              any("__Host-" in t and "prefix" in t for t in texts),
              f"hits={texts}")
    finally:
        srv.shutdown()


def test_cookie_good():
    port, srv = start_https_web(
        headers=[("Set-Cookie",
                  "sid=1; Secure; HttpOnly; SameSite=Strict; Path=/")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        check("cookie_good_no_findings", not by_check(f, "WEB-002"),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_cors_echo_credentials():
    port, srv = start_https_web(
        headers=[("Access-Control-Allow-Origin",
                  "https://cyberrakshak-probe.invalid"),
                 ("Access-Control-Allow-Credentials", "true")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-003")
        check("cors_echo_with_credentials_high",
              bool(hits) and hits[0]["severity"] == "HIGH", f"hits={hits}")
    finally:
        srv.shutdown()


def test_cors_star():
    port, srv = start_https_web(
        headers=[("Access-Control-Allow-Origin", "*")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-003")
        check("cors_star_low", bool(hits) and hits[0]["severity"] == "LOW",
              f"hits={hits}")
    finally:
        srv.shutdown()


def test_cors_none():
    port, srv = start_https_web(routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        check("cors_absent_quiet", not by_check(f, "WEB-003"),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_exposed_git_and_env():
    port, srv = start_https_web(routes={
        "/": (200, b"ok"),
        "/.git/HEAD": (200, b"ref: refs/heads/main\n"),
        "/.env": (200, b"DB_PASSWORD=supersecretvalue\nAPI_KEY=xyz\n"),
    })
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-004")
        check("git_head_high",
              any(".git" in h["issue"] and h["severity"] == "HIGH"
                  for h in hits), f"hits={hits}")
        check("env_high",
              any(".env" in h["issue"] and h["severity"] == "HIGH"
                  for h in hits), f"hits={hits}")
        # redaction rule: secret contents never reach the findings
        check("env_contents_redacted",
              "supersecretvalue" not in str(f), f"findings={f}")
        check("server_status_absent_quiet",
              not any("server-status" in h["issue"] for h in hits),
              f"hits={hits}")
        check("exposed_info_lists_paths",
              set(a.info.get("exposed_files", []))
              == {"/.git/HEAD", "/.env"},
              f"info={a.info.get('exposed_files')}")
    finally:
        srv.shutdown()


def test_exposed_status_dsstore_robots():
    port, srv = start_https_web(routes={
        "/": (200, b"ok"),
        "/server-status": (200, b"Apache Server Status"),
        "/.DS_Store": (200, b"Bud1\x00\x00"),
        "/robots.txt": (200, b"User-agent: *\nDisallow: /admin/\n"),
    })
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-004")
        check("server_status_medium",
              any("server-status" in h["issue"]
                  and h["severity"] == "MEDIUM" for h in hits),
              f"hits={hits}")
        check("ds_store_low",
              any(".DS_Store" in h["issue"] and h["severity"] == "LOW"
                  for h in hits), f"hits={hits}")
        check("robots_info",
              any("robots.txt" in h["issue"] and h["severity"] == "INFO"
                  for h in hits), f"hits={hits}")
        # redaction rule applies to robots.txt too in this build
        check("robots_contents_not_quoted", "/admin/" not in str(f),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_exposed_none():
    port, srv = start_https_web(routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        check("exposed_none_quiet", not by_check(f, "WEB-004"),
              f"findings={f}")
        check("exposed_none_info_empty", a.info.get("exposed_files") == [])
    finally:
        srv.shutdown()


def test_trace_confirmed():
    port, srv = start_https_web(
        headers=[("Allow", "GET, HEAD, POST, TRACE")],
        routes={"/": (200, b"")}, trace_echo=True)
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-005")
        check("trace_confirmed_medium",
              bool(hits) and hits[0]["severity"] == "MEDIUM"
              and "TRACE" in hits[0]["issue"], f"hits={hits}")
        check("methods_info_recorded",
              "TRACE" in a.info.get("http_methods", []),
              f"info={a.info.get('http_methods')}")
    finally:
        srv.shutdown()


def test_trace_listed_not_confirmed():
    port, srv = start_https_web(
        headers=[("Allow", "GET, TRACE")],
        routes={"/": (200, b"")}, trace_echo=False)
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-005")
        check("trace_unconfirmed_no_medium",
              not any(h["severity"] == "MEDIUM" for h in hits),
              f"hits={hits}")
        check("trace_unconfirmed_info_note",
              any(h["severity"] == "INFO" for h in hits), f"hits={hits}")
    finally:
        srv.shutdown()


def test_methods_no_trace():
    port, srv = start_https_web(
        headers=[("Allow", "GET, POST")], routes={"/": (200, b"")})
    try:
        a, f = audit_https(port)
        check("methods_no_trace_quiet", not by_check(f, "WEB-005"),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_mixed_content():
    body = (b'<html><img src="http://cdn.example.invalid/x.png">'
            b'<a href="http://example.invalid/page">x</a></html>')
    port, srv = start_https_web(routes={"/": (200, body)})
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-008")
        check("mixed_content_low",
              bool(hits) and hits[0]["severity"] == "LOW", f"hits={hits}")
        check("mixed_content_count", a.info.get("mixed_content_count") == 2,
              f"info={a.info.get('mixed_content_count')}")
    finally:
        srv.shutdown()


def test_mixed_content_clean():
    port, srv = start_https_web(
        routes={"/": (200, b'<img src="https://cdn.example.invalid/x.png">')})
    try:
        a, f = audit_https(port)
        check("mixed_content_clean_quiet", not by_check(f, "WEB-008"),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_referrer_unsafe():
    port, srv = start_https_web(
        headers=[("Referrer-Policy", "unsafe-url")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        hits = by_check(f, "WEB-012")
        check("referrer_unsafe_url_low",
              bool(hits) and hits[0]["severity"] == "LOW", f"hits={hits}")
    finally:
        srv.shutdown()


def test_referrer_ok():
    port, srv = start_https_web(
        headers=[("Referrer-Policy", "strict-origin-when-cross-origin")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        check("referrer_ok_quiet", not by_check(f, "WEB-012"),
              f"findings={f}")
    finally:
        srv.shutdown()


def test_clickjacking_xfo_only():
    port, srv = start_https_web(
        headers=[("X-Frame-Options", "SAMEORIGIN")],
        routes={"/": (200, b"ok")})
    try:
        a, f = audit_https(port)
        check("clickjacking_xfo_quiet", not by_check(f, "WEB-011"),
              f"findings={f}")
    finally:
        srv.shutdown()


def main():
    print("=" * 55)
    print("  CyberRakshak web auditor tests - v0.3 Phase 1+3 (localhost)")
    print("=" * 55)
    tests = [test_redirect_missing, test_redirect_ok,
             test_redirect_chain_http, test_hsts_over_http,
             test_disclosure, test_no_disclosure, test_security_txt,
             test_repeated_headers_preserved,
             test_csp_weak, test_csp_missing, test_csp_strong,
             test_cookies_bad, test_cookie_samesite_none,
             test_cookie_host_prefix, test_cookie_good,
             test_cors_echo_credentials, test_cors_star, test_cors_none,
             test_exposed_git_and_env, test_exposed_status_dsstore_robots,
             test_exposed_none, test_trace_confirmed,
             test_trace_listed_not_confirmed, test_methods_no_trace,
             test_mixed_content, test_mixed_content_clean,
             test_referrer_unsafe, test_referrer_ok,
             test_clickjacking_xfo_only]
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
