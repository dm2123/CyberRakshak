"""CyberRakshak web-layer auditor - v0.3 Phase 1 + Phase 3.

Phase 1 checks (passive header/config observation - own systems only):
  WEB-006  Technology version disclosure (Server / X-Powered-By /
           X-AspNet-Version / X-Generator headers carrying versions)
  WEB-007  Missing HTTP -> HTTPS redirect (port 80 serves content, or
           the redirect chain starts with a plain-HTTP hop)
  WEB-009  HSTS header sent over plain HTTP (browsers ignore it there)
  WEB-010  /.well-known/security.txt published (good practice, positive)

Phase 3 deep checks (spec section 4):
  WEB-001  CSP deep analysis (unsafe-inline / unsafe-eval / wildcard /
           data: / blob: / http: in script sources, missing object-src,
           base-uri, frame-ancestors, no script policy at all)
  WEB-002  Cookie flag audit (Secure / HttpOnly / SameSite, SameSite=None
           without Secure, __Host- / __Secure- prefix rules; cookie
           VALUES are never copied into findings)
  WEB-003  Passive CORS misconfiguration (one GET with a probe Origin;
           response headers only - no cross-origin request is executed)
  WEB-004  Exposed sensitive files - a FIXED list of 6 well-known paths
           (no wordlist, no brute force, no traversal); the report only
           records exposed / not exposed, never file contents
  WEB-005  Dangerous HTTP methods (TRACE / TRACK via OPTIONS Allow,
           confirmed with a single standard-method request)
  WEB-008  Mixed-content hints (http:// subresources in an HTTPS page)
  WEB-011  Clickjacking: neither X-Frame-Options nor CSP
           frame-ancestors present
  WEB-012  Referrer-Policy: unsafe-url leaks full URLs to third parties

Design notes (per V03_DEEP_AUDITOR_SPEC.md section 4):
  * The fetch helper preserves REPEATED headers as a list of
    (name, value) pairs - HTTPSAuditor._fetch_headers() collapses them
    into a dict, which loses e.g. multiple Set-Cookie headers.
  * Requests are sequential with a 0.5 s pause between them, small read
    caps, no retries, no parallelism.
  * Defensive only: no payloads, no form posts, no logins, no directory
    brute-forcing - just plain GETs and header reading.
  * Response bodies are never copied into findings (redaction rule);
    the only exception is WEB-008, which reports the http:// URLs the
    page itself references (public markup, not secrets).

100% original code, stdlib only.
"""

import http.client
import re
import ssl
import time

from scanner.service_detector import VERSION_PATTERNS

DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                      "x-generator")
READ_CAP = 16384        # max body bytes read per response
EXPOSED_READ_CAP = 8192  # spec section 4: smaller cap for WEB-004 probes
PAUSE_SECONDS = 0.5     # politeness pause between requests
PROBE_ORIGIN = "https://cyberrakshak-probe.invalid"
# WEB-004 fixed list (spec section 4). /.well-known/security.txt is the
# 6th path but is reported by WEB-010, so it is not repeated here.
EXPOSED_PATHS = ("/.git/HEAD", "/.env", "/server-status",
                 "/.DS_Store", "/robots.txt")


class WebAuditor:
    """Web-layer checks for one HTTP(S) endpoint.

    use_tls=True  -> HTTPS endpoint (all checks; WEB-007/009 are the
                     plain-HTTP branch instead)
    use_tls=False -> plain-HTTP endpoint
    """

    def __init__(self, target, port=None, use_tls=True, timeout=5):
        self.target = target
        self.use_tls = use_tls
        self.port = port if port is not None else (443 if use_tls else 80)
        self.timeout = timeout
        self.findings = []
        self.info = {}
        self._fetched = 0

    # -- helpers ---------------------------------------------------------
    def _add(self, severity, issue, detail, check=None):
        # Same dict shape as the TLS auditor (spec section 2).
        finding = {"severity": severity, "issue": issue, "detail": detail}
        if check:
            finding["check"] = check
        self.findings.append(finding)

    def _fetch(self, path="/", method="GET", extra_headers=None,
               read_cap=None):
        """One sequential request.

        Returns (status, headers, body) where headers is a LIST of
        (lowercased-name, value) pairs - repeated headers are preserved.
        Returns (None, [], b"") on any error so checks fail soft.
        """
        if self._fetched:
            time.sleep(PAUSE_SECONDS)
        self._fetched += 1
        try:
            if self.use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_ciphers("DEFAULT@SECLEVEL=0")
                except Exception:
                    pass
                conn = http.client.HTTPSConnection(
                    self.target, self.port, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(
                    self.target, self.port, timeout=self.timeout)
            headers = {"User-Agent": "CyberRakshak web audit",
                       "Connection": "close"}
            if extra_headers:
                headers.update(extra_headers)
            conn.request(method, path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            headers = [(k.lower(), v) for k, v in resp.getheaders()]
            body = resp.read(read_cap or READ_CAP)
            conn.close()
            return status, headers, body
        except Exception:
            return None, [], b""

    @staticmethod
    def _header_values(headers, name):
        return [v for k, v in headers if k == name]

    # -- main ------------------------------------------------------------
    def audit(self):
        self.findings = []
        self.info = {}
        self._fetched = 0
        status, headers, body = self._fetch("/")
        if status is None:
            return self.findings
        self.info["http_status"] = status
        self._check_csp(headers)                # WEB-001
        self._check_cookies(headers)            # WEB-002
        self._check_clickjacking(headers)       # WEB-011
        self._check_referrer_policy(headers)    # WEB-012
        if self.use_tls:
            self._check_disclosure(headers)     # WEB-006
            self._check_mixed_content(body)     # WEB-008
        else:
            self._check_redirect_and_hsts(status, headers)  # WEB-007/009
        self._check_cors()                      # WEB-003
        self._check_methods()                   # WEB-005
        self._check_exposed_files()             # WEB-004
        if self.use_tls:
            self._check_security_txt()          # WEB-010
        return self.findings

    # WEB-001: CSP deep analysis -------------------------------------------
    @staticmethod
    def _parse_csp(values):
        """Parse CSP header value(s) into {directive: [sources]}."""
        directives = {}
        for value in values:
            for part in value.split(";"):
                tokens = part.split()
                if not tokens:
                    continue
                name = tokens[0].lower()
                directives.setdefault(name, [])
                directives[name].extend(t.lower() for t in tokens[1:])
        return directives

    def _check_csp(self, headers):
        values = self._header_values(headers, "content-security-policy")
        if not values:
            self.info["csp"] = {}
            self._add("MEDIUM", "Content-Security-Policy header missing",
                      "Without a CSP, any injected markup can run script "
                      "in the page's origin. Add a Content-Security-Policy "
                      "header, e.g. \"default-src 'self'; object-src "
                      "'none'; base-uri 'self'; frame-ancestors 'self'\", "
                      "and tighten it per page.", check="WEB-001")
            return
        csp = self._parse_csp(values)
        self.info["csp"] = csp
        script = csp.get("script-src", csp.get("default-src"))
        if script is None:
            self._add("MEDIUM",
                      "CSP has neither script-src nor default-src",
                      "The policy does not restrict script sources at "
                      "all, so it gives no XSS protection. Add a "
                      "default-src or an explicit script-src.",
                      check="WEB-001")
        else:
            if "'unsafe-inline'" in script:
                self._add("MEDIUM",
                          "CSP script-src allows 'unsafe-inline'",
                          "Inline script is allowed, which defeats most "
                          "of the CSP's XSS protection. Replace "
                          "'unsafe-inline' with a per-response nonce or "
                          "hash, or move scripts to external files.",
                          check="WEB-001")
            if "'unsafe-eval'" in script:
                self._add("MEDIUM",
                          "CSP script-src allows 'unsafe-eval'",
                          "eval() and similar string-to-code APIs are "
                          "allowed, widening the XSS blast radius. Remove "
                          "'unsafe-eval' and refactor code that needs it.",
                          check="WEB-001")
            if "*" in script:
                self._add("MEDIUM",
                          "CSP script-src allows any origin (*)",
                          "A wildcard script source lets an attacker load "
                          "script from anywhere if markup is injected. "
                          "Restrict script-src to 'self' and the specific "
                          "CDNs you actually use.", check="WEB-001")
            for token, label in (("data:", "data:"), ("blob:", "blob:")):
                if token in script:
                    self._add("LOW",
                              f"CSP script-src allows {label} URLs",
                              f"{label} in script sources lets injected "
                              "content smuggle script past the policy in "
                              "some browsers. Drop it unless a feature "
                              "genuinely needs it.", check="WEB-001")
            if "http:" in script:
                self._add("LOW",
                          "CSP script-src allows plain http: sources",
                          "Scripts may be loaded over unencrypted HTTP "
                          "and tampered with in transit. Use https: or "
                          "explicit https:// hosts instead.",
                          check="WEB-001")
        if "object-src" not in csp:
            self._add("LOW", "CSP missing object-src",
                      "Without object-src, legacy plugin content "
                      "(<object>/<embed>) falls back to default-src and "
                      "can re-open XSS paths. Add \"object-src 'none'\" "
                      "unless plugins are genuinely required.",
                      check="WEB-001")
        if "base-uri" not in csp:
            self._add("LOW", "CSP missing base-uri",
                      "Without base-uri, injected markup can add a "
                      "<base> tag and hijack all relative URLs on the "
                      "page. Add \"base-uri 'self'\".", check="WEB-001")
        if "frame-ancestors" not in csp:
            self._add("LOW", "CSP missing frame-ancestors",
                      "frame-ancestors is the modern clickjacking "
                      "control; without it you rely on X-Frame-Options "
                      "alone. Add \"frame-ancestors 'self'\" (or 'none').",
                      check="WEB-001")

    # WEB-002: cookie flag audit -------------------------------------------
    def _check_cookies(self, headers):
        cookies = []
        for value in self._header_values(headers, "set-cookie"):
            parts = [p.strip() for p in value.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name = parts[0].split("=", 1)[0].strip()
            attrs, flags = {}, set()
            for part in parts[1:]:
                if "=" in part:
                    k, v = part.split("=", 1)
                    attrs[k.strip().lower()] = v.strip()
                elif part:
                    flags.add(part.lower())
            secure = "secure" in flags
            httponly = "httponly" in flags
            samesite = attrs.get("samesite", "").lower()
            # Redaction rule: name + flags only, NEVER the cookie value.
            cookies.append({"name": name, "secure": secure,
                            "httponly": httponly,
                            "samesite": samesite or None})
            if self.use_tls and not secure:
                self._add("MEDIUM",
                          f"Cookie '{name}' missing Secure flag",
                          "On an HTTPS site a cookie without Secure can "
                          "still leak over a plain-HTTP request to the "
                          "same host. Add '; Secure' to the Set-Cookie "
                          "header.", check="WEB-002")
            if not httponly:
                self._add("MEDIUM",
                          f"Cookie '{name}' missing HttpOnly flag",
                          "Without HttpOnly, any XSS bug lets script "
                          "read this cookie (session theft). Add "
                          "'; HttpOnly' unless the cookie is meant to be "
                          "read by JavaScript.", check="WEB-002")
            if not samesite:
                self._add("LOW",
                          f"Cookie '{name}' has no SameSite attribute",
                          "Without SameSite the browser default applies "
                          "and CSRF protection is inconsistent. Set "
                          "SameSite=Lax (or Strict) explicitly.",
                          check="WEB-002")
            elif samesite == "none" and not secure:
                self._add("MEDIUM",
                          f"Cookie '{name}' uses SameSite=None without "
                          "Secure",
                          "Browsers reject SameSite=None cookies that "
                          "lack Secure, and the combination usually "
                          "signals a config mistake. Add '; Secure' or "
                          "use SameSite=Lax.", check="WEB-002")
            if name.startswith("__Host-"):
                if (not secure or attrs.get("path") != "/"
                        or "domain" in attrs):
                    self._add("MEDIUM",
                              f"Cookie '{name}' violates __Host- prefix "
                              "rules",
                              "The __Host- prefix requires Secure, "
                              "Path=/ and no Domain attribute; browsers "
                              "silently drop non-conforming cookies. "
                              "Fix the attributes or drop the prefix.",
                              check="WEB-002")
            elif name.startswith("__Secure-") and not secure:
                self._add("MEDIUM",
                          f"Cookie '{name}' violates __Secure- prefix "
                          "rules",
                          "The __Secure- prefix requires the Secure "
                          "attribute; browsers drop the cookie without "
                          "it. Add '; Secure' or drop the prefix.",
                          check="WEB-002")
        if cookies:
            self.info["cookies"] = cookies

    # WEB-011: clickjacking (XFO + frame-ancestors cross-check) ------------
    def _check_clickjacking(self, headers):
        if self._header_values(headers, "x-frame-options"):
            return
        if "frame-ancestors" in self.info.get("csp", {}):
            return
        self._add("MEDIUM",
                  "Page can be framed (no X-Frame-Options, no CSP "
                  "frame-ancestors)",
                  "Any site can embed this page in an iframe and run "
                  "clickjacking attacks against your users. Send "
                  "\"X-Frame-Options: SAMEORIGIN\" and/or add "
                  "\"frame-ancestors 'self'\" to the CSP.",
                  check="WEB-011")

    # WEB-012: Referrer-Policy ---------------------------------------------
    def _check_referrer_policy(self, headers):
        for value in self._header_values(headers, "referrer-policy"):
            if "unsafe-url" in value.lower():
                self._add("LOW",
                          "Referrer-Policy: unsafe-url leaks full URLs",
                          "unsafe-url sends the complete URL - including "
                          "paths and query strings that may carry tokens "
                          "or IDs - to every third-party link and "
                          "resource. Use strict-origin-when-cross-origin "
                          "instead.", check="WEB-012")

    # WEB-006: technology version disclosure ------------------------------
    @staticmethod
    def _identify(value):
        """(product, version) from a banner/header value, or (None, '')."""
        for pattern, product in VERSION_PATTERNS:
            m = re.search(pattern, value, re.IGNORECASE)
            if m:
                return product, (m.group(1) if m.groups() else "")
        m = re.match(r"\s*([A-Za-z][\w.\-]*)/([\d][\w.\-]*)", value)
        if m:
            return m.group(1), m.group(2)
        return None, ""

    def _check_disclosure(self, headers):
        disclosed = []
        for name in DISCLOSURE_HEADERS:
            for value in self._header_values(headers, name):
                product, version = self._identify(value)
                disclosed.append({"header": name, "value": value,
                                  "service": product, "version": version})
                if version:
                    self._add(
                        "INFO",
                        f"Technology version disclosure: {name}: {value}",
                        "The banner reveals exact software versions, which "
                        "helps an attacker match known vulnerabilities; "
                        "these also feed the --vuln-check stage. Suppress "
                        "version tokens (Apache: 'ServerTokens Prod', "
                        "nginx: 'server_tokens off', and remove "
                        "X-Powered-By).", check="WEB-006")
        self.info["disclosed_tech"] = disclosed

    # WEB-008: mixed content ------------------------------------------------
    def _check_mixed_content(self, body):
        text = body.decode("utf-8", "ignore")
        urls = re.findall(r"(?:src|href)\s*=\s*[\"'](http://[^\"']+)",
                          text, re.IGNORECASE)
        self.info["mixed_content_count"] = len(urls)
        if urls:
            sample = ", ".join(u[:80] for u in urls[:3])
            self._add("LOW",
                      f"Mixed content: {len(urls)} http:// resource(s) "
                      "referenced from an HTTPS page",
                      f"The page loads resources over plain HTTP "
                      f"(e.g. {sample}), which browsers block or warn "
                      "about; active content (scripts) over HTTP can be "
                      "tampered with in transit. Confirm in a browser "
                      "and switch every subresource to https://.",
                      check="WEB-008")

    # WEB-003: passive CORS misconfiguration --------------------------------
    def _check_cors(self):
        status, headers, _body = self._fetch(
            "/", extra_headers={"Origin": PROBE_ORIGIN})
        if status is None:
            return
        acao = [v.strip() for v in
                self._header_values(headers, "access-control-allow-origin")]
        acac = [v.strip().lower() for v in self._header_values(
            headers, "access-control-allow-credentials")]
        creds = "true" in acac
        self.info["cors"] = {"allow_origin": acao,
                             "allow_credentials": creds}
        for value in acao:
            if value == PROBE_ORIGIN:
                if creds:
                    self._add("HIGH",
                              "CORS reflects any Origin together with "
                              "credentials",
                              "The server echoes an arbitrary Origin in "
                              "Access-Control-Allow-Origin AND sends "
                              "Access-Control-Allow-Credentials: true, "
                              "so a malicious site can read a logged-in "
                              "victim's responses cross-origin. Reflect "
                              "only an allow-list of trusted origins.",
                              check="WEB-003")
                else:
                    self._add("MEDIUM",
                              "CORS reflects any Origin",
                              "The server echoes an arbitrary Origin in "
                              "Access-Control-Allow-Origin. Without "
                              "credentials the impact is smaller, but "
                              "per-user data may still leak. Reflect "
                              "only an allow-list of trusted origins.",
                              check="WEB-003")
            elif value == "*":
                if creds:
                    self._add("MEDIUM",
                              "CORS wildcard (*) combined with "
                              "credentials",
                              "Access-Control-Allow-Origin: * together "
                              "with Allow-Credentials: true is forbidden "
                              "by the CORS spec and signals a confused "
                              "config. Use an explicit origin allow-list "
                              "for credentialed endpoints.",
                              check="WEB-003")
                else:
                    self._add("LOW",
                              "CORS allows any origin (*)",
                              "Any website can read this endpoint's "
                              "responses cross-origin. Fine for truly "
                              "public data; restrict to known origins "
                              "if the responses are user-specific.",
                              check="WEB-003")

    # WEB-005: dangerous HTTP methods ---------------------------------------
    def _check_methods(self):
        status, headers, _body = self._fetch("/", method="OPTIONS")
        if status is None:
            return
        allow = ", ".join(self._header_values(headers, "allow"))
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        if methods:
            self.info["http_methods"] = sorted(methods)
        for method in ("TRACE", "TRACK"):
            if method not in methods:
                continue
            confirm_status, _h, _b = self._fetch("/", method=method)
            if confirm_status == 200:
                self._add("MEDIUM",
                          f"{method} method enabled (Cross-Site Tracing "
                          "risk)",
                          f"The server lists {method} in Allow and "
                          f"answered a {method} request with 200. TRACE "
                          "echoes request headers and historically let "
                          "attackers steal HttpOnly cookies via XST. "
                          "Disable TRACE and TRACK in the server config "
                          "(Apache: 'TraceEnable off').", check="WEB-005")
            else:
                self._add("INFO",
                          f"{method} listed in Allow but not confirmed",
                          f"OPTIONS advertises {method}, but a direct "
                          f"{method} request did not return 200, so it "
                          "is probably filtered upstream. Verify on the "
                          "origin server and remove it from Allow if "
                          "it is not needed.", check="WEB-005")

    # WEB-004: exposed sensitive files (fixed list, redacted) ---------------
    def _check_exposed_files(self):
        exposed = []
        for path in EXPOSED_PATHS:
            status, _headers, body = self._fetch(
                path, read_cap=EXPOSED_READ_CAP)
            if status != 200:
                continue
            if path == "/.git/HEAD":
                head = body.strip()
                if (head.startswith(b"ref:")
                        or re.fullmatch(rb"[0-9a-f]{40,64}", head)):
                    exposed.append(path)
                    self._add("HIGH",
                              "Exposed .git repository (/.git/HEAD)",
                              "The .git directory is web-accessible, so "
                              "the full source code and history can be "
                              "downloaded and mined for secrets. Block "
                              "access to /.git/ in the server config or "
                              "move the checkout out of the web root.",
                              check="WEB-004")
            elif path == "/.env":
                if re.search(rb"(?m)^[A-Za-z_][A-Za-z0-9_]*=[^\s]", body):
                    exposed.append(path)
                    self._add("HIGH",
                              "Exposed environment file (/.env)",
                              "A .env file with KEY=value assignments "
                              "is web-accessible; such files routinely "
                              "hold live credentials. Its contents were "
                              "NOT copied into this report - rotate any "
                              "secrets it contains, then block access "
                              "and move secrets out of the web root.",
                              check="WEB-004")
            elif path == "/server-status":
                exposed.append(path)
                self._add("MEDIUM",
                          "Apache server-status page exposed "
                          "(/server-status)",
                          "mod_status reveals active connections, "
                          "client IPs and requested URLs. Restrict "
                          "/server-status to localhost / admin IPs.",
                          check="WEB-004")
            elif path == "/.DS_Store":
                exposed.append(path)
                self._add("LOW",
                          ".DS_Store file exposed (/.DS_Store)",
                          "macOS .DS_Store files reveal directory and "
                          "file names that help map the site. Delete "
                          "them from the web root and block the "
                          "pattern in the server config.", check="WEB-004")
            elif path == "/robots.txt":
                exposed.append(path)
                self._add("INFO",
                          "robots.txt published (/robots.txt)",
                          "robots.txt is public by design, but check "
                          "that its Disallow lines do not advertise "
                          "sensitive paths (admin panels, backups) to "
                          "anyone who reads it. Contents are not copied "
                          "into this report - review the file manually.",
                          check="WEB-004")
        self.info["exposed_files"] = exposed

    # WEB-010: security.txt -------------------------------------------------
    def _check_security_txt(self):
        status, _headers, _body = self._fetch("/.well-known/security.txt")
        if status == 200:
            self.info["security_txt"] = True
            self._add("INFO", "security.txt present (good practice)",
                      "A /.well-known/security.txt file is published "
                      "(RFC 9116), giving security researchers a clear "
                      "contact for responsible disclosure. Keep its "
                      "Expires field current.", check="WEB-010")
        else:
            self.info["security_txt"] = False

    # WEB-007 + WEB-009: plain-HTTP endpoint --------------------------------
    def _check_redirect_and_hsts(self, status, headers):
        # WEB-009: HSTS over plain HTTP is ignored by browsers
        if self._header_values(headers, "strict-transport-security"):
            self.info["hsts_over_http"] = True
            self._add("INFO", "HSTS header sent over plain HTTP",
                      "Strict-Transport-Security only counts when received "
                      "over HTTPS; browsers ignore it on plain-HTTP "
                      "responses. Harmless, but it usually means the header "
                      "was copy-pasted onto the HTTP vhost - send it from "
                      "the HTTPS vhost instead, and redirect HTTP to "
                      "HTTPS.", check="WEB-009")

        # WEB-007: port 80 should redirect straight to HTTPS
        locations = self._header_values(headers, "location")
        if status in (301, 302, 303, 307, 308) and locations:
            loc = locations[0]
            if loc.lower().startswith("https://"):
                self.info["http_redirects_to_https"] = True
            elif loc.lower().startswith("http://"):
                self.info["http_redirects_to_https"] = False
                self._add("LOW", "HTTP redirect chain starts on plain HTTP",
                          f"The first redirect goes to {loc} (plain HTTP) "
                          "instead of HTTPS directly, leaving an extra "
                          "unencrypted hop that can be intercepted or "
                          "stripped. Redirect straight to the https:// URL.",
                          check="WEB-007")
            else:
                self.info["http_redirects_to_https"] = False
        elif status == 200:
            self.info["http_redirects_to_https"] = False
            self._add("MEDIUM", "HTTP does not redirect to HTTPS",
                      "The plain-HTTP endpoint serves content (200 OK) "
                      "instead of redirecting to HTTPS, so users who type "
                      "the plain address browse unencrypted - HSTS cannot "
                      "protect the very first visit. Add a permanent "
                      "redirect (301) from http:// to https://.",
                      check="WEB-007")
