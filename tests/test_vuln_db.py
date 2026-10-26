#!/usr/bin/env python3
"""CyberRakshak vuln_db tests (v0.3 Phase 4) — offline CVE snapshot.

Covers: snapshot load + schema sanity (via tools/build_cve_snapshot.py's
validator), exact-version hits, range hits, patched-version no-hits,
lower-bound no-hits, unknown products, malformed banners (no crash),
alias matching, confidence levels, and the legacy fallback used when the
snapshot file is missing/corrupt.

Run: python3 tests/test_vuln_db.py
"""

import importlib.util
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vuln.vuln_db import (CVE_ID_RE, SNAPSHOT_PATH, SEVERITIES, VulnChecker,
                          _normalize_version, _version_key, load_snapshot)

PASSED, FAILED = [], []


def check(name, cond, detail=""):
    if cond:
        PASSED.append(name)
        print(f"  [PASS] {name}")
    else:
        FAILED.append(name)
        print(f"  [FAIL] {name} {detail}")


def cves(hints):
    return [h.get("cve") for h in hints]


def load_validator():
    path = os.path.join(os.path.dirname(__file__), "..",
                        "tools", "build_cve_snapshot.py")
    spec = importlib.util.spec_from_file_location("build_cve_snapshot", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------- snapshot file + schema ----------

def test_snapshot_loads():
    snap = load_snapshot()
    check("snapshot_loads", snap is not None)
    check("snapshot_has_date",
          bool(snap) and re.match(r"^\d{4}-\d{2}-\d{2}$",
                                  snap.get("snapshot_date", "")) is not None,
          f"got {snap and snap.get('snapshot_date')}")
    check("snapshot_has_entries",
          bool(snap) and len(snap.get("entries", [])) >= 8,
          f"got {snap and len(snap.get('entries', []))}")
    c = VulnChecker()
    check("checker_uses_snapshot", c.using_snapshot is True)
    check("checker_snapshot_date", c.snapshot_date == snap["snapshot_date"])


def test_snapshot_schema():
    validator = load_validator()
    with open(SNAPSHOT_PATH, encoding="utf-8") as f:
        data = json.load(f)
    errors = validator.validate(data)
    check("schema_validator_clean", errors == [], f"errors={errors}")
    # every entry/range carries the fields a hint needs
    ok = True
    for entry in data["entries"]:
        if not entry.get("product") or not entry.get("ranges"):
            ok = False
        for rng in entry["ranges"]:
            if not CVE_ID_RE.match(rng.get("cve", "")):
                ok = False
            if rng.get("severity") not in SEVERITIES:
                ok = False
            if not (rng.get("guidance") or "").strip():
                ok = False
            if not any(k in rng for k in ("exact", "min_vuln", "max_vuln")):
                ok = False
    check("schema_every_range_complete", ok)
    all_cves = {r["cve"] for e in data["entries"] for r in e["ranges"]}
    check("schema_distinct_cves", len(all_cves) >= 10, f"got {sorted(all_cves)}")


# ---------- matching behaviour ----------

def test_exact_version_hits():
    c = VulnChecker()
    h = c.check({"port": 80, "service": "Apache", "version": "2.4.49"})
    check("exact_apache_2449", "CVE-2021-41773" in cves(h), f"got {h}")
    h = c.check({"port": 21, "service": "vsftpd", "version": "2.3.4"})
    check("exact_vsftpd_234",
          len(h) == 1 and h[0]["cve"] == "CVE-2011-2523" and
          h[0]["severity"] == "CRITICAL", f"got {h}")
    h = c.check({"port": 21, "service": "ProFTPD", "version": "1.3.5"})
    check("exact_proftpd_135", "CVE-2015-3306" in cves(h), f"got {h}")
    h = c.check({"port": 80, "service": "IIS", "version": "6.0"})
    check("exact_iis_60", "CVE-2017-7269" in cves(h), f"got {h}")
    # 2.4.50 is the incomplete-fix release: 42013 yes, 41773 no
    h = c.check({"port": 80, "service": "Apache", "version": "2.4.50"})
    check("exact_apache_2450_only_42013",
          "CVE-2021-42013" in cves(h) and "CVE-2021-41773" not in cves(h),
          f"got {h}")


def test_range_hits():
    c = VulnChecker()
    h = c.check({"port": 22, "service": "OpenSSH", "version": "9.7p1"})
    check("range_regresshion",
          len(h) == 1 and h[0]["cve"] == "CVE-2024-6387" and
          h[0]["severity"] == "CRITICAL", f"got {h}")
    h = c.check({"port": 22, "service": "OpenSSH", "version": "8.5p1"})
    check("range_regresshion_lower_edge", "CVE-2024-6387" in cves(h),
          f"got {h}")
    h = c.check({"port": 25, "service": "Exim", "version": "4.91"})
    check("range_exim_wizard", "CVE-2019-10149" in cves(h), f"got {h}")
    h = c.check({"port": 445, "service": "Samba", "version": "4.5.4"})
    check("range_sambacry_454", "CVE-2017-7494" in cves(h), f"got {h}")
    h = c.check({"port": 445, "service": "Samba", "version": "4.6.3"})
    check("range_sambacry_463", "CVE-2017-7494" in cves(h), f"got {h}")
    h = c.check({"port": 443, "service": "OpenSSL", "version": "1.0.1f"})
    check("range_heartbleed",
          len(h) == 1 and h[0]["cve"] == "CVE-2014-0160", f"got {h}")
    h = c.check({"port": 22, "service": "OpenSSH", "version": "7.2"})
    check("range_userenum_only",
          cves(h) == ["CVE-2018-15473"], f"got {h}")


def test_patched_no_hits():
    c = VulnChecker()
    cases = [
        ({"port": 22, "service": "OpenSSH", "version": "9.8p1"}, "patched_ssh_98p1"),
        ({"port": 22, "service": "OpenSSH", "version": "9.9p1"}, "patched_ssh_99p1"),
        ({"port": 80, "service": "Apache", "version": "2.4.51"}, "patched_apache_2451"),
        ({"port": 80, "service": "Apache", "version": "2.4.62"}, "patched_apache_2462"),
        ({"port": 443, "service": "OpenSSL", "version": "1.0.1g"}, "patched_openssl_101g"),
        ({"port": 443, "service": "OpenSSL", "version": "3.0.13"}, "patched_openssl_3x"),
        ({"port": 25, "service": "Exim", "version": "4.92"}, "patched_exim_492"),
        ({"port": 21, "service": "vsftpd", "version": "2.3.5"}, "patched_vsftpd_235"),
        ({"port": 445, "service": "Samba", "version": "4.5.10"}, "patched_samba_4510"),
        ({"port": 445, "service": "Samba", "version": "4.4.14"}, "patched_samba_4414"),
        ({"port": 80, "service": "IIS", "version": "10.0"}, "patched_iis_10"),
    ]
    for svc, name in cases:
        h = c.check(svc)
        check(name, h == [], f"got {h}")


def test_lower_bound_no_hit():
    c = VulnChecker()
    # 8.4p1 predates the regreSSHion window (starts at 8.5p1) and is past
    # the user-enumeration range -> completely clean.
    h = c.check({"port": 22, "service": "OpenSSH", "version": "8.4p1"})
    check("lower_bound_ssh_84p1_clean", h == [], f"got {h}")
    # Exim 4.86 predates the WIZard window (starts at 4.87)
    h = c.check({"port": 25, "service": "Exim", "version": "4.86"})
    check("lower_bound_exim_486_clean", h == [], f"got {h}")


def test_unknown_and_malformed():
    c = VulnChecker()
    h = c.check({"port": 9999, "service": "SomeRandomServer", "version": "1.0"})
    check("unknown_product_no_hit", h == [], f"got {h}")
    bad_inputs = [
        {"port": 80, "service": "Apache", "version": ""},
        {"port": 80, "service": "Apache", "version": "abc"},
        {"port": 80, "service": "Apache", "version": "!!!"},
        {"port": 80, "service": "Apache"},                    # no version key
        {"port": 80, "version": "2.4.49"},                   # no service key
        {"service": "Apache", "version": "2.4.49"},          # no port key
        {},                                                  # nothing at all
        {"port": 80, "service": "Apache", "version": "2.4"},
    ]
    ok = True
    for svc in bad_inputs:
        try:
            res = c.check(svc)
            if not isinstance(res, list):
                ok = False
        except Exception:
            ok = False
    check("malformed_no_crash", ok)
    h = c.check({"port": 80, "service": "Apache", "version": "abc"})
    check("malformed_version_no_hit", h == [], f"got {h}")


def test_aliases():
    c = VulnChecker()
    h = c.check({"port": 80, "service": "httpd", "version": "2.4.49"})
    check("alias_httpd", "CVE-2021-41773" in cves(h), f"got {h}")
    h = c.check({"port": 80, "service": "Apache httpd", "version": "2.4.50"})
    check("alias_apache_httpd", "CVE-2021-42013" in cves(h), f"got {h}")
    h = c.check({"port": 80, "service": "Microsoft-IIS", "version": "6.0"})
    check("alias_microsoft_iis", "CVE-2017-7269" in cves(h), f"got {h}")
    h = c.check({"port": 445, "service": "smbd", "version": "4.5.4"})
    check("alias_smbd", "CVE-2017-7494" in cves(h), f"got {h}")


def test_confidence():
    c = VulnChecker()
    h = c.check({"port": 22, "service": "OpenSSH", "version": "9.7p1"})
    check("confidence_high_exact_clean",
          h and h[0]["confidence"] == "high", f"got {h}")
    h = c.check({"port": 22, "service": "OpenSSH server", "version": "7.2"})
    check("confidence_medium_substring",
          h and h[0]["confidence"] == "medium", f"got {h}")
    h = c.check({"port": 80, "service": "Apache",
                 "version": "2.4.49-1ubuntu2"})
    check("confidence_low_normalized",
          any(x["cve"] == "CVE-2021-41773" and x["confidence"] == "low"
              for x in h), f"got {h}")
    h = c.check({"port": 22, "service": "OpenSSH", "version": "9.7p1"})
    check("hint_carries_snapshot_date",
          h and h[0].get("snapshot_date") == c.snapshot_date, f"got {h}")
    check("hint_shape_backward_compatible",
          h and all(k in h[0] for k in
                    ("port", "product", "detected_version", "severity",
                     "guidance", "cve", "title", "confidence")),
          f"got {h}")


def test_version_normalization():
    check("normalize_distro_suffix",
          _normalize_version("2.4.49-1ubuntu2") == "2.4.49")
    check("normalize_keeps_portable_p",
          _normalize_version("8.9p1") == "8.9p1")
    check("normalize_keeps_openssl_letter",
          _normalize_version("1.0.1f") == "1.0.1f")
    check("key_openssh_order",
          _version_key("8.5p1") < _version_key("9.7p1") <
          _version_key("9.8p1"))
    check("key_openssl_letter_order",
          _version_key("1.0.1") < _version_key("1.0.1f") <
          _version_key("1.0.1g") < _version_key("1.0.2"))
    check("key_distro_equals_clean",
          _version_key("2.4.49-1ubuntu2") == _version_key("2.4.49"))


def test_fallback():
    missing = VulnChecker(snapshot_path="/nonexistent/cve_snapshot.json")
    check("fallback_flag_missing", missing.using_snapshot is False)
    h = missing.check({"port": 22, "service": "OpenSSH", "version": "7.2"})
    check("fallback_legacy_behaviour",
          len(h) == 1 and h[0]["severity"] == "HIGH" and
          "cve" not in h[0], f"got {h}")
    tmp = tempfile.mkdtemp()
    bad = os.path.join(tmp, "bad.json")
    with open(bad, "w") as f:
        f.write("{ this is not json")
    corrupt = VulnChecker(snapshot_path=bad)
    check("fallback_flag_corrupt", corrupt.using_snapshot is False)
    h = corrupt.check({"port": 22, "service": "OpenSSH", "version": "9.3"})
    check("fallback_corrupt_no_crash", h == [], f"got {h}")


def test_check_all():
    c = VulnChecker()
    hints = c.check_all([
        {"port": 22, "service": "OpenSSH", "version": "9.7p1"},
        {"port": 80, "service": "Apache", "version": "2.4.49"},
        {"port": 443, "service": "nginx", "version": "1.25.1"},
    ])
    got = sorted(cves(hints))
    check("check_all_flat",
          got == ["CVE-2021-41773", "CVE-2024-6387"], f"got {hints}")


def main():
    print("=" * 50)
    print("  CyberRakshak vuln_db tests (v0.3 Phase 4, localhost only)")
    print("=" * 50)
    for fn in [test_snapshot_loads, test_snapshot_schema,
               test_exact_version_hits, test_range_hits,
               test_patched_no_hits, test_lower_bound_no_hit,
               test_unknown_and_malformed, test_aliases, test_confidence,
               test_version_normalization, test_fallback, test_check_all]:
        print(f"\n* {fn.__name__}")
        try:
            fn()
        except Exception as e:
            FAILED.append(fn.__name__)
            print(f"  [ERROR] {fn.__name__}: {e}")
    print()
    print("=" * 50)
    print(f"  PASSED: {len(PASSED)}   FAILED: {len(FAILED)}")
    print("=" * 50)
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
