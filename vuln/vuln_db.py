"""Vulnerability hints database — DEFENSIVE ONLY.

Matches detected service versions against known-vulnerable releases and
returns upgrade guidance. Contains NO exploits, NO payloads, NO attack
techniques — only "this version is old, upgrade to X" style hints.

v0.3 (Phase 4): matching is snapshot-first. A curated, fully offline CVE
snapshot (``vuln/cve_snapshot.json``) maps product + version ranges to
verified CVE IDs with severity and one-line defensive remediation. If the
snapshot file is missing or corrupt, the checker falls back to the
built-in v0.2 ``VULN_DB`` list below (backward compatible). The snapshot
is NEVER fetched or updated at runtime — refreshing it is a manual
maintainer task (see ``tools/build_cve_snapshot.py``).

Version handling: versions are compared with a token key that
understands dotted numbers plus the suffix styles real banners use —
OpenSSH portable releases (``8.5p1``) and OpenSSL letter releases
(``1.0.1f``) — after stripping distro/build suffixes
(``2.4.49-1ubuntu2`` -> ``2.4.49``).
"""

import json
import os
import re

SNAPSHOT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "cve_snapshot.json")

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

def _parse_version(v):
    """Legacy numeric view: '1.2.3p1' -> (1, 2, 3, 1). Kept for compat."""
    parts = re.findall(r"\d+", v or "")
    return tuple(int(p) for p in parts[:4]) or (0,)


def _older_than(detected, fixed):
    """True if detected version is older than the fixed version (numeric)."""
    return _parse_version(detected) < _parse_version(fixed)


def _normalize_version(v):
    """Strip distro/build decoration from a banner version string.

    '2.4.49-1ubuntu2' -> '2.4.49'; '4.92-5' -> '4.92'; ' 9.7p1 ' -> '9.7p1'.
    Meaningful suffixes are KEPT: OpenSSH 'p1' and OpenSSL letters are part
    of the version itself, not decoration.
    """
    s = (v or "").strip()
    if not s:
        return ""
    s = s.split()[0]                    # drop anything after whitespace
    s = s.split("-", 1)[0]             # distro suffix: -1ubuntu2, -5, ...
    s = s.split("+", 1)[0]             # build suffix: +dfsg, ...
    if s[:1] in ("v", "V") and len(s) > 1 and s[1].isdigit():
        s = s[1:]
    return s


def _version_key(v):
    """Comparable key for a version string.

    Tokenizes into numbers and letter-runs so that '8.5p1' < '8.5p2',
    '1.0.1f' < '1.0.1g' and '1.0.1' < '1.0.1g' all hold. Each token is a
    (kind, number, text) triple so ints and strings never compare directly.
    """
    s = _normalize_version(v).lower()
    key = []
    for tok in re.findall(r"\d+|[a-z]+", s):
        if tok.isdigit():
            key.append((0, int(tok), ""))
        else:
            key.append((1, 0, tok))
    return tuple(key)


def _version_has_digits(v):
    return bool(re.search(r"\d", v or ""))


# ---------------------------------------------------------------------------
# Snapshot loading + range matching
# ---------------------------------------------------------------------------

def load_snapshot(path=SNAPSHOT_PATH):
    """Load the offline CVE snapshot. Returns dict, or None if unusable."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return None
    return data


def _range_matches(key, rng):
    """True if a version key falls in a snapshot range.

    Range shapes (at least one bound required):
      {"exact": "2.4.49"} or {"exact": ["1.3.5", ...]}  — single versions
      {"min_vuln": "8.5p1", "max_vuln": "9.8p1"}        — min inclusive,
                                                          max exclusive
                                                          (first fixed ver)
    """
    exact = rng.get("exact")
    if exact is not None:
        if isinstance(exact, str):
            exact = [exact]
        return any(key == _version_key(e) for e in exact)
    lo = rng.get("min_vuln")
    hi = rng.get("max_vuln")
    if lo is None and hi is None:
        return False
    if lo is not None and key < _version_key(lo):
        return False
    if hi is not None and not key < _version_key(hi):
        return False
    return True


def _product_match(detected, entry):
    """'exact' if the detected name equals the product/alias, 'substring'
    if one contains the other (banner variants), else None."""
    d = (detected or "").strip().lower()
    if not d:
        return None
    names = [entry.get("product", "")] + list(entry.get("aliases") or [])
    names = [n.strip().lower() for n in names if n and n.strip()]
    for n in names:
        if d == n:
            return "exact"
    for n in names:
        if n in d or d in n:
            return "substring"
    return None


# ---------------------------------------------------------------------------
# Built-in v0.2 fallback list (used only when the snapshot is unavailable)
# ---------------------------------------------------------------------------

# (product match, vulnerable condition, severity, guidance)
# 'max_vuln' = versions BELOW this are considered vulnerable.
VULN_DB = [
    {
        "product": "OpenSSH",
        "max_vuln": "7.4",
        "severity": "HIGH",
        "guidance": "OpenSSH before 7.4 has known auth-bypass issues. "
                    "Upgrade to OpenSSH 9.x and disable password auth (use keys).",
    },
    {
        "product": "OpenSSH",
        "max_vuln": "8.0",
        "severity": "MEDIUM",
        "guidance": "OpenSSH before 8.0 lacks newer key-exchange hardening. "
                    "Upgrade to OpenSSH 9.x.",
    },
    {
        "product": "Apache",
        "max_vuln": "2.4.50",
        "severity": "HIGH",
        "guidance": "Apache httpd before 2.4.50 is vulnerable to path traversal "
                    "(CVE-2021-41773). Upgrade to the latest 2.4.x immediately.",
    },
    {
        "product": "Apache",
        "max_vuln": "2.4.60",
        "severity": "MEDIUM",
        "guidance": "Apache httpd is outdated. Upgrade to the latest stable 2.4.x.",
    },
    {
        "product": "nginx",
        "max_vuln": "1.20.0",
        "severity": "MEDIUM",
        "guidance": "nginx is outdated. Upgrade to the latest stable/mainline release.",
    },
    {
        "product": "vsftpd",
        "max_vuln": "3.0.0",
        "severity": "MEDIUM",
        "guidance": "vsftpd is outdated. Upgrade to 3.0.3+ and consider SFTP instead of FTP.",
    },
    {
        "product": "ProFTPD",
        "max_vuln": "1.3.7",
        "severity": "HIGH",
        "guidance": "ProFTPD before 1.3.7c has known remote issues. Upgrade to 1.3.8+.",
    },
    {
        "product": "MySQL",
        "max_vuln": "5.7.0",
        "severity": "MEDIUM",
        "guidance": "MySQL 5.6 and older are end-of-life. Upgrade to MySQL 8.0+.",
    },
    {
        "product": "MariaDB",
        "max_vuln": "10.5.0",
        "severity": "LOW",
        "guidance": "MariaDB is getting old. Plan an upgrade to a supported release.",
    },
    {
        "product": "IIS",
        "max_vuln": "8.0",
        "severity": "MEDIUM",
        "guidance": "IIS 7.5 and older are end-of-life. Migrate to a supported IIS version.",
    },
]


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

class VulnChecker:
    """Match detected services against the CVE snapshot (or fallback list)."""

    def __init__(self, snapshot_path=SNAPSHOT_PATH):
        self.snapshot = load_snapshot(snapshot_path)
        self.using_snapshot = self.snapshot is not None
        self.snapshot_date = (self.snapshot.get("snapshot_date")
                              if self.snapshot else None)

    def check(self, service_info):
        """service_info: dict with 'service'/'product' and 'version' keys.

        Returns a list of hint dicts (may be empty). Snapshot-mode hints
        carry the v0.2 keys (port, product, detected_version, severity,
        guidance) plus cve, title, confidence and snapshot_date."""
        product = service_info.get("service", "") or ""
        version = service_info.get("version", "") or ""
        port = service_info.get("port", "")
        if not version:
            return []
        if self.using_snapshot:
            try:
                return self._check_snapshot(product, version, port)
            except Exception:
                pass  # fail soft: a malformed entry must not kill the scan
        return self._check_legacy(product, version, port)

    def check_all(self, services):
        """Check a list of service dicts. Returns flat list of hints."""
        hints = []
        for svc in services:
            hints.extend(self.check(svc))
        return hints

    # -- snapshot mode ------------------------------------------------------

    def _check_snapshot(self, product, version, port):
        hints = []
        if not _version_has_digits(version):
            # No digits at all -> there is no version to match responsibly.
            return hints
        key = _version_key(version)
        was_normalized = _normalize_version(version) != (version or "").strip()
        for entry in self.snapshot.get("entries") or []:
            kind = _product_match(product, entry)
            if not kind:
                continue
            for rng in entry.get("ranges") or []:
                if not _range_matches(key, rng):
                    continue
                if was_normalized:
                    confidence = "low"     # version had junk stripped off
                elif kind == "exact":
                    confidence = "high"    # exact product + clean version
                else:
                    confidence = "medium"  # substring product match
                hints.append({
                    "port": port,
                    "product": product,
                    "detected_version": version,
                    "severity": rng["severity"],
                    "guidance": rng["guidance"],
                    "cve": rng["cve"],
                    "title": rng["title"],
                    "confidence": confidence,
                    "snapshot_date": self.snapshot_date,
                })
        return hints

    # -- legacy fallback mode (v0.2 behaviour, unchanged) -------------------

    def _check_legacy(self, product, version, port):
        hints = []
        for entry in VULN_DB:
            if entry["product"].lower() in product.lower():
                if _older_than(version, entry["max_vuln"]):
                    hints.append({
                        "port": port,
                        "product": product,
                        "detected_version": version,
                        "severity": entry["severity"],
                        "guidance": entry["guidance"],
                    })
                    break  # one hint per product is enough
        return hints
