#!/usr/bin/env python3
"""Validate and normalize CyberRakshak's offline CVE snapshot.

The snapshot (``vuln/cve_snapshot.json``) is CURATED BY HAND and ships
with the tool; CyberRakshak itself never touches the network. This
script is the maintainer-side companion: it validates the snapshot's
schema, and with ``--write`` it sorts entries/ranges and bumps
``snapshot_version``. It does NOT scrape NVD or any other source.

Maintainer refresh workflow (deliberately manual — accuracy first):

  1. Review new disclosures on NVD / CISA KEV / vendor advisories.
  2. Add an entry ONLY if the CVE id and its exact affected version
     range are confirmed from the vendor advisory or NVD. When unsure
     about a range, narrow it or leave the CVE out — a small accurate
     snapshot beats a large sloppy one.
  3. Edit ``vuln/cve_snapshot.json`` and set ``snapshot_date`` to today.
  4. Run ``python3 tools/build_cve_snapshot.py --write`` to validate,
     sort and bump the version.
  5. Run ``python3 tests/test_vuln_db.py`` and commit JSON + script.

Usage:
  python3 tools/build_cve_snapshot.py [--path FILE] [--write]
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from vuln.vuln_db import CVE_ID_RE, SEVERITIES, _version_key  # noqa: E402

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "vuln", "cve_snapshot.json")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RANGE_KEYS = {"exact", "min_vuln", "max_vuln", "severity", "cve", "title",
              "guidance"}


def _bound_key(rng):
    """Sort key for a range: by its lowest affected version, then highest."""
    lo = rng.get("exact") or rng.get("min_vuln") or ""
    if isinstance(lo, list):
        lo = lo[0] if lo else ""
    hi = rng.get("max_vuln") or rng.get("exact") or ""
    if isinstance(hi, list):
        hi = hi[-1] if hi else ""
    return (_version_key(lo), _version_key(hi))


def validate(data):
    """Return a list of schema/accuracy error strings (empty = valid)."""
    errors = []
    if not isinstance(data, dict):
        return ["snapshot root is not a JSON object"]
    date = data.get("snapshot_date")
    if not isinstance(date, str) or not DATE_RE.match(date):
        errors.append("snapshot_date missing or not YYYY-MM-DD")
    if not isinstance(data.get("snapshot_version"), int):
        errors.append("snapshot_version missing or not an integer")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("entries missing or empty")
        return errors
    for i, entry in enumerate(entries):
        where = f"entries[{i}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: not an object")
            continue
        product = entry.get("product")
        if not isinstance(product, str) or not product.strip():
            errors.append(f"{where}: product missing/empty")
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list) or \
                not all(isinstance(a, str) for a in aliases):
            errors.append(f"{where}: aliases must be a list of strings")
        ranges = entry.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            errors.append(f"{where}: ranges missing/empty")
            continue
        for j, rng in enumerate(ranges):
            rwhere = f"{where}.ranges[{j}]"
            if not isinstance(rng, dict):
                errors.append(f"{rwhere}: not an object")
                continue
            unknown = set(rng) - RANGE_KEYS
            if unknown:
                errors.append(f"{rwhere}: unknown keys {sorted(unknown)}")
            if not any(k in rng for k in ("exact", "min_vuln", "max_vuln")):
                errors.append(f"{rwhere}: no version constraint "
                              "(need exact, min_vuln and/or max_vuln)")
            exact = rng.get("exact")
            if exact is not None:
                vals = exact if isinstance(exact, list) else [exact]
                if not vals or not all(isinstance(x, str) and _version_key(x)
                                       for x in vals):
                    errors.append(f"{rwhere}: exact must be a version string "
                                  "or list of version strings")
            for bound in ("min_vuln", "max_vuln"):
                if bound in rng and not _version_key(str(rng[bound])):
                    errors.append(f"{rwhere}: {bound} is not a parseable version")
            if "min_vuln" in rng and "max_vuln" in rng and \
                    not _version_key(str(rng["min_vuln"])) < \
                    _version_key(str(rng["max_vuln"])):
                errors.append(f"{rwhere}: min_vuln must be < max_vuln")
            if rng.get("severity") not in SEVERITIES:
                errors.append(f"{rwhere}: severity must be one of {SEVERITIES}")
            cve = rng.get("cve")
            if not isinstance(cve, str) or not CVE_ID_RE.match(cve):
                errors.append(f"{rwhere}: cve missing or not a CVE id")
            for field in ("title", "guidance"):
                if not isinstance(rng.get(field), str) or \
                        not rng[field].strip():
                    errors.append(f"{rwhere}: {field} missing/empty")
    return errors


def sort_snapshot(data):
    """Sort entries by product and ranges by affected-version span."""
    data["entries"] = sorted(data["entries"],
                             key=lambda e: (e.get("product") or "").lower())
    for entry in data["entries"]:
        entry["ranges"] = sorted(entry.get("ranges") or [], key=_bound_key)
    return data


def summarize(data):
    ranges = sum(len(e.get("ranges") or []) for e in data["entries"])
    cves = {r["cve"] for e in data["entries"] for r in e.get("ranges") or []}
    return (f"{len(data['entries'])} products, {ranges} ranges, "
            f"{len(cves)} distinct CVEs, snapshot_date="
            f"{data.get('snapshot_date')}, version="
            f"{data.get('snapshot_version')}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--path", default=DEFAULT_PATH,
                    help="snapshot JSON path (default: vuln/cve_snapshot.json)")
    ap.add_argument("--write", action="store_true",
                    help="sort ranges, bump snapshot_version, rewrite file")
    args = ap.parse_args()

    try:
        with open(args.path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[FAIL] cannot load {args.path}: {e}")
        return 1

    errors = validate(data)
    if errors:
        print(f"[FAIL] {len(errors)} problem(s) in {args.path}:")
        for err in errors:
            print(f"  - {err}")
        return 1
    print(f"[OK] schema valid: {summarize(data)}")

    if args.write:
        sort_snapshot(data)
        data["snapshot_version"] = int(data.get("snapshot_version", 0)) + 1
        with open(args.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"[OK] rewritten sorted, snapshot_version -> "
              f"{data['snapshot_version']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
