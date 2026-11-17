#!/usr/bin/env python3
"""
ioc_extractor.py - extract Indicators of Compromise from analyst reports (Case Omega, Part 3)

Parses free-text malware-analysis reports and pulls out structured IOCs (hashes,
IPs, defanged domains, registry keys, file paths, mutexes, service names).
With --compare <ioc_list.csv> it also reports how many values of the curated IOC
list were independently rediscovered in the text (a consistency check).

This is a defensive reporting tool: it reads descriptions an analyst already wrote.
It does not run, build or reproduce any malware.

Usage:
    python3 tools/ioc_extractor.py report1.txt [report2.txt ...] [--compare ioc_list.csv]
"""
import csv
import re
import sys
from pathlib import Path

PATTERNS = [
    ("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.I)),
    ("md5", re.compile(r"\bMD5 \(dummy\)\s*:\s*([a-f0-9]{32})\b", re.I)),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("domain", re.compile(r"\b[a-z0-9-]+(?:\[\.\][a-z0-9-]+)+\b", re.I)),
    ("registry_key", re.compile(r"HK(?:LM|CU)\\[A-Za-z0-9_\\]+")),
    ("file_path", re.compile(r"[A-Z]:\\[A-Za-z0-9_.\\ ]+?\.(?:exe|txt|7z)\b")),
    ("mutex", re.compile(r"Global\\[A-Za-z0-9_]+")),
    ("service_name", re.compile(r"\bOmegaSvc\b")),
]


def private(ip):
    a = [int(x) for x in ip.split(".")]
    return a[0] == 10 or (a[0] == 192 and a[1] == 168) or (a[0] == 172 and 16 <= a[1] <= 31)


def extract(text, source):
    found = []
    for kind, rx in PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if rx.groups else m.group(0)
            if kind == "ipv4" and (private(val) or val.endswith(".0")):
                continue
            found.append((kind, val.strip(), source))
    return found


def main():
    args = sys.argv[1:]
    compare = None
    if "--compare" in args:
        i = args.index("--compare")
        compare = args[i + 1]
        args = args[:i] + args[i + 2:]
    if not args:
        print(__doc__)
        return 1
    seen, rows = set(), []
    for a in args:
        for kind, val, src in extract(Path(a).read_text(errors="ignore"), Path(a).name):
            if (kind, val.lower()) not in seen:
                seen.add((kind, val.lower()))
                rows.append((kind, val, src))
    w = csv.writer(sys.stdout, lineterminator="\n")
    w.writerow(["ioc_type", "value", "source"])
    w.writerows(rows)
    print(f"\n[+] Extracted {len(rows)} unique IOC(s) from {len(args)} report(s).", file=sys.stderr)

    if compare:
        curated = [r["value"] for r in csv.DictReader(open(compare))]
        extracted_vals = {v.lower() for _, v, _ in rows}
        hits = [c for c in curated if c.lower() in extracted_vals]
        print(f"[+] Cross-check vs {Path(compare).name}: {len(hits)}/{len(curated)} curated IOC values "
              f"independently found in the reports.", file=sys.stderr)
        missing = [c for c in curated if c.lower() not in extracted_vals]
        print(f"    Not in the text reports (come from log/scene evidence): {len(missing)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
