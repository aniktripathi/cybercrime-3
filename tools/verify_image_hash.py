#!/usr/bin/env python3
"""
verify_image_hash.py - re-verify acquired evidence images against recorded SHA-256 values.

Reads every *.sha256 file in the given directory (format: "<hash>  <filename>"),
re-hashes the named file in 1 MiB chunks, and reports MATCH / MISMATCH.
Exit code 0 only if every image matches - suitable for use in CI and at every
chain-of-custody transfer.

Usage:
    python3 tools/verify_image_hash.py evidence/acquisition
"""
import hashlib
import sys
from pathlib import Path


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    directory = Path(sys.argv[1] if len(sys.argv) > 1 else "evidence/acquisition")
    hash_files = sorted(directory.glob("*.sha256"))
    if not hash_files:
        print(f"[!] No .sha256 files found in {directory}")
        return 1
    failed = 0
    for hf in hash_files:
        expected, name = hf.read_text().split(maxsplit=1)
        target = directory / name.strip()
        if not target.exists():
            print(f"[!] MISSING   {target}")
            failed += 1
            continue
        actual = sha256_of(target)
        if actual == expected:
            print(f"[+] MATCH     {target.name}  {actual}")
        else:
            print(f"[!] MISMATCH  {target.name}\n    expected {expected}\n    actual   {actual}")
            failed += 1
    print(f"\nSummary: {len(hash_files) - failed}/{len(hash_files)} image(s) verified.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
