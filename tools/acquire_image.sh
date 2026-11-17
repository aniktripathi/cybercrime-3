#!/usr/bin/env bash
# acquire_image.sh - forensic acquisition wrapper (dd + SHA-256 validation)
# Usage: tools/acquire_image.sh <source_device_or_file> <dest_image> <hash_file>
# Records the source hash BEFORE imaging, images with dd (bit-for-bit,
# continue-on-error), re-hashes the image, compares, then sets read-only.
set -euo pipefail
SRC="$1"; DST="$2"; HASHFILE="$3"

echo "[*] Hashing source (pre-acquisition)..."
SRC_HASH=$(sha256sum "$SRC" | awk '{print $1}')
echo "    source  SHA-256: $SRC_HASH"

echo "[*] Imaging with dd (bs=4M, conv=noerror,sync)..."
dd if="$SRC" of="$DST" bs=4M conv=noerror,sync status=progress 2>&1

echo "[*] Hashing acquired image (post-acquisition)..."
DST_HASH=$(sha256sum "$DST" | awk '{print $1}')
echo "    image   SHA-256: $DST_HASH"

if [ "$SRC_HASH" = "$DST_HASH" ]; then
  echo "[+] HASH VALIDATION PASSED - image is a bit-for-bit match of the source."
else
  echo "[!] HASH VALIDATION FAILED - do not rely on this image." >&2
  exit 1
fi

echo "$DST_HASH  $(basename "$DST")" > "$HASHFILE"
chmod 444 "$DST"
echo "[+] Hash recorded in $HASHFILE; image set read-only."
