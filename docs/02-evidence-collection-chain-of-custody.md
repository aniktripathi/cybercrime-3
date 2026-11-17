# Case Omega - Part 2: Evidence Collection and Chain of Custody

## 2.1 What was collected, and why

| Exhibit | Item | Collection method | Why it matters |
|---|---|---|---|
| EX-01 | Disk image of the `HOSP-FS01` D: volume (clinical shares) | Read-only acquisition with `dd`, SHA-256 validated | Holds encrypted files, ransom notes and attacker artefacts |
| EX-02 | Unregistered USB drive (ET-06) | Photographed in place, bagged, sealed | Possible delivery route for attacker tools (inserted 18:52 after hours) |
| EX-03 | Billing workstation `BILLING-WS-07` (ET-05) | Seized and sealed | Probable first-compromise host |
| EX-04 | Seven log exports and response notes | Exported by hospital admin under supervision, hashed | Basis of the timeline in Part 4 |
| - | `HOSP-FS01` volatile triage | Trusted read-only toolkit | Processes and connections before any shutdown |

## 2.2 Acquisition decision

A hospital file server cannot simply be switched off and carried away: the hospital must restore services quickly. The
plan was therefore:

1. Keep the server powered on and network-isolated (done at 03:41 by the hospital's engineer).
2. Capture volatile data first (`evidence/acquisition/volatile_triage_HOSP-FS01.txt`, simulated output).
3. Image the data volume through a **read-only path**. In a real case this is a hardware write blocker on a pulled drive,
   or a read-only snapshot or LUN export for a storage array, using FTK Imager or `dd`.
4. Leave the original drives sealed and in the hospital's custody after imaging.

## 2.3 Acquisition procedure and real run

The simulated source is an 8 MiB container (an ext4 volume built to look like the server's D: share), because a real
NTFS volume and FTK Imager are not available in this environment. The imaging, hashing and verification steps below are
genuine: they were run with `dd`, `sha256sum` and the scripts in `tools/`.

```bash
tools/acquire_image.sh <source> evidence/acquisition/HOSP-FS01_D_vol.dd \
    evidence/acquisition/HOSP-FS01_D_vol.dd.sha256
```

What the script does:

1. Hashes the **source** with SHA-256 (before touching it).
2. Images with `dd if=<source> of=<image> bs=4M conv=noerror,sync` (continue on read errors, pad with zeros so offsets
   stay aligned).
3. Hashes the **image**.
4. Compares the two hashes and stops with an error if they differ.
5. Writes the hash to a `.sha256` file and makes the image read-only.

Actual output (from `evidence/acquisition/acquisition_log.txt`):

```text
[*] Hashing source (pre-acquisition)...
    source  SHA-256: 806daab48eabf1e2fa0965c2297ca0cc4100a9b316be3cf56d27204e51a228cc
[*] Imaging with dd (bs=4M, conv=noerror,sync)...
2+0 records in
2+0 records out
8388608 bytes (8.4 MB, 8.0 MiB) copied, 0.00409662 s, 2.0 GB/s
[*] Hashing acquired image (post-acquisition)...
    image   SHA-256: 806daab48eabf1e2fa0965c2297ca0cc4100a9b316be3cf56d27204e51a228cc
[+] HASH VALIDATION PASSED - image is a bit-for-bit match of the source.
[+] Hash recorded in evidence/acquisition/HOSP-FS01_D_vol.dd.sha256; image set read-only.
```

## 2.4 Hash validation process

The image hash is checked every time the evidence changes hands, and in the repository's CI pipeline:

```bash
python3 tools/verify_image_hash.py evidence/acquisition
```

```text
[+] MATCH     HOSP-FS01_D_vol.dd  806daab48eabf1e2fa0965c2297ca0cc4100a9b316be3cf56d27204e51a228cc

Summary: 1/1 image(s) verified.
```

To show that the check really detects tampering, a copy of the image was altered by a single byte and re-hashed
(`evidence/acquisition/tamper_detection_test.txt`). The original image was not touched.

| Version | SHA-256 |
|---|---|
| Original image | `806daab48eabf1e2fa0965c2297ca0cc4100a9b316be3cf56d27204e51a228cc` |
| Copy with one byte changed | `aa30416afb459f5268090643b7362375db41a4bc66773c50822f3e743c5a6882` |

Any difference at all gives a completely different hash, so a match at each transfer is strong evidence that the image
is unchanged since acquisition.

## 2.5 What the image shows

Read-only examination with `debugfs` (`evidence/acquisition/image_examination.txt`) shows, on the D: volume:

- Encrypted files named `record_NNNNN.pdf.omega` in the Billing, Radiology and Admin shares. The first bytes of each
  are the marker `OMEGAENC1` followed by data that cannot be read.
- A ransom note `README_OMEGA.txt` in every share directory, with a modification time that converts from the image's UTC
  display to 02:17 IST, matching the log record of the first note at 02:17:41.
- Placeholders for the staging archives (`stage_NNNN.7z`) and the renamed archiver (`arch.exe`) created on 13 October
  between 19:30 and 20:00 IST.
- A quarantine note for the ransomware service image `omegasvc.exe` (the binary itself is deliberately not included).
- An RDP session cache entry for a connection from `10.20.8.17` first seen at 19:28:44 on 13 October.

## 2.6 Hash record for the other artefacts

All log exports and key analysis files are hashed in `evidence/chain-of-custody/artefact_hashes.sha256`. The hash is
taken at export time and re-checked on every handover, as for the disk image.

## 2.7 Chain of custody

The full form is in `evidence/chain-of-custody/chain_of_custody_form.md`. In summary:

| Exhibit | Handovers recorded | Hash re-verified at each | Seals |
|---|---|---|---|
| EX-01 disk image | 4 (creator, lab custodian, analyst, locker) | Yes | TE-30201, TE-30209 |
| EX-02 USB drive | 3 | Not applicable until imaged | TE-30106 |
| EX-03 workstation | 3 | Not applicable until imaged | TE-30105 |
| EX-04 log exports | 3 | Yes | Hash log |

Servers ET-01, ET-02 and ET-03 stay in the hospital's custody, sealed, under a written agreement that records every
access.

## 2.8 Admissibility: certificate under BSA section 63

Since 1 July 2024 the Bharatiya Sakshya Adhiniyam, 2023 (BSA) governs electronic evidence. Section 63(4) requires a
certificate, in two parts (person in charge of the device and an expert), that includes the hash value of the record.
Recent Supreme Court guidance (Pune Bar Association v. Union of India, 2026, as summarised by commentators) also
confirms that a qualified cyber-forensics expert can sign the expert part. A working template with the EX-01 hash filled
in is at `evidence/chain-of-custody/bsa63_certificate_template.md`. The official Schedule should be checked before any
real filing.

## 2.9 Limitations of this simulation

| Limitation | Effect |
|---|---|
| Image is an 8 MiB ext4 container, not an NTFS server volume | Timestamps and metadata differ from a real Windows image; Windows artefacts (registry, MFT, event logs) are represented by the CSV logs instead |
| No memory dump was produced | Real cases should capture RAM; this is listed as a gap |
| Volatile triage output is simulated | Format follows real tools, content is fictional |
| Signatures and seal numbers are placeholders | Real forms need handwritten or digital signatures |

---

*Next: Part 3 - Malware application analysis.*
