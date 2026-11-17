# Cyber Crime - Case Omega

**GitHub repo name:** `cybercrime-3`

**Assignment 3 - Unit 3: Investigation of Cyber Crimes**
"Case Omega: Investigating a Ransomware Attack on a Healthcare Network" (Case No. OMG-2026-047)

> Everything in this repository is **synthetic and created for coursework**: the hospital, people, hosts, IP addresses,
> hashes, logs, wallet and ransom note are fictional. **No malware or ransomware code is included.** The ransomware is
> documented the way a real analyst reports it (static findings, sandbox behaviour, ransom note as text, indicators of
> compromise). See `docs/03-malware-analysis.md` for why.

## What happened (summary)

| Item | Finding |
|---|---|
| Victim | Sunrise Medical Centre (fictional hospital, Gurugram) |
| Attack | Human-operated, double-extortion ransomware: fake claim-form site, loader, 40 h of beaconing, credential theft, USB tool, RDP, 6.93 GiB exfiltrated, shadow copies deleted, two servers encrypted (`.omega`) |
| Dwell time | 40 h 33 m 38 s from first execution to encryption |
| Detection | By nurses noticing the EHR outage, 47 m 57 s after encryption began; isolation at 1 h 24 m |
| Threat level | Critical (4.2 of 5 on the rubric in `docs/03-malware-analysis.md`) |
| Evidence | Validated disk image (SHA-256 `806daab4...a228cc`), 7 log sources (1,314 events), USB drive, workstation, ransom note |

## Repository structure

```text
cybercrime-3/
├── README.md
├── requirements.txt
├── docs/
│   ├── 01-first-responder-sop-scene-documentation.md   # Sub-problem 1
│   ├── 02-evidence-collection-chain-of-custody.md      # Sub-problem 2
│   ├── 03-malware-analysis.md                          # Sub-problem 3
│   ├── 04-timeline-correlation.md                      # Sub-problem 4
│   └── tools-used.md                                   # tool summary and workflow
├── report/
│   ├── Case-Omega-Forensic-Report.docx                 # Sub-problem 5 (law-enforcement report)
│   └── Case-Omega-Forensic-Report.pdf
├── evidence/
│   ├── scene/              # scene sketch, evidence tag sheet, simulated photo placeholders
│   ├── acquisition/        # disk image, SHA-256 files, acquisition log, tamper test, image examination, volatile triage
│   ├── chain-of-custody/   # custody form, BSA s.63(4) certificate template, artefact hashes
│   ├── malware-analysis/   # static and dynamic reports, ransom note, IOC list and extractor output
│   ├── logs/               # 7 simulated log sources (auth, system, USB, browser, firewall, files, response notes)
│   └── timeline/           # generated timeline CSV, key events, correlation findings, charts
├── tools/
│   ├── acquire_image.sh            # dd + SHA-256 acquisition wrapper
│   ├── verify_image_hash.py        # re-verifies image hashes (also used in CI)
│   ├── generate_simulated_logs.py  # reproducible synthetic logs (fixed seed)
│   ├── generate_scene_docs.py      # scene sketch, tag sheet, placeholder photos
│   ├── ioc_extractor.py            # IOC extraction from analyst reports
│   └── timeline_builder.py         # normalisation, detection rules, correlation, charts
├── screenshots/                    # 4 screenshots of real tool runs
└── .github/workflows/
    ├── markdown-lint.yml           # CI: Markdown formatting
    └── directory-check.yml         # CI: repo structure, hash verification, script checks
```

## Execution guide

### Clone and set up

```bash
git clone https://github.com/aniktripathi/cybercrime-3.git
cd cybercrime-3
pip install -r requirements.txt
```

Python 3.8 or later. The acquisition script needs a Linux or WSL shell (`dd`, `sha256sum`). On Windows, use Git Bash for
the Python scripts and WSL for `tools/acquire_image.sh`.

### 1. Verify the evidence image (Part 2)

```bash
python3 tools/verify_image_hash.py evidence/acquisition
```

Expected: `[+] MATCH ... Summary: 1/1 image(s) verified.`

### 2. Re-run the acquisition on a copy (optional)

```bash
tools/acquire_image.sh <source_file_or_device> /tmp/test_image.dd /tmp/test_image.dd.sha256
```

### 3. Extract IOCs (Part 3)

```bash
python3 tools/ioc_extractor.py evidence/malware-analysis/static_analysis_report.txt \
    evidence/malware-analysis/dynamic_analysis_report.txt --compare evidence/malware-analysis/ioc_list.csv
```

### 4. Rebuild the timeline and charts (Part 4)

```bash
python3 tools/timeline_builder.py evidence/logs evidence/timeline
```

Writes `timeline_full.csv`, `timeline_key_events.md`, `correlation_findings.txt` and two PNG charts.

### 5. Regenerate the simulated data (optional)

```bash
python3 tools/generate_simulated_logs.py evidence/logs
python3 tools/generate_scene_docs.py evidence/scene
```

Output is deterministic (fixed seed), so the files match those in the repository.

### 6. Read the write-up

Read `docs/01` to `docs/04` in order, then `report/Case-Omega-Forensic-Report.docx` (or the PDF).

### 7. CI

Two GitHub Actions run on every push and pull request:

- `markdown-lint.yml` lints every `.md` file with `markdownlint-cli`.
- `directory-check.yml` checks the required structure and file counts, re-verifies the evidence image hash, and
  compiles the Python tools and checks the shell script syntax.

## Tools

Full table, with what was run and what is only referenced, in `docs/tools-used.md`. Screenshots of real runs are in
`screenshots/`:

- `01-acquisition-and-hash-validation.png`
- `02-tamper-detection-test.png`
- `03-ioc-extraction.png`
- `04-timeline-correlation.png`

## Simulation notes

- The disk image is an 8 MiB ext4 container, not a real NTFS server volume; Windows artefacts are represented by the CSV logs.
- No memory image was captured; this is listed as a gap.
- "Malware files" in this repository are analysis artefacts (reports, ransom note text, IOC list), not executables.
- Scene photographs are labelled placeholders; signatures and seal numbers are placeholders.
- Legal references (IT Act, IPC with BNS equivalents, BNSS, BSA, CERT-In Directions, DPDP) were checked against current
  sources, but section numbers should be re-verified against the bare Acts before any real use.

## Authorship declaration

I declare that the analysis, scripts, simulated evidence and report in this repository were prepared by me for
Assignment 3 (Unit 3: Investigation of Cyber Crimes), as an educational simulation. All evidence is synthetic and was
generated for this exercise; no real persons, organisations, devices or patient data are involved, and no working
malware is included.

**Name:** Anik Tripathi
**Roll No. / Student ID:** 2301420046
**Course:** B.Tech CSE (Data Science)
**Date:** 16-11-2026
**Signature:** Anik Tripathi

## Evaluation cross-reference

| Criterion (marks) | Where addressed |
|---|---|
| First responder SOP and scene documentation (1.0) | `docs/01-first-responder-sop-scene-documentation.md`, `evidence/scene/` |
| Evidence collection and chain of custody (2.0) | `docs/02-evidence-collection-chain-of-custody.md`, `evidence/acquisition/`, `evidence/chain-of-custody/` |
| Malware analysis and behaviour classification (2.0) | `docs/03-malware-analysis.md`, `evidence/malware-analysis/` |
| Timeline and data correlation (2.0) | `docs/04-timeline-correlation.md`, `evidence/logs/`, `evidence/timeline/` |
| Final report: depth, clarity, legal correctness (2.0) | `report/Case-Omega-Forensic-Report.docx` and `.pdf` |
| GitHub structure, documentation, CI compliance (1.0) | This README, `docs/tools-used.md`, `.github/workflows/` |
