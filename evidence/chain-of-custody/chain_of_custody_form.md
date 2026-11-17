# Chain of Custody Record - Case OMG-2026-047 (Case Omega)

All names are role codes for a simulated case. "Signed (sim.)" stands in for a handwritten or digital signature.

| Field | Value |
|---|---|
| Case number | OMG-2026-047 |
| Incident | Ransomware attack on Sunrise Medical Centre (fictional) |
| Location of seizure | Level 2 IT and Admin Wing, Gurugram (fictional) |
| Lead first responder | FA-1 |
| Forensic analyst | FA-2 |
| Witness / scribe | W-1 |
| Lab custodian | LC-1 |
| Hospital representative | CISO (incident commander) |

## Exhibit EX-01 - Disk image of HOSP-FS01 D: volume

| Field | Detail |
|---|---|
| Source item | ET-01 HOSP-FS01 (file server), data volume D: (read-only LUN export) |
| Image file | `evidence/acquisition/HOSP-FS01_D_vol.dd` (8,388,608 bytes) |
| Hash algorithm | SHA-256 |
| Hash value | `806daab48eabf1e2fa0965c2297ca0cc4100a9b316be3cf56d27204e51a228cc` |
| Acquisition tool | `tools/acquire_image.sh` (dd, bs=4M, conv=noerror,sync) |
| Source hash equals image hash | Yes (validated 05:52 IST) |

| Date and time (IST) | Released by | Received by | Purpose | Hash re-verified | Seal intact | Signature |
|---|---|---|---|---|---|---|
| 14-Oct-2026 05:52 | FA-1 (creator) | FA-1, sealed evidence drive HDD-EV-01 | Initial acquisition, hash recorded | Source = image | Seal TE-30201 applied | Signed (sim.) |
| 14-Oct-2026 06:20 | FA-1 | LC-1 | Transport to forensic lab | Yes, matches | Yes | Signed (sim.) |
| 14-Oct-2026 07:10 | LC-1 | FA-2 | Analysis on a working copy (master untouched) | Yes, matches | Yes, reseal TE-30209 | Signed (sim.) |
| 14-Oct-2026 16:30 | FA-2 | LC-1 | Return to evidence locker; working copy destroyed and logged | Yes, matches | Yes | Signed (sim.) |

## Exhibit EX-02 - Unregistered USB flash drive (ET-06)

| Field | Detail |
|---|---|
| Description | Kingston DataTraveler 3.0 (dummy), serial 0019E06B1C2A9F31, VID 0951 / PID 1666 |
| Found | Inserted in front port of BILLING-WS-07 (photograph P4 taken before removal) |
| Seal | TE-30106 |
| Next step (not simulated) | Image through a hardware write blocker, hash, examine for `sysdiag.exe` and file-system timestamps |

| Date and time (IST) | Released by | Received by | Purpose | Seal intact | Signature |
|---|---|---|---|---|---|
| 14-Oct-2026 04:21 | Scene | FA-1 (witness W-1) | Seizure after in-place photograph | Bagged 04:40, TE-30106 | Signed (sim.) |
| 14-Oct-2026 06:20 | FA-1 | LC-1 | Transport to forensic lab | Yes | Signed (sim.) |
| 14-Oct-2026 07:30 | LC-1 | Evidence locker | Secure storage pending imaging | Yes | Signed (sim.) |

## Exhibit EX-03 - Billing workstation (ET-05)

| Field | Detail |
|---|---|
| Description | BILLING-WS-07, desktop PC (dummy), powered on and locked at seizure |
| Seal | TE-30105 |
| Handling note | Left powered and network-isolated until volatile data captured; then shut down by FA-1 and sealed |

| Date and time (IST) | Released by | Received by | Purpose | Seal intact | Signature |
|---|---|---|---|---|---|
| 14-Oct-2026 04:35 | Scene | FA-1 (witness W-1) | Seizure | TE-30105 applied | Signed (sim.) |
| 14-Oct-2026 06:20 | FA-1 | LC-1 | Transport to forensic lab | Yes | Signed (sim.) |
| 14-Oct-2026 07:30 | LC-1 | Evidence locker | Storage pending imaging | Yes | Signed (sim.) |

## Exhibit EX-04 - Exported logs (firewall, authentication, system, browser, USB, file activity) and response notes

| Field | Detail |
|---|---|
| Description | Seven CSV log exports under `evidence/logs/` |
| Export method | Exported by hospital network administrator under FA-1 supervision; hashed on export |
| Hash record | `evidence/chain-of-custody/artefact_hashes.sha256` |

| Date and time (IST) | Released by | Received by | Purpose | Hash recorded | Signature |
|---|---|---|---|---|---|
| 14-Oct-2026 05:30 | Hospital network administrator | FA-1 | Export of logs | Yes, at export | Signed (sim.) |
| 14-Oct-2026 06:20 | FA-1 | LC-1 | Transport to forensic lab | Yes, matches | Signed (sim.) |
| 14-Oct-2026 08:00 | LC-1 | FA-2 | Timeline analysis | Yes, matches | Signed (sim.) |

## Items imaged on site and left in hospital custody

ET-01, ET-02 and ET-03 (servers and backup appliance) were imaged or triaged on site. The hospital needs them to restore
services, so by written agreement the original drives are preserved untouched in a sealed state (seals TE-30101,
TE-30102, TE-30103) under the hospital CISO's custody, with a log of any access. ET-04 and ET-08 (network devices)
remain in service; their configuration and logs were exported and hashed (EX-04).

## Declaration

I confirm that the entries above are a complete and accurate record of the handling of the listed exhibits.

| Role | Name / code | Signature | Date |
|---|---|---|---|
| First responder | FA-1 | Signed (sim.) | 14-Oct-2026 |
| Witness | W-1 | Signed (sim.) | 14-Oct-2026 |
| Lab custodian | LC-1 | Signed (sim.) | 14-Oct-2026 |
