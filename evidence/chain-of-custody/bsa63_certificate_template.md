# Certificate for Electronic Records - Working Template (BSA 2023, Section 63(4))

Under the Bharatiya Sakshya Adhiniyam, 2023 (in force from 1 July 2024), an electronic record produced in court needs a
certificate. The certificate has two parts, one signed by the person in charge of the device or system and one by an
expert, and it must state the **hash value** of the record and the hashing algorithm used.

This is a working template that follows that two-part structure. The official Schedule to the Act is the authority:
check the exact current form against it before filing. Entries below are simulated.

## Part A - person in charge of the computer or communication device

| Item | Entry |
|---|---|
| Name and designation | CISO, Sunrise Medical Centre (fictional) |
| Electronic record | Disk image of HOSP-FS01 D: volume, file `HOSP-FS01_D_vol.dd` |
| Device and how the record was produced | Read-only export of the server data LUN, acquired with dd on 14-Oct-2026 |
| Statement | The device was in regular use for hospital operations; the record was produced from it as described |
| Hash algorithm | SHA-256 |
| Hash value | `806daab48eabf1e2fa0965c2297ca0cc4100a9b316be3cf56d27204e51a228cc` |
| Signature and date | Signed (sim.) |

## Part B - expert

| Item | Entry |
|---|---|
| Name and qualification | FA-2, digital forensic analyst |
| Statement | I examined the record and the acquisition logs; the hash of the image equals the hash of the source taken before imaging |
| Hash algorithm | SHA-256 |
| Hash value | `806daab48eabf1e2fa0965c2297ca0cc4100a9b316be3cf56d27204e51a228cc` |
| Tools used | `tools/acquire_image.sh`, `tools/verify_image_hash.py` |
| Signature and date | Signed (sim.) |
