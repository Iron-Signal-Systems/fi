# FI Windows Server 2019 — M22K4N Installation, File History, and Reboot Acceptance

**Test date:** 2026-10-12 (all event times below UTC unless labeled otherwise)

**Result:** **PASS — bounded functional/end-to-end and reboot-persistence acceptance**

**Release classification:** development lab, pre-alpha; **not** Gate 6, complete Server 2019 release acceptance, or proof of sustained-load/outage recovery.

## 1. Test identity and limits

| Field | Tested value |
|---|---|
| Source | `ISS-FS-2019.iss.local` (`source.id=iss-fs-2019.iss.local`) |
| Windows | Windows Server 2019 Standard Evaluation, build `17763` |
| Domain / LDAP discovery | `ISS` / `DC16.iss.local` |
| Installer package | `m22k4n-gmsa-netlogon-rebind-20261012` |
| Installer invocation | `fi-install.exe -config <approved preserved fi.conf> -pki-choice enroll` (interactive approvals) |
| Release validation | Detached manifest signature, payload SHA-256, installer/payload Authenticode, release-trust signer authorization reported `PASS` |
| Receiver | `fi-receiver.iss.local`, `192.168.1.219:8443` (mTLS activation `PASS`, TLS 1.3) |
| PostgreSQL | FreeBSD `fi-backend-b` / jail `fi-sor-db` / database `fi` / authoritative `fi.*` System-of-Record schema |
| Governed root | `C:\FI-Governed-Test` |
| Run ID | `FI-TEST-20261012-101110` (Windows local clock); recorded activity at `17:11:11 UTC` |
| Test subdirectory | `C:\FI-Governed-Test\FI-TEST-20261012-101110` |
| Surviving object path | `C:\FI-Governed-Test\FI-TEST-20261012-101110\Archive\renamed.txt` |
| Collection cadence | Security `1m`; USN `10m`; generation interval `10m`; sender poll `5s` |

This record concerns a single installed source and one controlled file workload. The ingest results came from PostgreSQL read-only queries; no production query-plane/Published Projection is claimed (Phase 5 projection remains separately gated).

### Signed installer / runtime verification

The interactive M22K4N installer reported `APPROVAL 1 RESULT: PASS`, receiver mTLS activation `PASS`, `APPROVAL 2 RESULT: PASS`, followed by a final authoritative discovery result `PASS WITH WARNINGS` and `FI INSTALLER RESULT: PASS`. The final desired-state plan reported no further local changes; all five installed runtime executable hashes matched the signed manifest. The warnings are explicitly tracked in section 6; the discovery result must not be described as warning-free.

The gMSA registrations and local Windows name-to-SID resolution were consistent with the Active Directory authoritative values after the first controlled Windows reboot and during the successful installer discovery:

| Service account | Expected AD RID | Local RID | Match |
|---|---:|---:|---|
| `ISS\gFI-FS2019$` (Collector and Sender) | 1172 | 1172 | Yes |
| `ISS\gFI-CRL-FS2019$` | 1173 | 1173 | Yes |
| `ISS\gFI-USN-FS2019$` | 1174 | 1174 | Yes |
| `ISS\gFI-OBJ-FS2019$` | 1175 | 1175 | Yes |

Domain SID prefix in this lab: `S-1-5-21-2096275705-3984399647-1579629934`.

## 2. Reproducible test workload

An operator executed the following PowerShell operations beneath the governed root, under a uniquely named subdirectory. The workload is intentionally small; it is not a scale benchmark.

1. Create test directory and `Archive` subdirectory.
2. Create `sample.txt`, then append additional content.
3. Rename `sample.txt` to `renamed.txt`.
4. Move `renamed.txt` into `Archive`.
5. Copy it to `copy.txt` at the test directory root.
6. Delete `copy.txt`, leaving `Archive\renamed.txt` intact.

The workload completed at approximately `17:11:11 UTC`. The later surviving file was independently checked on the Windows host, including after the second reboot.

## 3. Accepted transfer and relational ingest

| Observation | Actual result |
|---|---|
| Workload generation | `20261012T171950.364607700Z-181735f086990e45` |
| PostgreSQL accepted at | `2026-10-12 17:20:27 UTC` |
| Journal terminal outcome | `Accepted / AuthoritativeRecord` |
| Records seen / committed | **50 / 50** |
| Time from workload activity to ingest | approximately **9m 16s** (bounded by configured collection and generation cadence) |
| Matching USN change rows | **21** (2 test-dir, 11 surviving file, 8 deleted copy) |
| Matching Windows Security events | **28** |
| Operator events | **26**, `ISS\jwood.admin` through `powershell.exe` |
| FI Collector events | **2**, `ISS\gFI-FS2019$` through `fi-collector.exe` |

`Incomplete / AttemptStarted` in `fi.ingest_journal` is the journal's nonterminal start event for the same attempt; the terminal event is `Accepted` with 50/50 committed. Do not count this start record as an ingest failure.

## 4. File identity and historical reconstruction

The PostgreSQL object IDs are database-local surrogate identifiers; **file identity** is the volume plus NTFS FRN and sequence number, not the filename.

| Object | PostgreSQL object ID | FRN | Sequence | Recorded parent | USN change count | Final reobservation |
|---|---:|---:|---:|---:|---:|---|
| Test directory | 592 | 252163 | 13 | — | 2 | `Observed` |
| `Archive` directory | 600 | 253351 | 5 | — | 2 | `Observed` |
| `sample.txt` → `renamed.txt` → moved into `Archive` | **608** | **253352** | **10** | **592 → 600** | **11** | `Observed`, metadata + hashes |
| `copy.txt` (created and deleted) | **634** | **253353** | **6** | 592 | **8** | `Unavailable`, history retained |

For object 608, USN reason names included `FileCreate`, `DataExtend`, `RenameOldName`, `RenameNewName`, and `Close`. The initial rename retained parent 592; the move into `Archive` changed the parent to 600 **without changing FRN or sequence**. Object 634 was a separate NTFS identity and ended with `Close, FileDelete` at USN `1050435984`.

The deleted copy's follow-up collection was recorded as:

- `status=Unavailable`; `scope_basis=RecordedParentContained`;
- `reason_code=ObjectUnavailableAfterUSN`;
- `error_text=ntfs Open/OpenFileById: The parameter is incorrect.`;
- `has_ntfs_observation=false`; `has_content_hashes=false`.

This represents the observed inability to reopen the deleted file, while preserving its USN records. The precise Win32 error classification remains an engineering follow-up: a deleted-object test alone does not establish that all `ERROR_INVALID_PARAMETER` responses are deletions.

### 4.1 Full recorded object 608 observation

| Field | PostgreSQL value |
|---|---|
| Source record | **4001** (`USNObjectObservation`) |
| Governed root ID | `4` |
| Scope ID | `root-14ae450549e27257428a4aa0d422924d` |
| Volume GUID | `\\?\Volume{8223fa09-0000-0000-0000-602200000000}\` |
| Volume serial | `7671354858756139089` |
| Volume/object identity method | `windows-file-id-info-ntfs/0.1` |
| Observation time | `2026-10-12 17:11:49.104841 UTC` |
| Status / collection | `Complete` / `NTFSFileID` / `DirectWindowsNTFS` |
| Containment method | `windows-final-volume-path-containment/0.1` |
| Requested/resolved path | Both point to the final volume-qualified `...\Archive\renamed.txt` location |
| Subject kind | `File` |
| Parent state / object | `Present` / `600` |
| Logical / allocated size | **49 / 56 bytes** |
| File creation | `2026-10-12 17:11:11.196148 UTC` |
| Last write / NTFS change / last access | `2026-10-12 17:11:11.211777 UTC` |
| Raw attributes | `32` (`0x20`, Archive) |
| Link count | `1` |
| Hash state / bytes | `Present` / `49` |
| MD5 | `d152d446c9fefae1f8fcad0251b5b155` |
| SHA-1 | `14f2178a13d535041b43d09cb8d186506261ac4c` |
| SHA-256 | `e271bbbead08fb44ab23cacfd2b8efd902e6bdafca64a3234c6611313b752df6` |
| First 16 bytes | `46492054455354202d2046494c452043` (`FI TEST - FILE C`) |
| Reparse-point state | `NotPresent` |
| Stream inventory | One unnamed/default `$DATA` stream, 49 logical / 56 allocated bytes |
| Collection warnings | None |

The post-reboot Windows `Get-FileHash -Algorithm SHA256` for this 49-byte file returned `E271BBBEAD08FB44AB23CACFD2B8EFD902E6BDAFCA64A3234C6611313B752DF6`, **byte-for-byte matching** the recorded FI SHA-256. FI stores digests/prefix observations, not the entire file content for recovery.

### 4.2 Security descriptor / auditing (object 608)

- Recorded owner: `BUILTIN\Administrators` (`S-1-5-32-544`); primary group: domain Admins SID ending `-512`.
- Three inherited `AccessAllowed` DACL ACEs: `SYSTEM` (`0x1f01ff`, Full Control), `Administrators` (`0x1f01ff`, Full Control), and `BUILTIN\Users` (`0x1200a9`, Read/Execute).
- Two `SystemAudit` SACL ACEs, SID `Everyone` (`S-1-1-0`), flags `208` (success and failure audit plus inheritance); masks `852310` (`0x0d0156`) and `1` (`0x1`).
- Original raw security descriptors and ACE bytes are represented in the typed FI relational projections.
- Windows Security activity contained event IDs `4656`, `4663`, and `4670` for paths within the test workload, with operator and FI-service attribution as noted above.

## 5. Reboot survival and renewed ingest

After the first boot cleared a **stale local name-to-SID lookup** for `ISS\gFI-FS2019$` (old RID `1164`; authoritative current RID `1172`), the installer converged. The earlier Stage 3H attempted Netlogon rebind had failed because a successful removal call was followed by `NetIsServiceAccount` still reporting present. The observations support a stale local SID lookup cache; they do **not** prove that the attempted Netlogon removal repaired it. Treat this sequence as a regression scenario.

After the installation and file workload, the operator performed a **separate host reboot**:

| Post-install reboot check | Actual result |
|---|---|
| Windows boot | `2026-10-12 17:28:13 UTC` (10:28:13 host local time) |
| `FICollector` | `Running`, `Auto`, `ISS\gFI-FS2019$` |
| `FIUSNReader` | `Running`, `Auto`, `ISS\gFI-USN-FS2019$` |
| `FIObjReader` | `Running`, `Auto`, `ISS\gFI-OBJ-FS2019$` |
| `FICRLRefresher` | `Running`, `Auto`, `ISS\gFI-CRL-FS2019$` |
| `FISender` | `Running`, `Auto`, `ISS\gFI-FS2019$` |
| Post-reboot generation | `20261012T172827.518061300Z-d2db9b44af3ae92e` |
| Post-reboot ingest accepted | `2026-10-12 17:29:12.250108 UTC` |
| Journal terminal outcome | `Accepted`, `records_seen=10`, `records_committed=10` |
| Surviving file | Present, 49 bytes, unchanged SHA-256 |

Thus all five FI services restarted automatically under the required accounts, and another generation traversed the sender/receiver/authoritative relational ingest path after reboot.

## 6. Open findings / non-claims

1. **Installer stale-SID path:** on an earlier run, `ISS\gFI-FS2019$` resolved locally to retired RID `1164` while LDAP reported RID `1172`. Stage 3H failed to repair it via Netlogon remove/rebind. A reboot resolved the observed mismatch. Improve the installer to fail closed with an actionable stale-LSA-SID/restart-required diagnosis, rather than equating Netlogon registration presence with correct SID resolution. Characterize supported remediation; do not silently reboot or recreate gMSAs.
2. **Directory ACL warning:** final installer discovery reported inherited `BUILTIN\Users` write access on `C:\ProgramData\FI`, mask `0x00000116`. Investigate the parent-directory DACL and security implications separately. Do not turn the `PASS WITH WARNINGS` discovery into an unqualified clean pass.
3. **Deleted-object API error:** `copy.txt` reobservation had `ObjectUnavailableAfterUSN`, with `OpenFileById: The parameter is incorrect`. Add isolated regression cases for deleted FRNs, invalid handles/parameters, and known live objects; ensure errors are not silently misclassified.
4. **Acceptance limits:** no controlled receiver outage/backlog recovery, 2019 sustained-load/performance acceptance, rollback/reinstall validation from this exact package, 2022/2025 mutation acceptance, or Phase 5 Published Projection acceptance in this run. Source-code commit-to-signed-package traceability/reproducible build was not independently provided in the lab output and should be recorded before a release freeze.

## 7. Repeatability / review

The paired SQL `docs/acceptance/sql/WINDOWS-SERVER-2019-M22K4N-2026-10-12.sql` is a **read-only post-hoc check** for these immutable recorded identities. The PowerShell script `docs/acceptance/powershell/WINDOWS-SERVER-2019-POST-REBOOT-CHECK.ps1` is a read-only host-state check; it must be run on the intended Server 2019 lab host. Neither script executes a file workload, modifies deployment state, or grants approval to install/reconcile FI.

The immutable original log transcripts were reviewed during this acceptance session. This document is a curated, commit-friendly summary of those observed outputs, not a claim that raw transcripts or binary installer artifacts were added to the repository. Retain raw artifacts under an approved lab retention location if they are needed for independent audit or reproducibility.

**Disposition:** bounded test **PASS**. Close only this controlled FI Windows Server 2019 functional, historical-reconstruction and reboot-persistence test. Keep broader release gates open.
