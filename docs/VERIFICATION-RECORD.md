# FI Windows Split-Privilege Verification Record

Customer / Organization: _______________________________________________

File server: ___________________________________________________________

Windows Server release: ________________________________________________

Windows version/build: __________________________________________________

Administrator performing verification: _________________________________

Date: __________________________________________________________________

FI version/build or commit: _____________________________________________

Collector gMSA: _________________________________________________________

FIUSNReader gMSA: _______________________________________________________

Governed root used for verification: ____________________________________

## Script routing used

- [ ] Common scripts only
- [ ] Windows Server 2019 release-specific procedure used where documented
- [ ] Windows Server 2022 release-specific procedure used where documented

Release-specific README consulted:

_________________________________________________________________________

## Numbered verification results

| Test | Result | Notes |
|---|---|---|
| 01 File-server baseline | PASS / FAIL | |
| 02 Positive USN collection | PASS / FAIL | |
| 03 Local runtime authorization | PASS / FAIL | |
| 04 Helper failure and catch-up | PASS / FAIL | |
| 05 Remote pipe rejection | PASS / FAIL | |
| 06A-06D gMSA disable/recovery | PASS / FAIL / NOT RUN | |
| 07 Config / state / spool ACL boundary | PASS / FAIL | |
| 08 Collector exact service-token boundary | PASS / FAIL | |

## Release-specific characterization / acceptance

| Item | Result | Notes |
|---|---|---|
| Raw-volume characterization for this release | PASS / FAIL / NOT RUN | |
| Protected outside-scope containment | PASS / FAIL / NOT RUN | |
| Protected in-scope containment | PASS / FAIL / NOT RUN | |
| Windows Security Event Log collection/checkpoint | PASS / FAIL / NOT RUN | |
| Cold reboot/startup continuity | PASS / FAIL / NOT RUN | |
| Server 2022 protected-system containment fallback | PASS / FAIL / N/A | |

## Required security properties

### Service identities

- [ ] FICollector service account is not local Administrator.
- [ ] FIUSNReader service account is local Administrator on this host only.
- [ ] FICollector and FIUSNReader use separate per-host identities.
- [ ] FICollector managed-account setting is `TRUE` when a gMSA is used.
- [ ] FIUSNReader managed-account setting is `TRUE` when a gMSA is used.
- [ ] FICollector service SID type is `UNRESTRICTED`.

### Broker authorization

- [ ] The real FICollector service can perform positive broker work.
- [ ] Ordinary elevated local-administrator requests are denied unless the caller
      token carries the enabled `NT SERVICE\FICollector` service SID.
- [ ] Remote pipe use is denied.
- [ ] The helper independently restricts requests to configured scope.
- [ ] The broker exposes only the fixed bounded operation set.

### USN continuity

- [ ] USN checkpoint does not advance when FIUSNReader is unavailable.
- [ ] FICollector remains operational when FIUSNReader is unavailable.
- [ ] A configured collection cycle records helper unavailability explicitly.
- [ ] Recovery resumes from the previously accepted USN checkpoint.
- [ ] A change made during helper outage appears in catch-up output.

### Configuration, state, and spool

- [ ] FI config inspection completes without inaccessible objects.
- [ ] FI config contains no broad `BUILTIN\Users` access.
- [ ] FICollector has no direct FI config write/modify/ACL-administration
      permission.
- [ ] FI state ACL traversal completes without inaccessible objects.
- [ ] FI spool ACL traversal completes without inaccessible objects.
- [ ] FI state/spool contain no broad `BUILTIN\Users` entries.
- [ ] FICollector has required Modify access to FI state/spool without
      ChangePermissions or TakeOwnership.
- [ ] FIUSNReader has no FI-specific state/spool ACE.
- [ ] Checkpoint and durable spool ownership remain with FICollector.

### Privileged helper boundary

- [ ] FICollector cannot replace `fi-usn.exe` through its normal service token.
- [ ] FICollector cannot reconfigure FIUSNReader through its normal service token.
- [ ] FIUSNReader does not own parsing policy, hashing, spool writes, or
      checkpoint advancement.
- [ ] FIUSNReader containment returns only a bounded mechanical
      Contained / Outside / Unavailable result.

### Windows Server 2022 only

For Windows Server 2022 build `20348`:

- [ ] The release-specific build gate identifies `10.0.20348`.
- [ ] Protected-object containment does not require `SeRestorePrivilege`.
- [ ] The initial zero-access `OpenFileById` is attempted before the scoped
      `SeBackupPrivilege` fallback.
- [ ] `SeBackupPrivilege` is enabled only for the retry path.
- [ ] The previous privilege state is restored before the operation returns.
- [ ] A restore failure is treated as an operation failure.
- [ ] The protected outside-scope object is filtered.
- [ ] `scope_unresolved_object_count` remains zero in the acceptance cycle.
- [ ] No `FIUSNReader error 5` remains for the tested protected-object case.
- [ ] The corresponding `ConfiguredCollection` result is `Complete`.

For Windows Server 2016 or 2019, mark the Server 2022 items N/A.

## Windows Security source

- [ ] FICollector can read the local Security log under its restricted service
      identity with the approved Windows rights/group model.
- [ ] Security checkpoint advances only after accepted collection work.
- [ ] Required audit policy/SACL coverage is administrator-controlled and is not
      silently enabled by FI runtime.

## Final service state

- [ ] FICollector is Running.
- [ ] FIUSNReader is Running.
- [ ] FICollector StartType is the intended deployed value.
- [ ] FIUSNReader StartType is the intended deployed value.

## Notes / exceptions

_________________________________________________________________________

_________________________________________________________________________

_________________________________________________________________________

Administrator signature / change record reference:

_________________________________________________________________________
