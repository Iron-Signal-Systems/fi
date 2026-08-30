# FI USN Split-Privilege Verification Record

Customer / Organization: ______________________________

File server: __________________________________________

Administrator performing verification: _________________

Date: __________________________________________________

FI version/build: ______________________________________

## Results

| Test | Result | Notes |
|---|---|---|
| 01 Baseline | PASS / FAIL | |
| 02 Positive USN collection | PASS / FAIL | |
| 03 Local administrator rejection | PASS / FAIL | |
| 04 Helper failure and catch-up | PASS / FAIL | |
| 05 Remote pipe rejection | PASS / FAIL | |
| 06A-06D gMSA disable/recovery (optional) | PASS / FAIL / NOT RUN | |
| 07 Config ACL boundary | PASS / FAIL | |

## Required security properties

- [ ] FICollector service account is not local Administrator.
- [ ] FIUSNReader service account is local Administrator on this host only.
- [ ] FICollector service SID type is UNRESTRICTED.
- [ ] Ordinary elevated local administrator pipe requests are denied unless the
      caller token also carries the enabled `NT SERVICE\FICollector` service SID.
- [ ] Remote pipe use is denied.
- [ ] USN checkpoint does not advance when FIUSNReader is unavailable.
- [ ] FICollector remains operational when FIUSNReader is unavailable.
- [ ] USN catch-up recovers changes made while FIUSNReader was unavailable.
- [ ] FI config has no broad `BUILTIN\Users` access.
- [ ] FICollector has no direct write/modify/administrative FI config permission.
- [ ] FIUSNReader has only an explicit read entry for FI config; its effective
      local-Administrator authority is treated as the Windows administrative
      trust boundary, not as a config-ACL sandbox.
- [ ] FIUSNReader runtime code does not own FI config writes, checkpoints, spool
      writes, or collector state.

Administrator signature / change record reference:

________________________________________________________
