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
| 07 Config ACL | PASS / FAIL | |

## Required security properties

- [ ] FICollector service account is not local Administrator.
- [ ] FIUSNReader service account is local Administrator.
- [ ] FICollector service SID type is UNRESTRICTED.
- [ ] Ordinary elevated local administrator request is denied.
- [ ] Remote pipe use is denied.
- [ ] USN checkpoint does not advance when FIUSNReader is unavailable.
- [ ] FICollector remains operational when FIUSNReader is unavailable.
- [ ] USN catch-up recovers changes made while FIUSNReader was unavailable.
- [ ] FI config has no broad BUILTIN\Users access.
- [ ] Neither FI service account can write FI configuration.

Administrator signature / change record reference:

________________________________________________________
