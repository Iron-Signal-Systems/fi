# FI M6.1 — SCM service-SID bootstrap fix

Problem observed on ISS-FS-22A, Oct 22, 2026: configured `-run` CLI baseline failed immediately with `FIUSNReader error 5: FICollector service SID is required`. This is intentional broker authorization. A process launched by PowerShell (even elevated or using the gMSA account) does not have the FICollector service SID.

Fix: one-time `FI_USN_PIPELINE_LAB_BOOTSTRAP=1` in **FICollector's service process environment**, with `FI_USN_PIPELINE_LAB` unset. Service mode performs one configured-root baseline/catch-up, verifies the original FI USN checkpoint is continuous, calls the existing M6 durable-queue initializer under the service SID, writes an `USNPipelineLabBootstrap` result to the isolated state `service-runtime.jsonl`, and exits. FISender remains stopped. No service broker ACL weakening, no manual checkpoint write, no F: migration.

Required environment (SCM service registry Environment REG_MULTI_SZ): `FI_STATE_DIR=<isolated state>`, `FI_SPOOL_DIR=<isolated spool>`, and the bootstrap opt-in. These **must** agree with fixed `fi.conf` storage settings. Initialization requires exactly one configured canary root, and fails closed if an M6 queue already exists. The original `FI_USN_PIPELINE_LAB` must be absent.

After service stops successfully and the G: queue contains `legacy-anchor.json`, the operator may remove bootstrap opt-in and set `FI_USN_PIPELINE_LAB=1` for the next service start. Do not enable both flags. Retain the original FICollector binary and fi.conf rollback backups; do not delete any lab queue to roll back.

The first M6 `-run` attempt left an unrelated WindowsSecurityCoverage spool pair and a failed baseline operation. This fix preserves both; it does not treat them as a completed baseline. No automatic cleanup is performed.

Validation: compile and test with native Windows Go 1.27.2 (`go test -count=1 ./cmd/fi ./internal/usncapture ./internal/windows/usn`, then `go test -count=1 ./...`). Source package has not been natively tested in this environment.
