# C220 runtime operations and disposable acceptance

These scripts are current C220-specific operational or read-only verification helpers, extracted from the retired `fi-backlog-recover` experimental command tree. The backlog CLI and clone-benchmark tooling are **not** an FI runtime component.

| Script | Purpose |
|---|---|
| `fi_c1_c220_operational_install.sh` | Explicit host-pinned stage/start helper (operator-controlled; **not** a fresh-install recipe) |
| `fi_c1_freebsd_postgres18_native.sh` | Disposable GitHub FreeBSD VM / PG18 acceptance test; hard refuses physical C220 |
| `fi_c1_c220_telemetry_peer_auth.sh` | Telemetry PostgreSQL peer-auth inspection |
| `fi_c1_c220_telemetry_acceptance.sh` | Telemetry validation helper |
| `fi_c1_c220_telemetry_storage_audit.sh` | Telemetry spool / mounts audit |
| `fi_c1_c220_receiver_sor_readiness_audit.sh` | Receiver → SoR read-only readiness audit |
| `fi_c1_c220_receiver_live_runtime_audit.sh` | Receiver runtime inventory audit |

The `operational_install` helper defaults to the original C220 working-clone path for compatibility. To use a different working clone, set `FI_C220_REPO=/absolute/path` explicitly. **Never run any live deployment mode based only on these docs**; the installed versions/hashes and non-secret service configuration must be checked first.

[Current backend and diagrams](../../../../docs/architecture/FI-C220-CURRENT-BACKEND.md) · [As-built inventory](../../../../docs/deployment/C220-FREEBSD-AS-BUILT-20261127.md).
