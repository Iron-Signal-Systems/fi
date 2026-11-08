# Windows FI Volume-First — Fresh-Install Only

**Date:** 2026-11-08  
**Branch:** `dev/windows-volume-first-20261108`  
**Development machine:** `adminbox`  
**Acceptance status:** Read-only clean-host check implemented; **native v2 installation NOT implemented or accepted**.

## Engineering decision

The volume-first Windows implementation is a **replacement for the legacy source architecture**, not a product upgrade. We are still in development. When it is installed for acceptance, the test/source Windows machine starts without FI.

There is **no in-place update, repair, v1.1-to-v2 conversion, service adoption, config reconciliation, USN checkpoint migration, reuse of existing spool custody, or replacement of files in an occupied FI installation**. If a development machine has an older FI build, disposition and any preservation/removal are a separate, deliberate operator action **before** the future new installer is run. The new installer stops on any prior local FI footprint; it never deletes a local installation to make the host eligible.

An already established compatible **shared** AD or PKI trust prerequisite is not automatically an installed FI source. Compatibility and reuse of external trust require the normal explicit PKI approval checks. That does not authorize reusing existing local FI state.

## Read-only verification command now in the development branch

```powershell
.\fi-install.exe -check-clean-install
```

The branch's native installer returns a JSON report:

- `version`: `fi-windows-v2-fresh-preflight/1`
- `mode`: `FreshInstallOnly`
- `clean` and `install_blocked`
- `findings`: all seven fixed local FI locations/SCM names and their `Absent`, `Present` or `Unknown` status, with a diagnostic on a blocking/uncertain finding.

SCM services: `FICollector`, `FIUSNReader`, `FIObjReader`, `FICRLRefresher`, `FISender`.

FI-owned paths: `C:\Program Files\FI` and `C:\ProgramData\FI`. These encompass the legacy binary directory and FI data/config/state/spool tree under the known installed layout. A directory, file, symlink or reparse point is present. Missing service SCM rights or inaccessible filesystem entries are **Unknown**, not proof of absence.

Any `Present` or `Unknown` blocks, with a nonzero process exit. A clean host receives `clean=true`, but **no installer approval or authority token**. All statuses are read-only; no files, services, audits, Windows rights or signed FI state change.

The command must be used **alone**. It refuses combinations with `-list-volumes`, `-volume-config`, `-apply`, `-plan-only`, `-config` or any other installer argument, including explicitly passing default values. It returns before legacy installer's default `-apply=true`, old SACL recovery and all PKI/AD/SCM mutation paths. Running the command on an occupied FI host is safe for discovery, not a way to perform cleanup.

## Fresh authorization and first source custody

The new v2 installer must use:

1. `volumereview.BuildFreshInstall` to present **all** explicitly enrolled NTFS volumes and governed-root policies as first-install additions. It must not supply a trusted existing FI baseline.
2. `volumeconsent.VerifyFreshInstall` for installer transaction intent: signed, host-bound, sequence **1**, no prior FI configuration digest, freshly revalidated approved volume identities and policies.
3. `volumegrant.VerifyFreshInstallation` for the initial signed installed scope: generation **1**, no predecessor, separately pinned durable grant digest, actual operational config bytes and normalized v2 scope. This is for future native restart-time enforcement; no committed Windows store currently exists.
4. A new identity, new durable volume epochs and first-baseline checkpoint handling. No old USN state is silently assumed continuous. Historical evidence from previous development runs is never reinterpreted as new-source custody.

The installer must recheck clean-host absence at the actual write boundary, in addition to approved root/volume identity and native privilege checks. Because service creation, directory creation and authorization changes can fail halfway, **rollback of only artifacts created by that attempted fresh installation** and explicit crash-recovery evidence remain required. Such rollback must not be implemented as unconditional deletion of preexisting FI footprints.

## Tests and limitations

The new pure policy tests enumerate all five service blockers and two FI path blockers. They cover absence, present collisions, SCM access failures, file read failures, explicit unknown/native-invalid status, complete deterministic reporting and nil preflight. The Windows CLI tests cover standalone flag isolation, JSON evidence, nonzero blocking and unknown errors. Separate fresh-only review, signed transaction and signed installed-grant tests reject an old trusted baseline or a later approval generation.

**Not yet proven:** `adminbox` native SCM/ACL acceptance; prevention of installation races after the preflight; installer authenticated signing/trust; first-install protected state creation; transactional failure recovery; actual FIUSNReader mode selection; FICollector per-volume source custody; FreeBSD ingest. Go CI cannot substitute for these.

## Suggested acceptance evidence for the first clean installation

Capture host OS/build and test identity, dev branch SHA, signed executable hash, read-only preflight JSON, v2 selected-volume list/full-width serials, approved policy roots, local gMSA/SCM/PKI evidence, first-baseline USN journal/epoch observations, creation-only installer audit, service state after restart and signed batch custody results. Re-run the preflight on an already installed test host and verify it **refuses** another installation without touching existing source data.

Tests that intentionally plant FI remnants must use a disposable isolated test host or isolated simulation. Never create/remove FI-owned markers on a running county host merely to test this path.

See `WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md` and `WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md`.

No change is authorized to `main`, deployed `ISS-FS-22A`, FISender, or backend production data.
