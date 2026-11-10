# FI Windows v2 Development Installer — Legacy Execution Hard Stop

**Engineering date:** 2026-11-09  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Branch-only denial of all inherited FI 1.1 apply/plan execution. **There is no approved v2 apply path and no installation permission.**

## Reason and operator impact

The FI Windows executable `fi-install.exe` inherited a root-centric 1.1 desired-state installer whose `-apply` flag defaulted to true. While the v2 transaction is incomplete, invoking the development executable without arguments could otherwise enter the old installer and create or modify host, AD, PKI, audit, SACL, service or FI state. A clean host does not make that path suitable for v2.

`go/cmd/fi-install/main_windows.go` now calls `requireVolumeFirstReadOnlyMode` immediately after flag parsing, **before** discovery, signing prompts, SACL recovery, and any native mutation. The inherited installer implementation remains in source for historical review but cannot be reached by this branch-built executable.

The only permitted explicit operations are:

```powershell
.\fi-install.exe -check-clean-install

.\fi-install.exe -list-volumes
.\fi-install.exe -list-volumes -volume-config C:\FI-Dev\volume-v2.conf
.\fi-install.exe -list-volumes -volume-config C:\FI-Dev\volume-v2.conf -inspect-policy-roots
```

An empty invocation, `-apply`, `-apply=false`, `-plan-only`, legacy `-config`, a lone `-volume-config`, disabled read-only selectors, mixed actions, and positional arguments fail closed **before** legacy installation. Each permitted mode independently validates the full supplied flag set. A denied operation emits `FI VOLUME-FIRST INSTALLATION BLOCKED` and exits **2**, without entering Windows discovery or changes. A permitted read-only action can still return nonzero if its investigation fails.

The `-apply` help description states that legacy apply is disabled in the development branch. The old 1.1 operator procedures do not install the new architecture.

## Test evidence and non-goals

`go/cmd/fi-install/volume_first_guard_windows_test.go` contains negative and positive command-selector tests. Windows GitHub CI also builds and executes the real development `fi-install.exe` binary in an isolated runner, checks blocked flags, exit code 2, no stdout and the explicit block message, and times out if an unexpected interactive legacy installer is entered. Check CI against the **exact** source commit before relying on the evidence.

This mitigates the **legacy-fallback hazard** in audit finding A01. It does **not** close A01: the authenticated, fresh-only v2 apply transaction is still missing. The new FICollector pipeline, protected state, native `adminbox` acceptance and backend redesign are also incomplete. No source custody or installation authority is inferred from a successful diagnostic.

**Operational hold:** Do not remove FI from ISS-FS-22A, start FISender, update `main` or reuse the existing FI source state as a new v2 installation.
