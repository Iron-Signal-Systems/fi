# FI Deployment Tooling

This directory contains administrator-run deployment and characterization tools.

The current Windows source installation authority on
`windows-installer-multirelease-20261005` is the native Go installer:

```text
fi-install.exe
```

See:

```text
docs/WINDOWS-INSTALLER.md
docs/WINDOWS-INSTALLER-ACCEPTANCE-2026-10-09.md
```

Deployment tooling is not normal FI collector/runtime remediation authority.

## Current Windows source installation

The native installer owns current Windows source desired-state discovery,
prerequisite checks, configuration approval, Approval 1/Approval 2 boundaries,
PKI enrollment, package/release trust, local rights/groups/ACLs, SCM
configuration, runtime convergence, receiver activation, executable-name
migration, rollback, and durable install records.

The canonical five-service runtime is:

```text
FICollector
    C:\Program Files\FI\fi-collector.exe

FIUSNReader
    C:\Program Files\FI\fi-usn-reader.exe

FIObjReader
    C:\Program Files\FI\fi-obj-reader.exe

FICRLRefresher
    C:\Program Files\FI\fi-crl-refresher.exe

FISender
    C:\Program Files\FI\fi-sender.exe
```

The normal source installer should be used from a reviewed signed release
package. It applies by default after all required explicit approvals.

Planning-only mode is:

```powershell
.\fi-install.exe -plan-only
```

Do not invoke `fi-install.exe` without `-plan-only` merely to "look at" a system;
the native installer is apply-enabled by default.

## Legacy manual Windows runtime configuration script

The following script remains in the repository as earlier deployment and
characterization tooling:

```text
tools\deployment\windows\Configure-FI-Source-Runtime.ps1
```

It predates the current native Go installer, the five-service runtime,
FICRLRefresher, current release/package trust, receiver-pending activation, and
canonical executable-name migration.

It must not be treated as the authoritative current installer contract.

Historical material that refers to:

```text
fi.exe
fi-usn.exe
fi-obj.exe
four Windows runtime services
```

describes the older accepted deployment generation. Those names are no longer
the canonical installed executable names.

The script may remain useful for historical reproduction or controlled
characterization until it is deliberately retired or rewritten, but new
installer documentation and release acceptance must use the native Go installer
contract.

## Windows Phase 1 data ACL hardening

`Harden-FI-Data-ACL.ps1` is an administrator-run historical deployment action
for the earlier FI state/spool ACL contract.

The native installer now owns the current integrated FI-owned ACL plan,
including configuration, program files, state, spool, collector work directory,
stage, transport trust/CRL state, CRL refresher state, and applicable CNG key
files.

The hardening script remains useful for reproducing earlier Gate 1 deployment
acceptance. It should not be used as a substitute for current installer
convergence.

The earlier root ACL shape used by that script was:

```text
SYSTEM                  Full
BUILTIN\Administrators  Full
FICollector gMSA        Modify
```

The current installer contract is broader and path-specific. See
`docs/WINDOWS-INSTALLER.md`.

## Linux Phase 3 ingest-worker packaging

Permanent Linux relational ingest-worker service packaging lives under:

```text
tools/deployment/linux/
```

That subtree owns the accepted Phase 3 systemd unit, installer, package
validation, and operator instructions for the permanent Linux ingest worker.

The accepted Linux Phase 3 service remains engineering history. It does not
replace Phase 6 integrated backend/appliance packaging.

## Authority rule

When deployment scripts, old acceptance instructions, and the native installer
disagree about the current Windows source deployment contract:

```text
current reviewed installer source
        >
current Windows installer documentation
        >
historical/manual deployment tooling
```

Any disagreement between the first two is a documentation or implementation
defect that must be resolved before release acceptance.
