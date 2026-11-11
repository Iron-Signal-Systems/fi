# FI Windows Volume-First — Native Installer Token Read-Only Preflight

**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Read-only Windows process-token observation and pure negative-path policy; **NOT installer authorization, signed operator consent, service execution or release acceptance**.

## Why token identity matters

Membership in the local Administrators group does not by itself make the current process elevated. User Account Control (UAC), disabled/deny-only Administrators membership, impersonation, integrity level, restricted tokens and AppContainer status can all make apparently privileged code unsuitable for the planned create-only installer transaction. A genuine elevated administrator process is also not proof that the correct person approved FI's enrolled volumes or signed grant.

`go/internal/windows/freshinstall/installer_token_policy.go` defines `InstallerTokenEvidence` and `AssessInstallerTokenEvidence` without any Windows runtime dependency. `installer_token_windows.go` collects native evidence for the **current process token** on a pinned OS thread and never impersonates an account, duplicates an elevated token, adjusts token privileges or modifies Windows ACLs. Both remain package-private to the development foundation; `fi-install` and FI Windows services **do not invoke them**.

## Native fields and fail-closed decision

The observer opens its own process token with **TOKEN_QUERY only**, then checks whether the current OS thread has an impersonation token **before and after** gathering evidence. Only `ERROR_NO_TOKEN` is accepted as a clean absence; other failures or attached impersonation tokens block the evidence.

On that process token it reads the user SID, primary-token type, `TokenElevation`, `TokenElevationType`, mandatory integrity SID, **the actual primary `TokenGroups` attributes for the BUILTIN Administrators SID** (enabled and not deny-only), restricted-token and `TokenHasRestrictions` status, AppContainer status, and a bounded native `TokenPrivileges` array. Windows CI demonstrated that `Token.IsMember`/`CheckTokenMembership` can reject a primary token when the current thread does not impersonate; FI therefore reads group attributes directly rather than temporarily impersonating or duplicating a privileged token. Native token information errors, missing/truncated structures, duplicate LUIDs, excess counts and unknown privilege attribute flags fail closed rather than being silently interpreted as false.

The pure policy accepts as a **potentially eligible interactive installer precondition** only a non-service account with a primary, nonimpersonating, elevated token, **enabled** BUILTIN Administrators membership, **High integrity (RID 0x3000)**, unfiltered/restriction-free, non-AppContainer status, and an understood `TokenElevationType` of Full or Default. Default is considered only alongside the explicit elevation and high-integrity checks, allowing deployments with UAC configured differently. UAC-Limited, medium/low, SYSTEM (System integrity), LocalService, NetworkService, restricted and impersonation contexts do **not** satisfy this particular *interactive operator* preflight. A separate, explicitly authorized SYSTEM/gMSA service execution model remains necessary.

The six observed privilege names are `SeBackupPrivilege`, `SeRestorePrivilege`, `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeImpersonatePrivilege` and `SeDebugPrivilege`. Their **present/enabled** flags are recorded but not modified; some privileges may be absent or disabled even in a valid elevated administrator token. Presence or enabled status does not prove administrative consent or entitle FI to sensitive access. Required privileges for actual creation actions must be established and bounded separately during the authorized installer transaction.

## Tests and unresolved security authority

Pure tests reject false claims for UAC elevation, medium/System integrity, disabled group membership, SYSTEM/service identities, thread impersonation, restricted/app-container contexts, missing or inconsistent privilege information and incomplete arrays. Windows-native tests inspect the CI runner's actual process token **read-only** and exercise invalid token-handle rejection. Its token may be elevated or unelevated; either is a valid test environment, but the observer itself must return complete, well-formed evidence. An ineligible test runner is **not** an accepted installer host.

**This is not a token-based AccessCheck for the live `ProgramData` DACL or an authenticated actor/session.** The observer does not establish a trusted OS issuer, user presence, recorded consent, signed receipt, CNG key custody, protected system-parent provenance, correct gMSA/service SID, complete creation journal or durable installed-grant commitment. The development bootstrap still accepts a supplied parent path and is **not bound to this snapshot**.

Next required gates: controlled `adminbox` verification of the intended elevated operator token and real system ACLs, independently authenticated consent/signer, proven handle-based parent-to-creation transaction, and interrupted-install recovery before any installer enablement. **A05 stays P0/open; V14/V16 remain NOT RUN; ISS-FS-22A removal or reinstall is NO-GO.**
