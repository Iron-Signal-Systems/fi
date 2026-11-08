# Windows Volume-First Scope Review — Deterministic Preflight

**Date:** 2026-11-08
**Branch:** `dev/windows-volume-first-20261108`
**Status:** Read-only review and stale-plan detection implemented with Go tests; complete installer authority and deployment NOT implemented.

## Why this exists

FI's previous installer assumes `version_id: 1.1` with one or more governed roots. A volume-first configuration changes **what is captured**, not just a path list. Adding a single NTFS volume enables minimal source-change capture across the enrolled volume even outside governed roots. A governed-root policy separately authorizes deeper observation. Neither action can be silently inferred from the old configuration.

`go/internal/windows/volumereview` produces evidence for an explicit operator review; it does not constitute or issue approval.

## Read-only review contents

The separate branch-only `fi-install.exe -list-volumes -volume-config <file>` command emits `requested_scope_review` in its JSON, in addition to the native inventory and ordinary enrollment match details. The review includes:

- `version = fi-windows-volume-scope-review/1`;
- SHA-256 of the **canonical requested v2 scope**;
- optional SHA-256 of a **trusted old v2 baseline** if one is supplied by future installer code; ordinary CLI preflight has no installed v2 baseline and therefore represents all requested volumes and policies as additions;
- typed changes: `VolumeAdded`, `VolumeRemoved`, `VolumeIdentityChanged`, `PolicyAdded`, `PolicyRemoved`, and `PolicyChanged`;
- the independently observed current status and full-width NTFS serial for **each specifically requested volume**;
- `blocks_mutation` on any requested volume mismatch, and `requires_explicit_approval` on any proposed scope/policy change;
- a domain-separated `review_fingerprint_sha256` of the complete deterministic review body.

Review fingerprints intentionally do not include drive letters, mounted-folder aliases, or the discovery order. They are not independent volume identities. An extra unrequested volume stays visible in the broader inventory but is not enrolled or added to the approved review scope.

All policy changes — including `metadata` to `security`, `security` to `metadata`, `security` to `content`, root moves, additions, and removals — require review. These depths express distinct permissions, not a single safe monotonic ordering. The v2 declaration allows a volume to have **zero governed-root policies**, while still requiring explicit volume enrollment for minimal USN change detection.

## Revalidation and security limitations

`volumereview.Build(existing, requested, native)` demands canonical v2 declarations and validates a complete native snapshot. `volumereview.Revalidate(previous, existing, requested, freshNative)` recomputes the entire review and refuses changes in the presented review body, installed baseline, proposed scope, native eligibility, full-width serial or volume identity. Missing/unsupported/offline/replaced requested volumes block revalidation even if the prior review already showed them missing.

**Important: SHA-256 is not an approval signature.** A digest can detect stale data against an independently retained expected value; it cannot prove that an administrator authorized scope. The future installer must obtain and authenticate explicit operator consent, bind the review to host identity and approved installation state, persist an appropriately protected receipt, verify ACLs and signature/trust as required, perform fresh native discovery before each mutation, and recover transactionally on failure. Neither a `requested_scope_review` nor a successful `Revalidate` grants the broker access.

The standalone preflight continues to run before the legacy installer's default `-apply=true` path and before SACL recovery, PKI/AD operations or service changes. No installed v2 configuration is created; the legacy collector and helper still load v1.1.

## Signed consent verifier remains separate from scope review

`go/internal/windows/volumeconsent` verifies a short-lived ECDSA P-256/SHA-256 signed installer intent bound to this exact review, native volume observation, trusted old/new configuration, host/installation identity and an independently maintained approval sequence. The signer and trust-anchor provisioning are **not implemented**. This does not issue operator consent, persist an installed grant or enable volume-mode USN. See `WINDOWS-VOLUME-FIRST-CONSENT-RECEIPT.md`.

## Test coverage

- First-time enrollment requires explicit review of every volume and policy.
- Identical old/new trusted v2 scope produces zero change proposals; it does not itself authorize a reinstall.
- Changed serial, missing volume or access denied blocks a scope, and cannot pass a later revalidation.
- Changed policy depth, changed root, policy removal, changed volume identity, volume removal and modified old baseline produce a stale-plan rejection.
- Changed mount alias and reordered native discovery do **not** falsely invalidate a requested volume identity.
- Duplicate/untrusted native entries and malformed/absent configuration fail closed.
- A tampered review body with its previous fingerprint retained does not pass revalidation.
- The installer JSON test requires `collection_authorized=false`, the matching scope-review fingerprint, and nonzero exit status on native mismatch.

**Not tested / not implemented:** Signed approved receipt, host-bound authorization, protected v2 config installation, installer rollback, broker startup selection, FICollector volume workers, and end-to-end source custody. Native Windows Server acceptance on `adminbox` has not occurred.

See `docs/development/WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md`, `docs/development/WINDOWS-VOLUME-FIRST-DISCOVERY.md`, and `docs/development/WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md`.
