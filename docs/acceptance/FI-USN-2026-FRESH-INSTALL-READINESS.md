# FI volume-first USN: fresh-install acceptance gate

**Status: NOT READY / NOT ACCEPTED / PRE-ALPHA — development branches only.**

**Scope:** one complete integrated FI product from a completely FI-free,
AD-joined Windows Server sender, through verified local spool and FIGT
transport, to the currently governed FreeBSD receiver/C1/PostgreSQL SoR. A
successful synthetic SQL fixture, Windows CI compile, or individual unit test
is not a fresh-install acceptance result.

**Target branches:** `windows-usn` (Windows collector, queue, spool, service,
installer) and `backend-usn` (FreeBSD source contract, C1 and independent B
relational proof). Neither is `main` or deployed C220 authority. Each
candidate must be pinned to an **exact immutable commit** before any physical
test, with corresponding complete CI evidence.

## Non-negotiable deployment isolation

- Do **not** merge into `main`, modify or deploy to C220, reset the live
  PostgreSQL SoR, or change ISS-FS-22B's running FI, USN journal, checkpoints,
  ACLs, sender or Windows services while pre-install gates are outstanding.
- Build from an exact Windows branch commit on governed AdminBox. No Git work
  from the C220 host and no fresh-install attempt on a host with leftover FI
  state. Use a deliberately FI-free, AD-joined test Windows Server.
- The only backend native acceptance target is a disposable FreeBSD 15.1 /
  PostgreSQL 18 VM with a disposable database. Keep original signed custody
  and independent verifier B; **do not replace B with full source replay**.
- FI remains a single configuration-driven installer/product. Development jails
  are an implementation detail, not customer deployment requirements.

## Evidence gates — all required

| Gate | Required objective evidence | Current disposition |
| --- | --- | --- |
| W1 Volume raw capture | One journal owner and durable source cursor per NTFS volume; capture independent of NTFS reopen, hashing, network and governed-root processing | Integrated opt-in service volume owner and independent raw capture; measured 20M-file physical throughput unaccepted |
| W2 Journal continuity | Exact volume GUID/serial, journal ID, capture NextUSN, FirstUSN and LowestValidUSN; wrap, reset, full queue, disk full and broker failure fail closed | Subsecond capture schedule, source free-space floor, fail-closed wrap/capacity tests; actual power-loss and journal-wrap acceptance missing |
| W3 Baseline anchor | Journal cursor established before verified baseline, no historical interval invented; complete tested baseline-to-index handoff, never adopt an aged-out old checkpoint | Bootstrap captures source before/during all verified roots, requires immutable completion witness; product installer still lacks governed automatic bootstrap transition |
| W4 Historical scope | Persistent replayable time-indexed directory + hard-link identity evidence; negative decisions require exact complete historical proof; no exclusion of Unresolved | Source-verified forward directory USN history index implemented and replay-tested; baseline ancestry/hard-link completeness and negative-proof ledger still missing; never exclude Unresolved |
| W5 Selective NTFS observation | Separate bounded worker performs policy-required file-ID/ACL/SACL/ADS/content hash observations with actual observation timestamps; source-only USN never impersonates these observations | Third independent File-ID observation worker, source-bound spool verification and durable observation cursor are in CI; failures remain pending, missing-object outcome acceptance and stress proof missing |
| W6 Spool custody | All roots published exactly once per original source segment; verified manifest, source SHA, receipt and cursor ordering; crash windows recover without duplicates or unproved retirement | Locally finalized spool crash recovery verified; transferred/missing spool fails closed; remote-ack reconciliation and authorized custody retention missing |
| W7 Windows service / installer | Explicit versioned, opt-in service configuration; disable conflicting legacy USN cursor owner; install/upgrade/rollback ACL and queue capacity gates; Security and supporting workers preserved | Exact opt-in installer config, secured source root, gMSA ACL, manual staged collector/sender and distinct service workers; governed installer bootstrap/activation and physical rollback gates missing |
| B1 Source wire and C1 | Sender, receiver, ordered C1 USN P6 and PostgreSQL 18 recognize same exact source-only contract; unknown kinds fail; source and event conservation | Source-only USN P6/PostgreSQL 18 proof green at backend 491eda9; signed Windows-to-backend acceptance still missing |
| B2 Verifier B | B separately checks relational counts, identities, ordered ordinals and inconsistent/overlapping intervals within generation, without source reread | Independent B source/child counts, source ordinals, overlap and missing-child rejection green on disposable native PostgreSQL 18 at backend 491eda9 |
| B3 Replay/continuity | Exact signed generation idempotence, conflicting duplicates, cross-generation source overlap/restart, tamper and failure proofs | Native PostgreSQL 18 B cross-generation duplicate/overlap rejection green at backend 491eda9; Windows-signed transport outage/replay acceptance outstanding |
| F1 Fresh Windows installation | AdminBox reproducible Windows binaries, FI-free AD-joined host, helper/gMSA service controls, installer, uninstall/rollback, new state and receiver wiring | **Not performed** |
| F2 Stress / recovery | Measured sustained 20-million-event/file workload, capture lag vs journal retention, transport down/up, crash/power loss at each durable boundary, disk limits and restart | **Not performed** |
| F3 End-to-end SoR | Exact fresh Windows source -> actual local spool -> signed sender/receiver custody -> P5/P6 -> disposable PostgreSQL readback -> independent B proof, no fabricated success | **Not performed on a fresh Windows installation** |

## Source and verification invariants

1. Keep original USN observations in exact journal order and preserve every
   occurrence. Deduplicate **observation work only**, never original source
   records. One volume capture may feed many governed roots.
2. A local **capture cursor** advances only after immutable original
   volume-source segment persistence. The separate **scoped-source processed
   cursor** advances only after verified scoped source publication; it **never
   waits for NTFS file re-observation**. A third independently scheduled
   **observation cursor** advances only after real policy-required current
   NTFS evidence and a verified spool witness (or verified no-work decision).
   Original raw source retirement is prohibited until downstream acceptance
   AND all independently required observation-consumption evidence exist.
3. Incomplete spool work is never finalized as successful output. An ambiguous
   publication must not be blindly replayed: retain source and fail closed
   until verified spool/receiver custody can reconcile it.
4. A current NTFS path is not historical scope evidence. An unknown ancestor
   or incomplete hard-link ledger means Unresolved, not ProvenOutside.
5. Backend A and independently executed B check different evidence stages.
   Verify native relational consistency and source custody at their own
   boundaries, rather than rereading the entire historical source repeatedly.
6. Never claim a synthetic `USNScopedCapture` source fact is a successful
   FileObservation; raw USN contains no proof of current file content, ADS,
   DACL/SACL or full file hash.
7. Preserve exact source identity and durable timestamps across recovery and
   make false or unverifiable evidence fail closed, not silently disappear.

## Current development evidence (2026-11-28)

- Windows latest **development candidate** `54291f6` adds the third scheduled
  File-ID observation worker, source-hash-bound policy, observation cursor,
  manifest verification and installer configuration. CI runs on this exact
  candidate are **not yet accepted**; check all Windows Collector, CodeQL,
  Security Validation (including race/vulnerability) conclusions.
- Windows `b634e65` passed all three CI gates after disabling unsafe original
  source reclamation. Windows `74e4358` passed the same gates after verifying
  restart directory ancestry against original immutable USN evidence.
  Later new observation worker commits must be tested independently.
- Backend `491eda9` passed its **four** CI gates, including native disposable
  FreeBSD 15.1/PostgreSQL 18 relational source/child/ordinal/overlap and
  signed cross-generation conflict proofs. No fresh Windows-signed real
  receiver-to-SoR acceptance exists.
- The Windows installer can stage services and protected source custody, but
  it does not yet perform an automatic gMSA-run initial bootstrap and governed
  service activation. Do not mistake `-usn-volume-bootstrap` source code
  existing for a completed FI-free, one-installer deployment.
- W4's directory index only makes **positive** source-native ancestry claims.
  Complete historical hard-link membership and negative exclusion proof are
  unaccepted. The selective observer treats unknown membership as a candidate
  and retries instead of reporting invented current file state.
- All changes are development-only. The live C220 and ISS-FS-22B have not
  been used as validation or migration targets.

## Installation-release decision

**FAIL / NO GO** if any gate lacks objective, traceable evidence. Record the
two exact branch SHAs, CI run IDs, AdminBox binary hashes, installer manifest,
gMSA/privilege boundaries, source/capture/processed cursor snapshots, journal
FirstUSN/NextUSN throughout load, manifest and generation identities, SoR
canonical row counts, verifier B result, rollback result and all failure
injections before proposing an isolated 22B test.

Do not call this pre-alpha implementation safe to install until every relevant
gate has genuinely passed. No existing FI state or live workload is expendable.
