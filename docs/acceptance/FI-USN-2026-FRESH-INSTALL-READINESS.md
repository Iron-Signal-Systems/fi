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
| W1 Volume raw capture | One journal owner and durable source cursor per NTFS volume; capture independent of NTFS reopen, hashing, network and governed-root processing | Implemented in inactive development code; physical throughput unaccepted |
| W2 Journal continuity | Exact volume GUID/serial, journal ID, capture NextUSN, FirstUSN and LowestValidUSN; wrap, reset, full queue, disk full and broker failure fail closed | Unit tests partial; power-loss/stress evidence missing |
| W3 Baseline anchor | Journal cursor established before verified baseline, no historical interval invented; complete tested baseline-to-index handoff, never adopt an aged-out old checkpoint | **Blocked: missing governed migration** |
| W4 Historical scope | Persistent replayable time-indexed directory + hard-link identity evidence; negative decisions require exact complete historical proof; no exclusion of Unresolved | **Blocked: index and exclusion ledger missing** |
| W5 Selective NTFS observation | Separate bounded worker performs policy-required file-ID/ACL/SACL/ADS/content hash observations with actual observation timestamps; source-only USN never impersonates these observations | **Blocked: independent observation worker missing** |
| W6 Spool custody | All roots published exactly once per original source segment; verified manifest, source SHA, receipt and cursor ordering; crash windows recover without duplicates or unproved retirement | In development: durable intent and fail-closed ambiguity; **automatic safe reconciliation missing** |
| W7 Windows service / installer | Explicit versioned, opt-in service configuration; disable conflicting legacy USN cursor owner; install/upgrade/rollback ACL and queue capacity gates; Security and supporting workers preserved | **Blocked: service activation and fresh-install gates missing** |
| B1 Source wire and C1 | Sender, receiver, ordered C1 USN P6 and PostgreSQL 18 recognize same exact source-only contract; unknown kinds fail; source and event conservation | Implemented in separate development branch; real cross-branch transport acceptance missing |
| B2 Verifier B | B separately checks relational counts, identities, ordered ordinals and inconsistent/overlapping intervals within generation, without source reread | New native acceptance tests pending on exact backend commit |
| B3 Replay/continuity | Exact signed generation idempotence, conflicting duplicates, cross-generation source overlap/restart, tamper and failure proofs | **Blocked: full cross-generation acceptance missing** |
| F1 Fresh Windows installation | AdminBox reproducible Windows binaries, FI-free AD-joined host, helper/gMSA service controls, installer, uninstall/rollback, new state and receiver wiring | **Not performed** |
| F2 Stress / recovery | Measured sustained 20-million-event/file workload, capture lag vs journal retention, transport down/up, crash/power loss at each durable boundary, disk limits and restart | **Not performed** |
| F3 End-to-end SoR | Exact Windows source batch -> spool -> sender -> signed receiver custody -> P5/P6 -> 51-table disposable PostgreSQL readback -> independent B proof, no fabricated success | **Not performed on a fresh Windows installation** |

## Source and verification invariants

1. Keep original USN observations in exact journal order and preserve every
   occurrence. Deduplicate **observation work only**, never original source
   records. One volume capture may feed many governed roots.
2. A local capture cursor advances only after immutable original source
   segment persistence. A processed cursor advances only after complete
   governed-root source decisions, required separate observations when
   applicable, durable verified spool custody, and a bound publication receipt.
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

- Windows `b9fff2f`: Windows Collector CI, CodeQL and Security Validation
  passed. Later window-source proof binding and multi-root test commits are
  development candidates **pending their own complete CI**.
- Backend `d774b3a`: native disposable FreeBSD/PostgreSQL acceptance passed.
  Backend `f1ce48f` adds two-source-batch and independent B overlap/ordinal
  tampering tests; the latest native run must pass before its acceptance is
  claimed.
- The live C220 and ISS-FS-22B deployments have not been used as test data
  sources by this development work.

## Installation-release decision

**FAIL / NO GO** if any gate lacks objective, traceable evidence. Record the
two exact branch SHAs, CI run IDs, AdminBox binary hashes, installer manifest,
gMSA/privilege boundaries, source/capture/processed cursor snapshots, journal
FirstUSN/NextUSN throughout load, manifest and generation identities, SoR
canonical row counts, verifier B result, rollback result and all failure
injections before proposing an isolated 22B test.

Do not call this pre-alpha implementation safe to install until every relevant
gate has genuinely passed. No existing FI state or live workload is expendable.
