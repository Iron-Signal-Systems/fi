# FI C1 — Governed pending relational state (unreleased development)

**Date:** 2026-11-22
**Branch:** `dev/c1-two-process-20261120`
**Status:** code-only schema plan; not installed; live ingestion prohibited.

## Verified integration blocker

The live two-jail C1 service still assumes the discarded
`fi_recovery_projection` / `fi_recovery` development staging schemas,
and the independent offline canonical remapper is not part of its Drain
path. Installing those schemas back onto the populated physical C220 is
prohibited. Multiple independently committed SourceParent/family SQL
transactions must remain invisible to canonical `fi` readers until verifier
B and a single atomic Accepted transaction complete.

## Governed pending representation (code-only first slice)

`C1GovernedPendingPlan` builds a SHA-checked schema migration plan for
`fi_c1_pending` in the **existing fi-sor PostgreSQL server**. It mirrors
the exact audited canonical relational structure, FKs and identity rules,
and adds a constrained `generation_control` table linking all original
signed generation fields. A transaction-scoped DDL helper is exercised only by disposable PostgreSQL 18 CI; no production installer or service invokes it.

The native SoR five-family writer/COPY boundary is now capable of targeting the governed pending namespace while the original isolated benchmark path still targets its original schema.
Independent verifier B now has an explicitly whitelisted SQL schema in its
signed group plan. Its original receiver custody, committed group, typed-root
and whole-generation relational readbacks can use exactly the same pending
schema chosen by the SoR writer pool. The isolated benchmark preserves the
original private schema by default; schema selection never comes from
fi-ingest network input. The active `C1SoRService.Bootstrap` now uses a read-only governed pending
schema/ACL gate, the original signed-custody metadata admission transaction,
exact pending SQL-ID readback, and the existing C1 SourceParent/five-family
pool. Verifier B can follow the same schema. This is **application code**,
not an authorized installation on physical C220.

The existing 49-table canonical remapper has now been parameterized to
consume precisely the single governed pending generation. Its natural NTFS
identity reconciliation, generated-ID mapping, FK audit, and all-or-nothing
Accepted journal transaction remain the SAME SQL implementation as the
previous isolated benchmark. It holds pending table and control locks,
rechecks original signed custody and relational proof under those locks,
and refuses foreign or uncertain control state.

The development `FinalProof` continuation now invokes pending publication
only after independent process B fully completes, then checks the *actual*
canonical recorded_generation + Accepted journal in a fresh read-only
PostgreSQL transaction before returning `FinalAccepted`. An uncertain SQL
outcome leaves fi-ingest READY intact and requires read-only reconciliation.

Disposable PostgreSQL 18 exposed an essential SQL privilege boundary:
the normal `fi_ingest` role cannot obtain SHARE ROW EXCLUSIVE table locks on
canonical `fi`. Granting broad canonical UPDATE privileges to fi_ingest
would violate the SQL-worker isolation requirement.

The canonical publisher therefore now uses **a distinct fi-sor-only role**
`fi_c1_publisher` and a separate Unix-domain PostgreSQL connection/
credential. PostgreSQL 18's MAINTAIN privilege grants the necessary strong table
lock authority without allowing UPDATE/DELETE/TRUNCATE of canonical FI
records. The dedicated, offline administrator-reviewed role plan therefore
grants canonical SELECT/INSERT/MAINTAIN and pending SELECT/MAINTAIN
(also on the governing control row), never canonical UPDATE. This isolates
the publisher's locking authority without increasing fi_ingest permissions. The active
fi-sor server requires an explicit publisher DSN and checks its role before
accepting connections. No publisher role or secret has been installed on
physical C220.

Disposable PostgreSQL 18 tests exercise the real pending-to-canonical
remapper with a **synthetic relational test-only proof callback**, late CHECK
failure rollback, exactly one Accepted journal transaction, canonical readback,
and duplicate retry. That proves SQL transaction mechanics only; it does NOT
replace independent signed-custody verifier B or full two-jail acceptance.

The native FreeBSD signed-replay fixture now separately commits an
ORIGINAL receiver-signed SourceParent using the real C1 SQL pool, tears down
the SQL pool before its typed-family transaction, and proves on a new
read-only PostgreSQL session that the parent was durable but its typed
root was not. Independent B must reject the incomplete original generation.
A new C1 SQL pool then executes the exact `EnqueueReplay` path, assigning
virtual commit credit only to the independently verified original parent,
and actually writing only the missing typed family. The commit-ready
scheduler, final SQL totals and independent original-custody B readback
must then agree, with precisely one parent/typed root and no premature
Accepted journal. The fixture destroys this deliberately unaccepted
pending SQL only inside the disposable CI database.

This is an SQL-worker **restart simulation**, not a full PostgreSQL
immediate-stop, hard power-loss, or two-jail service restart test.

A native FreeBSD restart test also confirms that the PostgreSQL
single-generation advisory lock stays unavailable to a competing worker
until the previous database session actually releases it. A bounded
test-only poll replaces an unsafe instantaneous-release assumption; no
production advisory-lock bypass or forced unlock is introduced.

A development-only, explicitly gated **pending replay reconciler** now
reopens original immutable recorded custody and signed manifest bytes,
surveys the committed SourceParent/typed prefix read-only, and reuses C1's
existing per-record signed-identity comparison to skip only matching
committed SQL rows. The fi-sor SQL session holds a PostgreSQL advisory
singleton lock throughout the attempted generation, and FinalProof
requires that same lock before publication. This is not blind replay:
unavailable original receipt, foreign pending source, inconsistent ordinal,
missing typed proof, or uncertain canonical state fail closed.

An **Accepted-only pending retirement** step now uses the dedicated
fi_c1_publisher PostgreSQL identity. Only that role receives TRUNCATE on
the 50 governed `fi_c1_pending` tables; it receives **no TRUNCATE on
canonical `fi`**. The retirement transaction locks canonical journal
evidence and every pending relation, proves the exact original
source/generation/receipt/transfer/counts against one durable Accepted,
and atomically TRUNCATEs only the pending relational tables with
`CONTINUE IDENTITY RESTRICT`. The original receiver custody and all
canonical FI rows remain unchanged. An uncertain cleanup commit is
read back, never presumed successful. After a server restart, Bootstrap
checks the prior original receiver receipt and canonical Accepted status
before automatically retiring a previously accepted pending generation.
An unaccepted or unrelated pending generation is retained for replay.

Synthetic PostgreSQL18 tests include refusal before Accepted, late
canonical rollback, forged/mismatched receipt, foreign pending metadata,
one Accepted journal, successful retirement, and exact retry. The updated
fixture repeats this process for **two distinct generations in the same
populated canonical database**, with pending retirement between them; it
never reclones or resets the canonical 49-table history. They do
not yet establish complete signed two-jail or physical power-loss
acceptance.

This automatic implementation is **not yet accepted for live deployment**:
a complete real signed generation through the **two-jail** mTLS/RAM/
SoR writer, unclean power-loss recovery, and throughput acceptance remain
mandatory. CI now has a FreeBSD test that creates a genuinely signed and
recorded receiver generation and independently checks C1's original
signed-custody manifest reader and tampering rejection. In native FreeBSD disposable PostgreSQL 18 CI, the next gate now
passes that genuinely signed and receiver-recorded custody receipt and
per-batch manifest into the **same fi-sor atomic pending metadata and
generation_control transaction** as C1 Bootstrap. It must commit the exact
receipt/transfer/manifest/data SHA and immutable counts, reject forged
rosters and repeated admission, and leave canonical fi unchanged.
The test trust resolver is confined to an unexported authenticated-fixture
helper; production continues to use installed receiver trust.

The same native FreeBSD fixture now also sends a genuine signed JSONL
SourceParent through the **existing C1 ordered SQL writer and five-family
worker pool**. A separate read-only PostgreSQL B session now reconstructs the
signed generation from committed Pending SQL, then streams the **complete
original receiver-signed transfer** again, independently checking every
artifact, manifest and SourceParent/typed-root digest. Modified committed
SQL digests or absent fixture trust must be rejected. The fixture's
trust resolver is unexported; the independent production B process always
uses the installed receiver trust path. This avoids inventing any replacement SQL
ingestion code. The full B independent OS-process lifecycle is still a
separate acceptance gate.

The first real signed SourceParent -> PostgreSQL -> independent B test
exposed an identity mismatch when recorder JSONL timestamps contain
nanoseconds: PostgreSQL `timestamptz` preserves microseconds. The
read-only recovery/B identity comparison now normalizes only the SQL
timestamp to microsecond precision. The original signed JSONL byte count,
SHA-256 digest, record kind, scope and version remain exact comparisons,
so changed evidence still fails. Unit tests include real RFC3339Nano
timestamps, a changed microsecond and modified SHA.

The native FreeBSD disposable PostgreSQL 18 test now runs **one,
three, four, and five distinct genuinely receiver-signed JSONL records**
through an in-process two-endpoint TLS 1.3 mTLS transport. The three-record case
crosses two SourceParent and two typed-family SQL handoffs within one
original signed batch. The new four-record case contains two Other records, one audited
Windows Security event and one Security Coverage record, all with
original signed envelopes. Native acceptance surfaced the real shared-RAM
contract: Security must retain P5's selected single-pass event and Coverage
must retain validated prepared coverage/observation time. The test now uses
FI's existing `privateFamilyP3Prepare` for every original signed record,
checks the original SHA remains unchanged, and rejects missing Security
selection rather than bypassing prepared provenance. They exercise three distinct SQL family
lanes and must independently prove their actual typed roots before
canonical Accepted. The five-record case uses FI's actual spool writer
to create **three independently signed source batches (2+2+1)**, and
SourceParent handoffs intentionally cross the boundary between those
batches; typed SQL handoffs divide the ordinals differently. Before three-batch admission a swapped batch roster must fail without
writing any pending SQL rows. In the separate FreeBSD B process the test
also modifies the committed digest in source batch two and requires B to
reject it; only restoring the exact original signed digest permits
publication. Every signed source batch ID, per-batch ordinal and original
full SHA-256 must match the canonical PostgreSQL record after one atomic
publication. The test
uses the same producer-owned prepared shared RAM, C1 handoff protocol,
ordered SourceParent writer and five-family-capable SQL pool. The scenarios exercise Security, Coverage and Other families,
but do not yet constitute a single five-family signed generation
with NTFS File and USN dependencies. On Drain a separate read-only PostgreSQL connection
reconstructs the signed generation and verifies the entire original custody
before returning only `FinalVerified`, not `FinalAccepted`. A PostgreSQL
check requires one committed parent and correct typed root, zero canonical
source rows and zero Accepted journal entries. The fixture explicitly keeps
both TLS endpoints inside the disposable test process; it is NOT evidence of
two real jailed workers, an independent B OS process, or canonical
publication. It uses the same C1 SQL implementation, not a second writer.

The same disposable native FreeBSD fixture then exercises the exact
**atomic populated-SoR publisher** with that genuine signed generation,
not a fabricated proof callback: it rereads the receiver's signed
custody under canonical and pending locks, verifies committed typed
relational completeness, promotes the complete parent/typed rows,
inserts a single matching Accepted journal, independently reads back
that canonical status, rejects duplicate publication, and retires
the Pending rows only afterward. The fixture preserves the two previous synthetic canonical
generations and adds four genuinely signed generations, without resetting
canonical history between them.
The production publisher wrapper still resolves only installed receiver
trust; the fixture-only resolver remains private and cannot be supplied
over C1 transport.

The fixture also launches a **distinct FreeBSD B operating-system test
process** before canonical publication. The child receives only a
serialized signed plan and isolated fixture receiver trust, opens its own
`fi_ingest` PostgreSQL session with `default_transaction_read_only=on`,
independently verifies original recorded receipt and custody bytes,
all signed manifests/JSONL, SQL SourceParent/typed roots, and complete
relational coverage. Before invoking the successful B child, the native regression also
mutates a committed Pending SourceParent SHA-256 and requires the
distinct B process to **reject the changed SQL evidence**, then restores
only that isolated fixture row and requires a successful independent
re-verification. A failed child blocks the test publisher. The next native FreeBSD acceptance case also runs the SAME
`RunC1SoRNativeBChild` READY/PASS/FINAL protocol in a separate test
operating-system process with its own **local PostgreSQL Unix socket**
and read-only session. It must reject a premature FINAL and duplicate
READY before accepting precisely one post-COMMIT group followed by final
full original signed-custody and relational proof. The production
`RunC1SoRNativeBChild` wrapper remains fixed to installed receiver
trust; the unexported in-package test entrypoint alone uses ephemeral
signed CI fixture trust. No arbitrary trust resolver can be selected
by fi-ingest or over the authenticated transport.

The disposable test also starts the SAME production B parent launcher,
notification-channel writer, strict PASS response scanner, process-lifetime
management and final `Finish` barrier, with the test binary substituted
for the installed worker executable. That test revealed a real protocol
fault: successful original signed-custody verification wrote a human-readable
diagnostic to stdout, where the parent accepts **only** `PASS n` or
`FINAL PASS`. The original signed-custody diagnostic now goes to stderr,
without weakening the parser or changing final proof semantics. The test child exits without Go's
extra PASS footer, so the real parent parser accepts only exact C1 proof
protocol messages. The production launcher remains pinned to its own
`--c1-b-child` executable; the substitute is injectable only from
in-package tests.

The fixture now exercises both real parent and child B IPC mechanisms
in independent OS processes. It does not yet establish the full
`fi-c1-sor-worker` installed service lifecycle, concurrent notifications
while SQL families are still processing, or actual two-jail deployment.

The fixture uses the actual C1 SQL and canonical publisher primitives
but invokes final publication as a **separate test step**, not as a live
`C1SoRService.FinalProof` process in two jails. It is not yet evidence
of distinct fi-ingest/fi-sor jail services, accepted parallel B child
scheduling against concurrent SQL workloads, power-loss recovery, or
performance acceptance. Pending replay remains explicitly
opt-in until real original signed-custody interruption acceptance passes. The optional
`BVerified` lifecycle transition is not yet made durable: publication
instead requires independent B completion and repeats the full proof under
locks before committing Accepted. Existing incomplete generations fail closed.

Control state is `Pending`, `SQLSealed`, `BVerified`,
`PublicationUncertain`, or `Retired`. None means canonically Accepted.
The unique index admits only one unresolved generation; an uncertain
commit fails closed rather than making a new generation eligible.
The SoR SQL worker role has SELECT-only access to the *pending*
`ingest_journal`, because clean START/replay must prove it is empty.
The first native signed PostgreSQL admission test caught that the prior
total REVOKE made real clean START fail with SQLSTATE 42501. It must
never be allowed to INSERT, UPDATE, DELETE, or TRUNCATE journal rows.
The SoR SQL worker role may INSERT only the six signed-identity columns of
a Pending generation control record in the same transaction as the original
signed source metadata. It cannot specify B proof fields or the lifecycle
state, and cannot UPDATE those fields or write a pending `ingest_journal`.
The new `StageC1SignedPendingMetadata` primitive enforces original
immutable signed receipt and exact batch roster before this atomic SQL
admission; it does not enable service startup or claim final acceptance. The canonical journal remains the sole acceptance
authority.

This is a **design candidate**, not approval to install a second
authoritative database or revive the deleted private development schemas.

## Remaining mandatory engineering work

1. Complete the admin-only installation and SoR-owned lifecycle API. The
   existing transaction-scoped DDL helper and disposable PostgreSQL 18 tests
   cover rollback, mirrored FKs, writer ACLs and unresolved-generation fence;
   production preflight and a safe state-transition owner are still missing.
2. Complete disposable PostgreSQL18/FreeBSD interruption and power-loss
   acceptance for pending replay, including original signed custody checks,
   partial SourceParent + typed families, missing/changed hashes, and recovery
   of interrupted SQL commits. The replay implementation is gated until
   this acceptance passes; no second SQL algorithm or PostgreSQL in fi-ingest.
3. Validate the reused canonical promotion SQL against a fully populated
   disposable PostgreSQL 18 database and a genuine original signed C1
   generation, including NTFS natural-key remaps and each five-family table.
   The current one-unresolved-generation admission model intentionally
   prohibits unrelated pending source rows; future concurrency requires a
   separate accepted isolation design.
4. Prove the wired final Drain publisher in full disposable acceptance:
   all typed rows and the one canonical `fi.ingest_journal` Accepted event
   must commit in the same SQL transaction. An error or uncertain commit
   must never become an accepted Drain ACK.
5. Re-read canonical generation and journal after publication before sending
   `FinalAccepted`. Preserve original custody and READY marker on all
   errors; reconcile exact prior Accepted on restart before attempting replay.
6. Run FreeBSD / disposable PostgreSQL 18 acceptance for complete signed
   generation, duplicate receipt, forged ACK, corruption, SQL rollback,
   SIGKILL/power loss, interrupted transfer, ambiguous commit and restart.
   Compare relational contents/families and previous C1 throughput; no
   Windows backend tests.

## Physical C220 hold

Do not start C1, install pending DDL, change canonical PostgreSQL or restart
C220 on the strength of this schema-plan commit. Only tested and reviewed
application integration can lift that hold.
