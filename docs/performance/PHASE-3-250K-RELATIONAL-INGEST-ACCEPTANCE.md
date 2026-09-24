# Phase 3 — 250K Relational Ingest Acceptance

## Status

**IN PROGRESS — Phase 3 / Gate 3**

This document records the fresh relational PostgreSQL acceptance campaign that
began on 2026-09-20 using the active 250K FI corpus.

It is a Phase 3 backend acceptance record. It does **not** rewrite the earlier
post-Gate-1 Phase 2 250K randomized nested source campaign as a clean onboarding
PASS. That earlier campaign was intentionally interrupted during fault injection
and remains engineering/resilience characterization.

## Purpose

The Phase 3 campaign answers a different question:

> Can immutable recorder-authorized generations be re-opened, validated,
> materialized into the typed relational model, reconciled, retried, and caught
> up without creating partial or ambiguous authority?

The campaign intentionally started with a fresh relational database so current
results would not be confused with earlier development materialization state.

## Relational foundation under test

The active implementation is:

```text
IngestVersion:        fi-postgresql-relational-ingest/0.2
PostgreSQLUser:       fi_ingest
PostgreSQLDatabase:   fi
RelationalTables:     49
SupportedRecordKinds: 13
```

The runtime boundary requires:

- zero JSON, JSONB, or XML storage columns;
- append-only normal runtime authority;
- no `UPDATE`, `DELETE`, or `TRUNCATE` authority over `fi.source_record`;
- exact recorder receipt and FIGT transfer identity binding;
- generation-level transactional ingest;
- typed source-record projection; and
- typed-projection completeness before authoritative acceptance.

## Authority path

The campaign uses the supported authority path only:

```text
immutable recorder receipt
        |
        v
exact durable FIGT custody
        |
        v
LoadRecordedGeneration
        |
        v
custody + trust + transfer + collector validation
        |
        v
PrepareSourceRecord over exact LF-terminated record bytes
        |
        v
single PostgreSQL generation transaction
        |
        +-- recorded_generation
        +-- source_batch
        +-- source_record
        +-- typed projections
        +-- ingest_journal terminal outcome
```

No test in this campaign treats `/var/lib/fi/custody/recorded` as a source-JSONL
directory. The recorded root contains immutable generation recorder receipts.

## Fresh database start

All 49 relational tables were deliberately reset with identity restart before the
fresh campaign.

Initial state:

```text
recorded_generation    0
source_batch            0
source_record           0
ingest_journal          0
database_bytes          10,991,295
```

This reset applied only to the relational database acceptance state. It did not
rewrite receiver custody or recorder receipts.

## Initial sequential ingest

The first eight existing recorded generations were ingested sequentially while
the receiver was stopped for the controlled start of the campaign.

The largest of those early generations contained three batches, approximately
33.5 MB of data, and 6,844 source records. That generation committed in roughly
81 seconds during the initial unoptimized relational acceptance path.

After the initial eight generations, read-only reconciliation reported the eight
recorder receipts as accepted with no conflict.

No PostgreSQL tuning conclusion is drawn from this early timing. The campaign is
currently validating correctness, authority, recovery, and representative
behavior before deciding whether database tuning is necessary.

## ContentPrefix rejection and correction

During live catch-up, one real `FileObservation` generation was rejected because
the relational projector incorrectly required a non-empty base64url value when
the source contract validly contained:

```text
State:           Present
BytesObserved:   0
PrefixBase64URL: ""
```

The source contract allows that state for an observed empty file.

The projector was corrected so that:

- the source `ContentPrefixObservation` is validated first;
- non-`Present` states remain non-materialized prefix data;
- `Present` parses `BytesObserved`;
- empty base64url is valid when zero bytes were observed;
- decoded prefix length must exactly equal the declared byte count; and
- a valid zero-length decoded prefix is stored as zero-length `bytea`, not NULL.

Focused tests prove:

- `Present`, zero bytes, empty prefix is accepted;
- a four-byte `%PDF` prefix decodes correctly; and
- an empty prefix with `bytes_observed=1` is rejected.

The formerly failing real generation was then retried:

```text
GenerationID:         20260920T190821.455176200Z-404d96177e0eb1d9
Batches:              3
DataBytes:            33,552,873
RecordsSeen:          7,167
RecordsCommitted:     7,167
RecordedGenerationID: 49
Outcome:              Accepted
```

That is the real-data acceptance proof for the zero-byte-prefix correction.

## Real zero-byte file relationship proof

A later relational query selected the exact real source record that exercised the
corrected zero-byte path.

Representative facts:

```text
source_record_id:     43135
record_kind:          FileObservation
record_bytes:         4521
record_sha256:        07ffba4c243d5658954517eeb27107b1610441e32fefb8812c37f3e1f61fe747
logical_size:         0
allocated_size:       0
content_prefix_state: Present
bytes_observed:       0
prefix_length:        0
```

The stored content hashes were the canonical hashes for empty content:

```text
MD5     d41d8cd98f00b204e9800998ecf8427e
SHA1    da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The same relational object could be followed through governed-root identity,
path, volume-qualified NTFS object identity, metadata, hashes, content prefix,
stream inventory, owner, DACL/SACL state, reparse state, and warnings.

This is an important Gate 3 result: the relational model is not merely counting
records; it is preserving and reconnecting the source relationships required for
later FI queries.

## Content-prefix population check

At the recorded campaign checkpoint:

```text
total_prefix_rows            93,038
present_rows                 87,656
valid_zero_byte_prefixes          1
length_mismatches                 0
```

At that same point, the `FileObservation` count equaled the content-prefix row
count, and no observed prefix length disagreed with its decoded byte length.

## Live Go ingest worker

The temporary shell consumer used during early diagnostics was retired.

The current live acceptance consumer is the Go command:

```text
go/cmd/fi-ingest-worker
```

The worker uses FI-native APIs:

- `PlanRecordedGenerations`;
- `LoadRecordedGeneration`;
- `IngestPreparedGeneration`;
- `WriteAttemptStarted`; and
- terminal ingest-journal events.

It processes pending generations sequentially.

A bounded validation run with `-once -max-attempts 3` observed no pending work at
that instant after the earlier shell consumer had caught up.

A subsequent continuous run observed a real newly recorded generation become
pending and commit through the relational path. Another observed cycle moved
from:

```text
102 discovered / 101 accepted / 1 pending
```

to:

```text
102 discovered / 102 accepted / 0 pending
```

after the one-record generation committed.

### Worker hardening status

The worker remains under Phase 3 acceptance and is not yet the packaged permanent
service, but the original runtime-hardening list has materially advanced.

Closed hardening items now include:

- durable PostgreSQL-backed `SOURCE_RECORD_REJECTED` retry state across worker
  restart;
- bounded READY-marker discovery for normal operational ingest;
- deterministic journal-driven rejected-generation retry ordering that does not
  allow deferred markers to starve later READY work;
- a hardened host-local singleton `flock()` acquired before PostgreSQL access;
- hard process restart recovery with unchanged relational state;
- durable rejected-generation reconstruction across independent worker
  processes; and
- controlled `SIGKILL` while a relational transaction was open, proving
  PostgreSQL rollback, retained `AttemptStarted` crash history, rediscovery of
  the immutable generation, and exactly-once later acceptance.

The singleton is intentionally local to one backend host. Phase 3 supports one
active backend ingest-worker host per deployment. This does not make Windows
source count part of the singleton contract; the current acceptance worker
remains explicitly source-scoped through `-source`, and final multi-source
backend topology is separate work. Cross-backend HA/failover requires a future
authoritative distributed lock or lease. PostgreSQL uniqueness is an integrity
backstop, not a distributed election mechanism.

The worker now also uses adaptive full operational repair reconciliation:
six clean hourly sweeps, one clean 12-hour sweep, then 24-hour steady-state
repair. Unexpected pending authority or conflict resets the cadence to hourly.
READY-notified pending work and durable source-record rejection state do not
reset repair confidence.

PostgreSQL reconnect/backoff behavior has completed controlled runtime
acceptance. Permanent service packaging remains open.

See `docs/PHASE-3-INGEST-WORKER-OPERATING-CONTRACT.md`.

### Adaptive repair runtime proof

The adaptive authoritative repair cadence completed isolated runtime acceptance on 2026-09-24 using the real ingest-worker candidate, isolated PostgreSQL instances, isolated custody roots, and exact immutable production generations.

The first case reduced only the validation interval to 200ms for controlled testing. After startup accepted one authoritative generation, six consecutive clean full operational repair sweeps transitioned the worker from Validation mode to Intermediate mode with a 12-hour interval and clean_count=6.

The second case established two clean validation sweeps and then introduced a second valid immutable recorder receipt and FIGT custody object without creating a READY marker. The full repair path reported discovered=2, accepted=1, pending=1, conflict=0, ready_notified=0, known_rejected=0, and unexpected_pending=1.

That same repair sweep ingested the generation exactly once and reset repair confidence to Validation mode with clean_count=0.

The production ingest worker, production PostgreSQL database, production custody, and production READY state were not modified by the test.

The 12-hour Intermediate-to-24-hour Steady transition remains covered by the repair-cadence unit test; no test-only production configuration surface was added solely to compress that real interval.

### PostgreSQL reconnect/backoff runtime proof

PostgreSQL reconnect/backoff completed isolated runtime acceptance on 2026-09-24
using the real ingest-worker candidate, isolated PostgreSQL clusters, isolated
custody/READY roots, and exact immutable production generations.

The startup-unavailable case proved that the worker acquired and retained its
host-local singleton while PostgreSQL was down, used bounded availability
backoff, rejected a second worker, then connected without a worker restart.
After PostgreSQL became available, the worker revalidated `fi_ingest`, database
`fi`, and the 49-table relational/security foundation before performing the
authoritative startup reconciliation. The pending immutable generation was then
accepted exactly once.

The live-session-loss case proved that the same worker PID survived PostgreSQL
loss and retained the singleton. While PostgreSQL was down, a second exact
immutable generation and READY marker were added to the isolated authority
tree. After PostgreSQL restarted, the same worker process reconnected, reset
repair confidence to Validation, and performed authoritative reconciliation
before READY processing resumed. The outage generation was accepted exactly
once; the subsequent READY pass observed it as already accepted and retired the
marker.

The controlled test used accelerated reconnect bounds of 200ms initial and
800ms maximum. Production defaults remain 1 second initial and 30 seconds
maximum.

The production ingest worker, production PostgreSQL database, production
custody, and production READY state were not modified by the test.

The campaign intentionally remains sequential. Parallel relational ingest is not
yet authorized.

## PostgreSQL campaign checkpoint

At 2026-09-20 16:07:12 -04:00, the fresh relational database reported:

```text
database_bytes        340,326,079
recorded_generation           105
source_batch                   167
source_record               93,195
ingest_journal                 214
```

Record-kind counts at that checkpoint were:

```text
CollectorIdentity               1
FileObservation             93,038
LocalPrincipalSnapshot          1
SMBShareSnapshot                1
WindowsSecurityCoverage       154
```

The journal state was:

```text
Accepted          AuthoritativeRecord    105
AlreadyAccepted   IdentityCheck            1
Incomplete        AttemptStarted         107
Rejected          AuthoritativeRecord      1
```

There were 107 started attempts and 107 terminal outcomes at that checkpoint.
The single rejected attempt was the known pre-fix content-prefix rejection; the
same real generation later committed successfully after the projector fix.

This checkpoint therefore showed no unmatched partial authority.

## Security-descriptor relationship check

A current-file query over latest unique NTFS file objects showed one owner and
one full raw security-descriptor pattern across the synthetic corpus at that
point in time:

```text
latest unique files:                 94,432
owner:                               BUILTIN\Administrators
security observation state:          Present
distinct raw descriptor byte values: 1
DACL revision:                        2
DACL size:                            112
DACL ACE count:                       4
```

The descriptor grouping used the full raw `bytea` value for equality; a display
MD5 was used only as a compact fingerprint and not as equality authority.

This uniformity is expected for the synthetic creation/inheritance context. It
is not a claim that production data should have one descriptor pattern.

## Record-kind authoritative proof

The relational projector supports all 13 current collector record kinds:

```text
CollectorIdentity
DirectoryPrincipalSnapshot
FileObservation
LocalPrincipalSnapshot
NTFSCollectionError
SMBShareSnapshot
SupportingSourceCollectionError
USNContinuityGap
USNObjectObservation
USNReadBoundary
WindowsSecurityContinuityGap
WindowsSecurityCoverage
WindowsSecurityEvent
```

Controlled authoritative receiver/database proofs now close all 13 supported
record kinds.

Notable controlled generations included:

```text
SupportingSourceCollectionError
  GenerationID: 20260920T155239.047010200Z-74b6ffee9f178062
  Source condition: controlled LDAP Server Down
  Result: exact relational acceptance

WindowsSecurityEvent
  GenerationID: 20260920T161438.962456500Z-5cf6e5d4fdbd9c6c
  Source condition: controlled audit-policy toggle
  Result: exact relational acceptance

USNContinuityGap
  Source: iss-fs-01.iss.local
  GenerationID: 20260920T224721.460692300Z-9b2a72230f46185b
  GovernedRoot: Y:\FI-Phase3-USNGap
  ReasonCode: JournalIDChanged
  CheckpointJournalID: 0
  CurrentJournalID: 134333792069841021
  CoverageState: Incomplete
  ReconciliationAction: CurrentStateBaselineAndUSNCatchUp
  TransferSHA256: 46b3887288b0458d120d15f395bfdb3c4edc820811473be202be070707cee385
  ReceiptSHA256: dec2b68b6c44074b4cb27f9ba46a8c761583bb586999c8961dcb0f2ffcdffd7c
  Result: exact relational acceptance
```

## USNContinuityGap authoritative proof

A dedicated controlled governed root was used for the gap test:

```text
Y:\FI-Phase3-USNGap
```

The accepted checkpoint was deliberately altered only in its Journal ID so FI
would encounter a controlled continuity mismatch.

FI then:

- detected `JournalIDChanged`;
- durably published the `USNContinuityGap` source record;
- reconciled to the actual current Journal ID;
- established a new forward `NextUSN`;
- transported the resulting record through normal Phase 2 generation custody;
- created the immutable recorder receipt; and
- materialized the exact typed Phase 3 relational record.

The authoritative relational row was materialized as:

```text
source_record_id: 238472
record_kind: USNContinuityGap
scope_id: root-e4e56e13ef412aa90bb5fe072db7ebcb
checkpoint_next_usn: 751243768
current_first_usn: 134217728
current_lowest_valid_usn: 0
current_next_usn: 751253000
```

After reconciliation the source checkpoint returned to the real journal and
advanced forward:

```text
JournalID: 134333792069841021
NextUSN:   751263488
```

At the receiver/database closure checkpoint:

```text
ReceiptsDiscovered: 263
AlreadyAccepted:    263
Pending:            0
Conflict:           0
```

The fresh relational database at that checkpoint contained eight of the 13
record kinds naturally produced by the active campaign. That corpus population
count is separate from authoritative record-family proof: controlled receiver /
database proofs now exist for all 13 supported kinds.

## Reconciliation contract

The supported read-only reconcile command starts from immutable recorder receipts.

For an already-authoritative generation, it verifies:

- receipt SHA-256;
- transfer SHA-256;
- declared batch/data-byte/record totals;
- actual source-batch count;
- actual source-record byte total;
- actual source-record count; and
- zero missing typed projections.

A mismatch is a `Conflict`; a missing authoritative generation is `Pending`.

Inventory mode reopens only pending exact generations through the same FI custody
loader and reports record-kind coverage. Both modes report zero database writes.

## Remaining Gate 3 acceptance work

The campaign is not complete until the following remaining work is closed:

- finish the fresh 250K relational ingest/catch-up closeout;
- package/deploy the permanent worker only after the remaining hardening gates
  pass;
- run the final authoritative reconcile with `Pending=0` and `Conflict=0`; and
- compare final generation, batch, source-record, database-size, and journal
  totals.

The earlier durable-retry, bounded discovery, rejection ordering, host-local
singleton, ordinary restart, durable-rejection restart, in-transaction crash
recovery, adaptive repair, and PostgreSQL reconnect/backoff items are closed.

Distributed backend locking is documented as a future HA/failover requirement,
not a current Gate 3 blocker, because Phase 3 authorizes one active backend
ingest-worker host per deployment.

## Acceptance rule

Phase 3 / Gate 3 must not be declared complete merely because PostgreSQL contains
rows or the current worker is keeping up.

Closure requires the authority chain, relational relationships, journal outcomes,
recovery semantics, all supported record kinds, and the permanent ingest runtime
to remain reconstructable and unambiguous under the accepted failure cases.
