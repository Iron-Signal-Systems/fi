# Phase 3 — 250K Relational Ingest Acceptance

## Status

**COMPLETE — PASS — Phase 3 / Gate 3**

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

No PostgreSQL tuning conclusion is drawn from this early timing. At this early
checkpoint, the campaign was validating correctness, authority, recovery, and
representative behavior before deciding whether database tuning was necessary.

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

At this checkpoint, the live acceptance consumer was the Go command:

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

At this intermediate acceptance checkpoint, the worker remained under Phase 3
acceptance and had not yet been packaged as the permanent service. The later
sections in this record preserve the subsequent permanent-service acceptance and
final Gate 3 closeout.

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
source count part of the singleton contract; the worker used for this acceptance
remained explicitly source-scoped through `-source`, and final multi-source
backend topology is separate work. Cross-backend HA/failover requires a future
authoritative distributed lock or lease. PostgreSQL uniqueness is an integrity
backstop, not a distributed election mechanism.

The worker now also uses adaptive full operational repair reconciliation:
six clean hourly sweeps, one clean 12-hour sweep, then 24-hour steady-state
repair. Unexpected pending authority or conflict resets the cadence to hourly.
READY-notified pending work and durable source-record rejection state do not
reset repair confidence.

PostgreSQL reconnect/backoff behavior has completed controlled runtime
acceptance. Permanent Linux ingest-worker service packaging has also completed
controlled runtime acceptance.

See `docs/PHASE-3-INGEST-WORKER-OPERATING-CONTRACT.md`.

### Permanent systemd service runtime proof

Permanent Linux ingest-worker service packaging completed controlled runtime
acceptance on 2026-09-24 on `fi-receiver-a`.

The accepted service runs as `fi-receiver`, uses
`/opt/fi/bin/fi-ingest-worker`, receives its source ID from
`/etc/fi/fi-ingest-worker.env`, and uses a systemd-owned `/run/fi` runtime
directory with mode `0700`. The unit is enabled for boot and uses
`Restart=on-failure`, a five-second restart delay, and a bounded systemd start
limit. PostgreSQL availability remains owned by the worker's internal reconnect
state machine rather than by a hard systemd database dependency.

The first controlled manual-to-systemd cutover intentionally remains part of the
acceptance history because it exposed a real lock-namespace lifecycle defect.
The original manually launched worker still held
`/run/fi/fi-ingest-worker.lock`. The first systemd service start correctly
failed on the host-local singleton, but the failed unit then removed
`RuntimeDirectory=/run/fi`. The manual worker continued holding the now-unlinked
lock inode. A subsequent systemd restart recreated `/run/fi`, acquired a new
pathname/inode, connected to PostgreSQL, and reconciled successfully while the
old manual worker still existed.

No READY work was present during that overlap, and the systemd worker reported
`discovered=1280 accepted=1280 pending=0 conflict=0`, but the event proved that
runtime-directory deletion could defeat the pathname-based same-host singleton
boundary.

The service contract was corrected with:

```text
RuntimeDirectory=fi
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
```

The corrected cutover then stopped the manual worker with the required service
identity/root authority, proved no ingest worker remained during the ownership
gap, and started the permanent systemd worker. The service created the expected
`fi-receiver:fi-receiver` `0700` runtime directory, acquired the singleton,
validated the 49-table PostgreSQL foundation, entered Validation repair mode,
and reported:

```text
discovered=1280
accepted=1280
pending=0
conflict=0
```

A real generation arriving immediately after corrected cutover was accepted once
with 11 records committed and the READY queue returned to zero.

Unexpected-process-death acceptance killed the permanent worker with `SIGKILL`.
Systemd recorded the signal failure, waited five seconds, restarted the worker,
and incremented the restart counter exactly once. The lock-file inode remained
stable at `8122` across the crash/restart. The replacement worker revalidated
PostgreSQL, reset repair confidence to Validation, and reported:

```text
discovered=1281
accepted=1281
pending=0
conflict=0
```

PostgreSQL-unavailable startup acceptance used a temporary service override
pointing the worker at a closed local TCP port while the real FI PostgreSQL
instance remained untouched. The same worker PID stayed active, systemd restart
count remained zero, the lock inode remained `8122`, and the worker's internal
availability backoff progressed through 1, 2, 4, and 8 seconds. This proved that
systemd owns process failure while the worker owns database availability.

Permanent-failure acceptance used a temporary invalid PostgreSQL configuration.
The actual observed PostgreSQL failure was authentication SQLSTATE `28000`; it
remained fail-closed and did not enter the availability retry loop. Systemd
performed three bounded restart attempts and then reached
`Result=start-limit-hit`. The lock inode remained `8122`, and the real FI
database remained healthy.

After the temporary failure override was removed, the permanent worker returned
to the real PostgreSQL database and reconciled:

```text
discovered=1341
accepted=1341
pending=0
conflict=0
```

Finally, an explicit operator `systemctl stop` exited cleanly with no automatic
restart. The runtime lock inode remained `8122` while the service was stopped.
A later explicit `systemctl start` created a new worker PID without changing the
lock inode, revalidated PostgreSQL, and again reported
`discovered=1341 accepted=1341 pending=0 conflict=0`.

At the end of permanent-service acceptance:

```text
service state         active/running
service enabled       yes
database_bytes        1,705,948,863
recorded_generation   1,341
source_batch           7,073
source_record        512,010
ingest_journal         2,686
READY markers              0
```

These are live acceptance checkpoint values, not the final Gate 3 relational
totals.

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

## Post-Gate-3 collection-method version-skew characterization — 2026-09-25

This characterization is supplemental to the 2026-09-24 Gate 3 closeout. It
does not replace or rewrite the accepted Gate 3 totals.

A Windows source running the FIObjReader-compatible collector produced immutable
generation:

```text
20260925T204756.233378900Z-3ee88f52f943e90f
```

The installed receiver worker predated the
`BackupAuthorityWindowsNTFS` collection method. Its strict nested
`USNObjectObservation` validation rejected the generation at the
`AuthoritativeRecord` stage with:

```text
SOURCE_RECORD_REJECTED
validate FI USN nested NTFS observation:
UnsupportedValue: collection_method
```

The rejected attempt committed zero authoritative source records. FI retained
the immutable recorder receipt and FIGT custody object, and the durable
`SOURCE_RECORD_REJECTED` retry state prevented immediate uncontrolled retry.

A compatible worker built from the FIObjReader branch was then installed. Its
startup reconciliation found the retained generation as the single pending item
and honored the existing retry delay rather than bypassing durable retry state.

At 2026-09-25 17:03:18 -04:00, the worker retried that same immutable
generation and accepted it atomically:

```text
records_seen:       20
records_committed:  20
outcome:            Accepted
```

The earlier rejection remained in the append-only ingest journal; later success
did not overwrite or erase the failed attempt.

This proves the intended version-skew behavior for this case:

```text
new producer semantic value
        |
        v
older strict receiver rejects fail-closed
        |
        v
zero authoritative partial commit
        |
        v
immutable generation custody retained
        |
        v
durable SOURCE_RECORD_REJECTED retry state retained
        |
        v
compatible receiver installed
        |
        v
same immutable generation accepted atomically
```

The result does **not** authorize permissive handling of unknown enum-like
values. `collection_method` remains strict source semantics even though the
PostgreSQL column is `text`. Producer additions to enum-like source semantics
must add receiver validation/regression coverage and be deployed with receiver
compatibility established before or with the producer rollout.

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

## Gate 3 closeout

The fresh relational campaign, permanent runtime acceptance, final authoritative
reconciliation, and final totals review are complete.

Distributed backend locking remains a future HA/failover requirement rather than
a Gate 3 blocker because the accepted Phase 3 topology authorizes one active
backend ingest-worker host per deployment.

## Acceptance rule

Phase 3 / Gate 3 must not be declared complete merely because PostgreSQL contains
rows or the current worker is keeping up.

Closure requires the authority chain, relational relationships, journal outcomes,
recovery semantics, all supported record kinds, and the permanent ingest runtime
to remain reconstructable and unambiguous under the accepted failure cases.

## Final Gate 3 authoritative closeout

Gate 3 closed on 2026-09-24 at the timestamped acceptance checkpoint:

```text
2026-09-24T17:56:27-04:00
```

The final read-only reconciliation was deliberately run without a source filter.
It therefore compared all immutable recorder receipts visible to the accepted
backend against PostgreSQL authority rather than assuming that only the current
acceptance source existed.

Final authoritative reconciliation:

```text
ReceiptsDiscovered: 1342
AlreadyAccepted:    1342
Pending:            0
Conflict:           0
```

The database contained one recorded source at that checkpoint:

```text
iss-fs-01.iss.local=1342
```

Final relational totals:

```text
database_bytes       1,705,965,247
recorded_generation  1,342
source_batch          7,085
source_record       512,022
ingest_journal        2,688
READY markers             0
```

Final source-record kind counts naturally present in the live relational
campaign:

```text
CollectorIdentity=180
DirectoryPrincipalSnapshot=179
FileObservation=504067
LocalPrincipalSnapshot=180
NTFSCollectionError=1
SMBShareSnapshot=180
USNContinuityGap=1
USNObjectObservation=2
USNReadBoundary=1
WindowsSecurityCoverage=6835
WindowsSecurityEvent=396
```

Those counts sum exactly to `512022` source records. The two supported kinds not
naturally present in this final live corpus,
`SupportingSourceCollectionError` and `WindowsSecurityContinuityGap`, remain
covered by the separate authoritative 13/13 record-kind acceptance proof and are
not reclassified as missing support.

Final ingest-journal outcomes:

```text
Accepted=1342
AlreadyAccepted=1
Incomplete=1344
Rejected=1
```

Final ingest-journal stages:

```text
AttemptStarted=1344
AuthoritativeRecord=1343
IdentityCheck=1
```

The journal totals sum to `2688`. `AuthoritativeRecord=1343` is exactly the
accepted plus rejected authoritative terminal history (`1342 + 1`). Earlier
incomplete attempt history remains preserved rather than being overwritten by
later successful recovery.

The permanent service was active/running and enabled at closeout. The accepted
service contract includes host-local singleton protection, preserved runtime-lock
namespace, bounded systemd restart behavior, PostgreSQL in-process
reconnect/backoff, fail-closed permanent database/configuration errors, and clean
operator stop/start behavior.

This final checkpoint closes the Phase 3 question: every immutable recorder
receipt visible to the accepted backend was represented by unambiguous
relational authority, with zero pending work, zero conflict, and zero READY
backlog.
