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

### Worker acceptance limits

The worker is validated for the current campaign but is not yet the permanent
production service.

Known hardening items:

1. source-record rejection cooldown is in memory and is lost on worker restart;
2. `PlanRecordedGenerations` currently scans the recorded receipt root each
   polling cycle rather than using bounded/incremental discovery;
3. long-term ordering policy for bypassing a rejected generation still needs an
   explicit product contract;
4. singleton/advisory locking is not implemented; and
5. database failure/backoff behavior still needs final production supervisor
   treatment.

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

Before the fresh 250K database reset, controlled authoritative proofs had closed
12 of the 13 kinds.

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
```

The only outstanding record-kind receiver/database proof is:

```text
USNContinuityGap
```

## USNContinuityGap source-side proof

A dedicated controlled governed root was used for the gap test:

```text
Y:\FI-Phase3-USNGap
```

The accepted checkpoint was deliberately altered only in its Journal ID so FI
would encounter a controlled continuity mismatch.

FI then:

- detected the continuity condition;
- recorded the gap/baseline/catch-up source behavior;
- reconciled to the actual current Journal ID;
- established a new forward `NextUSN`; and
- completed all configured roots.

That closes the source-side behavior required for the record kind.

The final Gate 3 task for this kind is to carry the resulting real
`USNContinuityGap` generation through receiver custody and the relational
materialization path. The source fault must not be repeated merely because the
backend proof is still open.

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

The campaign is not complete until the following are closed:

- finish the fresh 250K relational ingest/catch-up run;
- final reconcile: every discovered accepted corpus receipt accepted,
  `Pending=0`, `Conflict=0`;
- compare final generation, batch, source-record, database-size, and journal
  totals;
- close the final `USNContinuityGap` receiver/database proof;
- persist rejection retry suppression across worker restart;
- implement bounded/incremental receipt discovery;
- formalize rejected-generation ordering/bypass behavior;
- add singleton/advisory locking;
- accept production database failure/backoff behavior;
- test PostgreSQL outage while receiver custody continues;
- test worker restart during representative ingest;
- test restart during a transaction and eventual catch-up; and
- package/deploy the permanent worker only after those hardening gates pass.

## Acceptance rule

Phase 3 / Gate 3 must not be declared complete merely because PostgreSQL contains
rows or the current worker is keeping up.

Closure requires the authority chain, relational relationships, journal outcomes,
recovery semantics, all supported record kinds, and the permanent ingest runtime
to remain reconstructable and unambiguous under the accepted failure cases.
