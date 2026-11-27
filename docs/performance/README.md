# Performance Measurement

FI measures source impact before production thresholds are established.

Performance/resource observations are engineering and operational data. They do
not replace authoritative file/source history.

Gate 1 requires source impact to remain bounded and measurable, but FI does not
invent performance thresholds before representative measurements exist.

## Real NTFS collection

From the repository `go` directory:

```powershell
go build -o .\fi.exe .\cmd\fi
.\fi.exe -perf-root "C:\Path\To\Representative\Tree"
```

`-perf-root` uses the same `ntfs.WalkGovernedRoot` and `ntfs.CollectPath` path as
normal recursive collection. It does not emit every object record. Instead it
emits one JSON resource report containing:

- elapsed time, objects/second, and files/second;
- files, directories, reparse objects, and stream counts;
- Complete, Partial, ChangedDuringCollection, and ReplacedDuringCollection
  counts;
- warning-code and collection-error-stage counts;
- process CPU time, current and peak working set, and private bytes;
- Go heap, allocation, garbage-collection, and goroutine observations; and
- Windows, Go, CPU-count, host, VCS revision, and governed-root/volume identity
  context.

The report states:

```text
Resource observation: RECORDED
Performance thresholds: NOT_EVALUATED
```

until representative same-environment measurements exist and a real operational
threshold is intentionally defined.

To retain a report during development:

```powershell
.\fi.exe -perf-root "C:\Path\To\Representative\Tree" `
  > .\docs\performance\results\server2016-representative.json
```

## Operation resource journal

FI also has a separate process-resource journal associated with journaled USN
operations.

The operation lifecycle journal answers whether a bounded operation Started,
Completed, Failed, or was Interrupted.

The resource journal answers how the FI process used CPU/RAM/I/O while that
operation ran.

Those are separate concerns and should remain separate.

Resource-journal coverage can be expanded where useful for sizing and pilot
validation, but broad resource instrumentation is not a reason to wrap every
internal function in lifecycle records.

## Focused Go benchmarks

The Windows NTFS benchmark file measures nearby syscall-sensitive paths
separately from the full collector run, including ordinary files, ADS-heavy
files, native state queries, stream enumeration, containment rejection, and a
synthetic recursive tree.

From `go\`:

```powershell
go test ./internal/windows/ntfs -run '^$' -bench '^Benchmark' -benchmem -count 3
```

## Gate 1 performance campaign status

The Server 2016 Gate 1 campaign has completed the first bounded Gate 1
performance/source-impact campaign:

- Test 13 — repeated real `-perf-root` baseline measurements;
- Test 14 — bounded churn characterization;
- Test 15 — bounded spool-pressure characterization; and
- Test 16 — immutable operation/resource-journal summary.

These results establish bounded, measurable behavior for the tested Server 2016
acceptance workloads. They are not production sizing guidance and do not establish
production collection or supporting-source refresh intervals.

Before production cadence is accepted, continue repeated representative
measurement of:

- initial baseline;
- normal low-churn configured runs;
- high-churn USN catch-up;
- Security activity volume, retained-log margin, and independent-worker catch-up;
- supporting-source refresh;
- gap reconciliation;
- CPU/RAM/I/O;
- spool growth; and
- recovery after interruption.

Record the environment, exact FI executable hash, governed-root size/object
count, and source workload.

Gate 1 does not declare one universal production cadence. Do not optimize against one machine
or one run. Compare like workloads on like environments before defining
thresholds or production defaults.

## Final Phase 1 / Gate 1 source-impact acceptance

The final onboarding campaign used `100,000` files totaling `122.344 GiB`.

```text
ConfiguredCollection:        Complete
Collection elapsed:          10,048.082 sec
Peak whole-host CPU:         36.91 %
Peak combined FI CPU:        11.14 % of host
Peak combined FI RAM:        36.21 MiB
Minimum host available RAM:  7,069.99 MiB
Peak host memory load:       21.00 %
Peak Y: logical read:        34.842 MiB/s
Peak Y: logical write:       0.723 MiB/s
Peak observed Y: queue:       3
Spool files:                 6,320
Spool bytes:                 870,946,901
Manifest record count:       202,012
```

These are measurements from the tested environment, not universal production
limits.

The accepted operating principle is that host availability and durable FI state
take priority over maintaining nominal FI cadence.

See `PHASE-1-GATE-1-CLOSEOUT.md`.


## Post-Gate-1 250K randomized nested onboarding and resilience campaign

The 250K campaign was executed beginning 2026-09-19 as additional Phase 2
characterization. It does not replace or rewrite the accepted 100K Gate 1 result.

The generator created 250,000 payload files in 20,000 directories with maximum
depth 15. Four deliberate manual semantic-validation probes were later introduced
under the governed root, producing a live count of 250,004 files.

The strict clean onboarding acceptance was intentionally interrupted during fault
injection and is therefore **not a clean 250K PASS**.

The retained campaign validated receiver-outage backlog retention/recovery,
sender interruption recovery, collector interruption history, governed-source
zero-free behavior, source-host CPU/RAM/I/O impact, cross-root independent USN
scheduling after remediation in `41906af`, and later independent Windows
Security scheduling after the campaign exposed that Security catch-up could be
stranded behind multi-hour root work.

During recovery from the one-hour receiver outage, host CPU averaged 9.946% and
combined FI CPU averaged 7.626%, essentially unchanged from the surrounding
250K workload. The measured recovery did not create a source-server CPU, memory,
or logical-volume recovery storm.

See:

- `PHASE-2-250K-RANDOM-NESTED-ONBOARDING-PLAN.md`
- `PHASE-2-250K-RANDOM-NESTED-ONBOARDING-REPORT.md`
- `PHASE-2-WINDOWS-SECURITY-WORKER-VALIDATION.md`
- `PHASE-2-GATE-2-CLOSEOUT.md`

## Phase 3 fresh relational 250K acceptance campaign — COMPLETE

Phase 3 used the active 250K corpus for a **separate backend acceptance
campaign**. This does not convert the interrupted Phase 2 source-side campaign
into a clean onboarding PASS.

The Phase 3 campaign deliberately emptied the 49-table relational PostgreSQL
schema and then re-materialized immutable recorder-authorized generations through
the typed relational ingest path.

The campaign began on 2026-09-20 and completed on 2026-09-24.

```text
Phase 3 / Gate 3:                         COMPLETE — PASS
Authoritative record-kind proof:          13/13 PASS
USNContinuityGap receiver/DB proof:       PASS
Permanent Linux ingest-worker service:    PASS
PostgreSQL reconnect/backoff:             PASS
Final pending recorder receipts:          0
Final relational conflicts:               0
Final READY backlog:                      0
```

The campaign proved:

- generation-atomic relational ingest;
- exact receipt/FIGT identity binding;
- batch, byte, and record total reconciliation;
- typed-projection completeness;
- append-only ingest-journal balance;
- duplicate-safe `AlreadyAccepted` behavior;
- rejected-generation rollback and durable retry ordering;
- real-file relationship reconstruction;
- valid zero-byte `ContentPrefix` handling;
- all 13 supported record kinds;
- bounded READY-marker operational discovery;
- host-local singleton protection;
- restart/crash recovery;
- adaptive authoritative operational repair;
- PostgreSQL availability reconnect/backoff; and
- permanent systemd service behavior.

An intermediate checkpoint recorded on 2026-09-20 showed:

```text
recorded_generation    105
source_batch            167
source_record        93,195
database_bytes     340,326,079
```

At that checkpoint the ingest journal contained 107 started attempts and 107
terminal outcomes, including 105 `Accepted`, one idempotent `AlreadyAccepted`,
and one known pre-fix source-record `Rejected` attempt. No partial relational
authority remained from the rejected generation.

A real formerly failing generation was re-run after the content-prefix correction
and committed 7,167 / 7,167 records successfully. The database then contained a
real `Present` content-prefix observation with zero bytes observed and an empty
prefix, and zero observed prefix-length mismatches.

`USNContinuityGap` subsequently completed authoritative receiver/database
materialization proof, closing supported record-kind coverage at 13/13.

The final unfiltered authoritative reconciliation on 2026-09-24 reported:

```text
ReceiptsDiscovered: 1342
AlreadyAccepted:    1342
Pending:            0
Conflict:           0

recorded_generation  1,342
source_batch          7,085
source_record       512,022
ingest_journal        2,688
READY markers             0
```

The final live relational corpus naturally contained 11 of the 13 supported
record kinds. `SupportingSourceCollectionError` and
`WindowsSecurityContinuityGap` remain covered by their separate authoritative
record-kind acceptance proofs and are not reclassified as missing support.

See `PHASE-3-250K-RELATIONAL-INGEST-ACCEPTANCE.md` for the authoritative Gate 3
acceptance and closeout record.
