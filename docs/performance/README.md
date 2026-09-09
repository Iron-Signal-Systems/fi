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
- Security activity volume;
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
