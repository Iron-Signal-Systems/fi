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

## Gate 1 performance campaign still required

Before Gate 1 acceptance, measure representative:

- initial baseline;
- normal low-churn configured runs;
- high-churn USN catch-up;
- Security activity volume;
- gap reconciliation;
- CPU/RAM/I/O;
- spool growth; and
- recovery after interruption.

Run repeated comparable workloads. Record the environment, FI executable hash,
governed-root size/object count, and source workload.

Do not optimize against one machine or one run. Compare like workloads on like
environments before defining thresholds.
