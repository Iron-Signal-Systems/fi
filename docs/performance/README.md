# Performance Measurement

FI measures resource use before performance thresholds are established. Performance observation is diagnostic engineering data, not authoritative file history and not a release gate.

## Real NTFS collection

Build FI normally, then run the collector against a representative governed root:

```powershell
go build -o .\cmd\fi\fi.exe .\cmd\fi
.\cmd\fi\fi.exe -perf-root "C:\Path\To\Representative\Tree"
```

`-perf-root` uses the same `ntfs.WalkGovernedRoot` and `ntfs.CollectPath` path as normal recursive collection. It does not emit each object record. Instead it emits one JSON resource report containing:

- elapsed time, objects/second, and files/second;
- files, directories, reparse objects, and stream counts;
- Complete, Partial, ChangedDuringCollection, and ReplacedDuringCollection counts;
- warning-code and collection-error-stage counts;
- process CPU time, current and peak working set, and private bytes;
- Go heap, allocation, garbage-collection, and goroutine observations;
- Windows, Go, CPU-count, host, VCS revision, and governed-root/volume identity context.

The report states:

```text
Resource observation: RECORDED
Performance thresholds: NOT_EVALUATED
```

until representative same-environment measurements exist and a real operational threshold is intentionally defined.

To retain a report during development, redirect the JSON output:

```powershell
.\cmd\fi\fi.exe -perf-root "C:\Path\To\Representative\Tree" `
  > .\docs\performance\results\server2016-representative.json
```

## Focused Go benchmarks

The Windows NTFS benchmark file measures nearby syscall-sensitive paths separately from the full collector run, including ordinary files, ADS-heavy files, native state queries, stream enumeration, containment rejection, and a synthetic recursive tree.

From `go\`:

```powershell
go test ./internal/windows/ntfs -run '^$' -bench '^Benchmark' -benchmem -count 3
```

Do not optimize against one machine or one run. Record measurements first and compare only like workloads on like environments.
