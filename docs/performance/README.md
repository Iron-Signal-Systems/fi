# Performance Measurement

FI records baseline performance so later engineering changes can be compared to known measurements. These numbers are measurements, not release gates or optimization targets.

## Windows NTFS baseline

Run from the repository root on a representative NTFS system:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\perf\windows-baseline.ps1 `
  -Root "C:\Path\To\Representative\Tree" `
  -Label "server2016-representative"
```

The script:

- builds the current `fi.exe`;
- runs `-walk-root` three times by default;
- records objects, files, directories, elapsed time, objects/second, files/second, peak working set, process CPU time, collection errors, observation states, and named ADS count;
- runs the Windows NTFS Go benchmark suite with `-benchmem`;
- writes one Markdown report under `docs/performance/results/`.

The Go benchmark suite contains focused measurements for:

- plain-file `CollectPath`;
- ADS-heavy `CollectPath` with 32 named streams;
- `queryNativeState`;
- default-only stream enumeration;
- ADS-heavy stream enumeration;
- governed-root sibling rejection;
- recursive collection of a synthetic 1,000-file tree.

Run only the Go benchmarks from `go\` with:

```powershell
go test ./internal/windows/ntfs -run '^$' -bench '^Benchmark' -benchmem -count 3
```

Do not optimize against one machine or one run. Record the baseline first, then compare later changes under the same dataset and environment.
