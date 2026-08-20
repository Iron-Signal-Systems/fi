# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this source code is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [string]$Label = "manual",

    [ValidateRange(1, 20)]
    [int]$Iterations = 3,

    [ValidateRange(1, 20)]
    [int]$BenchmarkCount = 3,

    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"

function Get-SafeName {
    param([string]$Value)
    $safe = $Value -replace '[^A-Za-z0-9._-]', '-'
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return "baseline"
    }
    return $safe
}

function Get-Mean {
    param([double[]]$Values)
    if ($Values.Count -eq 0) {
        return 0.0
    }
    return ($Values | Measure-Object -Average).Average
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptRoot "..\..")).Path
$goRoot = Join-Path $repoRoot "go"
$resolvedRoot = (Resolve-Path $Root).Path

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot "docs\performance\results"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$binary = Join-Path $env:TEMP ("fi-perf-{0}.exe" -f $PID)
$results = @()
$benchmarkOutput = @()

try {
    Push-Location $goRoot
    try {
        & go build -o $binary ./cmd/fi
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed with exit code $LASTEXITCODE"
        }

        $goVersion = (& go version | Out-String).Trim()
        $commit = (& git rev-parse HEAD 2>$null | Out-String).Trim()
        if (-not $commit) {
            $commit = "NotKnown"
        }

        $benchmarkOutput = & go test ./internal/windows/ntfs -run '^$' -bench '^Benchmark' -benchmem -count $BenchmarkCount 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Go benchmark run failed with exit code $LASTEXITCODE`n$($benchmarkOutput -join [Environment]::NewLine)"
        }
    }
    finally {
        Pop-Location
    }

    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        $stdout = Join-Path $env:TEMP ("fi-perf-{0}-{1}.jsonl" -f $PID, $iteration)
        $stderr = Join-Path $env:TEMP ("fi-perf-{0}-{1}.stderr" -f $PID, $iteration)

        try {
            $argumentRoot = '"' + $resolvedRoot.Replace('"', '\"') + '"'
            $arguments = @("-walk-root", $argumentRoot)

            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $process = Start-Process `
                -FilePath $binary `
                -ArgumentList $arguments `
                -RedirectStandardOutput $stdout `
                -RedirectStandardError $stderr `
                -NoNewWindow `
                -PassThru
            $process.WaitForExit()
            $stopwatch.Stop()
            $process.Refresh()

            $objects = 0
            $files = 0
            $directories = 0
            $errors = 0
            $complete = 0
            $partial = 0
            $changed = 0
            $replaced = 0
            $namedStreams = 0

            foreach ($line in [System.IO.File]::ReadLines($stdout)) {
                $objects++
                if ($line.Contains('"subject_kind":"File"')) { $files++ }
                if ($line.Contains('"subject_kind":"Directory"')) { $directories++ }
                if ($line.Contains('"error":')) { $errors++ }
                if ($line.Contains('"observation_status":"Complete"')) { $complete++ }
                if ($line.Contains('"observation_status":"Partial"')) { $partial++ }
                if ($line.Contains('"observation_status":"ChangedDuringCollection"')) { $changed++ }
                if ($line.Contains('"observation_status":"ReplacedDuringCollection"')) { $replaced++ }
                $namedStreams += ([regex]::Matches($line, '"kind":"NamedData"')).Count
            }

            $seconds = $stopwatch.Elapsed.TotalSeconds
            $objectsPerSecond = 0.0
            $filesPerSecond = 0.0
            if ($seconds -gt 0) {
                $objectsPerSecond = $objects / $seconds
                $filesPerSecond = $files / $seconds
            }

            $stderrText = ""
            if (Test-Path $stderr) {
                $stderrText = [System.IO.File]::ReadAllText($stderr).Trim()
            }

            $results += [pscustomobject]@{
                Iteration        = $iteration
                ExitCode         = $process.ExitCode
                Seconds          = $seconds
                Objects          = $objects
                Files            = $files
                Directories      = $directories
                ObjectsPerSecond = $objectsPerSecond
                FilesPerSecond   = $filesPerSecond
                PeakWorkingSetMB = $process.PeakWorkingSet64 / 1MB
                CPUSeconds       = $process.TotalProcessorTime.TotalSeconds
                Errors           = $errors
                Complete         = $complete
                Partial          = $partial
                Changed          = $changed
                Replaced         = $replaced
                NamedStreams     = $namedStreams
                StandardError    = $stderrText
            }
        }
        finally {
            Remove-Item -Force -ErrorAction SilentlyContinue $stdout, $stderr
        }
    }

    $processor = "NotKnown"
    $memoryGB = "NotKnown"
    try {
        $processor = ((Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name) -join "; ").Trim()
        $totalMemory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
        $memoryGB = "{0:N2}" -f ($totalMemory / 1GB)
    }
    catch {
    }

    $fileSystem = "NotKnown"
    try {
        $rootPath = [System.IO.Path]::GetPathRoot($resolvedRoot)
        if ($rootPath -match '^[A-Za-z]:\\$') {
            $driveLetter = $rootPath.Substring(0, 1)
            $fileSystem = (Get-Volume -DriveLetter $driveLetter).FileSystem
        }
    }
    catch {
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
    $fileStamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $safeLabel = Get-SafeName $Label
    $reportPath = Join-Path $OutputDirectory ("{0}-{1}.md" -f $fileStamp, $safeLabel)

    $meanObjectsPerSecond = Get-Mean ([double[]]($results | ForEach-Object { $_.ObjectsPerSecond }))
    $meanFilesPerSecond = Get-Mean ([double[]]($results | ForEach-Object { $_.FilesPerSecond }))
    $meanPeakMemory = Get-Mean ([double[]]($results | ForEach-Object { $_.PeakWorkingSetMB }))
    $meanCPU = Get-Mean ([double[]]($results | ForEach-Object { $_.CPUSeconds }))

    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("# FI Windows NTFS Performance Baseline")
    $report.Add("")
    $report.Add("This is a measurement record, not a performance gate.")
    $report.Add("")
    $report.Add("## Environment")
    $report.Add("")
    $report.Add("- Label: ``$Label``")
    $report.Add("- Recorded UTC: ``$timestamp``")
    $report.Add("- Computer: ``$env:COMPUTERNAME``")
    $report.Add("- OS: ``$([System.Environment]::OSVersion.VersionString)``")
    $report.Add("- Processor: ``$processor``")
    $report.Add("- Logical processors: ``$([System.Environment]::ProcessorCount)``")
    $report.Add("- Physical memory GiB: ``$memoryGB``")
    $report.Add("- Filesystem: ``$fileSystem``")
    $report.Add("- Go: ``$goVersion``")
    $report.Add("- FI commit: ``$commit``")
    $report.Add("- Governed root: ``$resolvedRoot``")
    $report.Add("")
    $report.Add("## Recursive collection")
    $report.Add("")
    $report.Add("| Run | Exit | Seconds | Objects | Files | Dirs | Objects/s | Files/s | Peak MiB | CPU s | Errors | Complete | Partial | Changed | Replaced | Named ADS |")
    $report.Add("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")

    foreach ($result in $results) {
        $report.Add(("| {0} | {1} | {2:N3} | {3} | {4} | {5} | {6:N1} | {7:N1} | {8:N2} | {9:N3} | {10} | {11} | {12} | {13} | {14} | {15} |" -f `
            $result.Iteration,
            $result.ExitCode,
            $result.Seconds,
            $result.Objects,
            $result.Files,
            $result.Directories,
            $result.ObjectsPerSecond,
            $result.FilesPerSecond,
            $result.PeakWorkingSetMB,
            $result.CPUSeconds,
            $result.Errors,
            $result.Complete,
            $result.Partial,
            $result.Changed,
            $result.Replaced,
            $result.NamedStreams))
    }

    $report.Add("")
    $report.Add("### Mean")
    $report.Add("")
    $report.Add(("- Objects/s: **{0:N1}**" -f $meanObjectsPerSecond))
    $report.Add(("- Files/s: **{0:N1}**" -f $meanFilesPerSecond))
    $report.Add(("- Peak working set MiB: **{0:N2}**" -f $meanPeakMemory))
    $report.Add(("- CPU seconds: **{0:N3}**" -f $meanCPU))
    $report.Add("")

    $stderrRuns = $results | Where-Object { -not [string]::IsNullOrWhiteSpace($_.StandardError) }
    if ($stderrRuns.Count -gt 0) {
        $report.Add("## Standard error")
        $report.Add("")
        foreach ($result in $stderrRuns) {
            $report.Add("### Run $($result.Iteration)")
            $report.Add("")
            $report.Add('```text')
            $report.Add($result.StandardError)
            $report.Add('```')
            $report.Add("")
        }
    }

    $report.Add("## Go NTFS micro/synthetic benchmarks")
    $report.Add("")
    $report.Add("The benchmark suite measures plain-file collection, ADS-heavy collection, native state queries, stream enumeration, governed-root rejection, and a 1,000-file recursive walk.")
    $report.Add("")
    $report.Add('```text')
    foreach ($line in $benchmarkOutput) {
        $report.Add([string]$line)
    }
    $report.Add('```')
    $report.Add("")

    [System.IO.File]::WriteAllLines($reportPath, $report, [System.Text.UTF8Encoding]::new($false))

    Write-Host "FI baseline written to: $reportPath"
    Write-Host ("Mean objects/s: {0:N1}" -f $meanObjectsPerSecond)
    Write-Host ("Mean files/s:   {0:N1}" -f $meanFilesPerSecond)
    Write-Host ("Mean peak MiB:  {0:N2}" -f $meanPeakMemory)
}
finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $binary
}
