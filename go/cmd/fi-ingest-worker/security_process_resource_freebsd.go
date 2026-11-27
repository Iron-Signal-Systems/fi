// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"fmt"
	"math"
	"syscall"
	"time"
)

// fiProcessResourceSnapshot captures FreeBSD RUSAGE_SELF counters and a
// monotonic timestamp. These measurements belong to the WHOLE worker process,
// not one source, PostgreSQL session, or jail. In concurrent-source mode they
// must never be used as per-source adaptive capacity evidence.
//
// FreeBSD's ru_maxrss is the process-lifetime resident high-water in KiB;
// it is NOT the RSS peak of only the most recent generation.
type fiProcessResourceSnapshot struct {
	At                   time.Time
	CPUTime              time.Duration
	LifetimePeakRSSBytes uint64
}

// fiProcessResourceDelta is read-only, best-effort operational telemetry.
// EquivalentCores is process CPU seconds divided by elapsed wall seconds.
// It is NOT CPUFraction: a correct adaptive pressure ratio additionally needs
// a verified effective CPU allowance for this worker/jail.
type fiProcessResourceDelta struct {
	Elapsed              time.Duration
	CPUTime              time.Duration
	EquivalentCores      float64
	LifetimePeakRSSBytes uint64
}

func fiTimevalDuration(v syscall.Timeval) (time.Duration, error) {
	sec := int64(v.Sec)
	usec := int64(v.Usec)
	if sec < 0 || usec < 0 || usec >= 1000000 || sec > math.MaxInt64/int64(time.Second) {
		return 0, errors.New("invalid FreeBSD rusage timeval")
	}
	// Check the microsecond remainder as well as whole seconds: an
	// otherwise-valid timeval near MaxInt64 can overflow during addition.
	if usec > (math.MaxInt64-sec*int64(time.Second))/int64(time.Microsecond) {
		return 0, errors.New("FreeBSD rusage timeval overflow")
	}
	duration := time.Duration(sec)*time.Second + time.Duration(usec)*time.Microsecond
	return duration, nil
}

func fiCaptureProcessResources() (fiProcessResourceSnapshot, error) {
	// Timestamp is captured adjacent to Getrusage, not taken from SQL timing.
	before := time.Now()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return fiProcessResourceSnapshot{}, fmt.Errorf("getrusage RUSAGE_SELF: %w", err)
	}
	after := time.Now()
	userCPU, err := fiTimevalDuration(usage.Utime)
	if err != nil {
		return fiProcessResourceSnapshot{}, err
	}
	systemCPU, err := fiTimevalDuration(usage.Stime)
	if err != nil {
		return fiProcessResourceSnapshot{}, err
	}
	if userCPU > time.Duration(math.MaxInt64)-systemCPU {
		return fiProcessResourceSnapshot{}, errors.New("FreeBSD rusage CPU counter overflow")
	}
	if usage.Maxrss < 0 || uint64(usage.Maxrss) > math.MaxUint64/1024 {
		return fiProcessResourceSnapshot{}, errors.New("invalid FreeBSD process RSS high-water")
	}
	return fiProcessResourceSnapshot{
		At:                   before.Add(after.Sub(before) / 2),
		CPUTime:              userCPU + systemCPU,
		LifetimePeakRSSBytes: uint64(usage.Maxrss) * 1024,
	}, nil
}

// fiSummarizeProcessResources rejects invalid/retrograde counters instead of
// emitting misleading data. A successfully committed generation may still
// lack this optional telemetry; that must never affect authoritative ingest.
func fiSummarizeProcessResources(start, end fiProcessResourceSnapshot) (fiProcessResourceDelta, error) {
	elapsed := end.At.Sub(start.At)
	if start.At.IsZero() || end.At.IsZero() || elapsed <= 0 ||
		end.CPUTime < start.CPUTime ||
		end.LifetimePeakRSSBytes < start.LifetimePeakRSSBytes ||
		end.LifetimePeakRSSBytes == 0 {
		return fiProcessResourceDelta{}, errors.New("invalid FreeBSD process resource sample pair")
	}
	cpu := end.CPUTime - start.CPUTime
	cores := cpu.Seconds() / elapsed.Seconds()
	if math.IsNaN(cores) || math.IsInf(cores, 0) || cores < 0 {
		return fiProcessResourceDelta{}, errors.New("invalid FreeBSD process CPU equivalent")
	}
	return fiProcessResourceDelta{
		Elapsed:              elapsed,
		CPUTime:              cpu,
		EquivalentCores:      cores,
		LifetimePeakRSSBytes: end.LifetimePeakRSSBytes,
	}, nil
}

// fiReportProcessResources emits a separate process-level log only for a
// confirmed, newly accepted relational generation. It never creates a policy
// sample or grants a profile promotion. Unknown samples are explicit.
func fiReportProcessResources(sourceID, generationID string, eligible bool,
	start fiProcessResourceSnapshot, startErr error,
	end fiProcessResourceSnapshot, endErr error,
) {
	if !eligible {
		return
	}
	if startErr != nil || endErr != nil {
		fmt.Printf("INGEST PROCESS RESOURCE source=%s generation=%s status=unavailable reason=rusage_error adaptive_pressure_complete=false\n", sourceID, generationID)
		return
	}
	delta, err := fiSummarizeProcessResources(start, end)
	if err != nil {
		fmt.Printf("INGEST PROCESS RESOURCE source=%s generation=%s status=unavailable reason=invalid_counters adaptive_pressure_complete=false\n", sourceID, generationID)
		return
	}
	fmt.Printf("INGEST PROCESS RESOURCE source=%s generation=%s status=observed scope=worker_process cpu_time=%s elapsed=%s equivalent_cores=%.4f lifetime_peak_rss_bytes=%d storage_p95=unknown effective_cpu_limit=unknown effective_memory_limit=unknown adaptive_pressure_complete=false\n",
		sourceID, generationID, delta.CPUTime, delta.Elapsed,
		delta.EquivalentCores, delta.LifetimePeakRSSBytes)
}
