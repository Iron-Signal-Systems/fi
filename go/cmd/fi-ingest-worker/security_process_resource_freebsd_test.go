// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"math"
	"syscall"
	"testing"
	"time"
)

func TestFIProcessResourceCorrectCPUAndRSS(t *testing.T) {
	now := time.Now()
	first := fiProcessResourceSnapshot{At: now, CPUTime: 3 * time.Second, LifetimePeakRSSBytes: 12 << 20}
	second := fiProcessResourceSnapshot{At: now.Add(2 * time.Second), CPUTime: 6 * time.Second, LifetimePeakRSSBytes: 20 << 20}
	got, err := fiSummarizeProcessResources(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if got.Elapsed != 2*time.Second || got.CPUTime != 3*time.Second || got.EquivalentCores != 1.5 || got.LifetimePeakRSSBytes != 20<<20 {
		t.Fatalf("incorrect worker process resource delta: %+v", got)
	}
}

func TestFIProcessResourceRejectsBadSamples(t *testing.T) {
	now := time.Now()
	base := fiProcessResourceSnapshot{At: now, CPUTime: time.Second, LifetimePeakRSSBytes: 100 << 20}
	tests := []fiProcessResourceSnapshot{
		{At: now, CPUTime: 2 * time.Second, LifetimePeakRSSBytes: 100 << 20},
		{At: now.Add(time.Second), CPUTime: 0, LifetimePeakRSSBytes: 100 << 20},
		{At: now.Add(time.Second), CPUTime: 2 * time.Second, LifetimePeakRSSBytes: 1},
		{At: now.Add(time.Second), CPUTime: 2 * time.Second, LifetimePeakRSSBytes: 0},
	}
	for i, end := range tests {
		if _, err := fiSummarizeProcessResources(base, end); err == nil {
			t.Fatalf("accepted invalid sample %d", i)
		}
	}
	if _, err := fiSummarizeProcessResources(fiProcessResourceSnapshot{}, base); err == nil {
		t.Fatal("accepted empty initial snapshot")
	}
}

func TestFIProcessResourceTimevalBounds(t *testing.T) {
	one, err := fiTimevalDuration(syscall.Timeval{Sec: 1, Usec: 500000})
	if err != nil || one != 1500*time.Millisecond {
		t.Fatalf("valid timeval: %s %v", one, err)
	}
	invalid := []syscall.Timeval{
		{Sec: -1}, {Usec: -1}, {Usec: 1000000}, {Sec: math.MaxInt64},
		{Sec: math.MaxInt64 / int64(time.Second), Usec: 999999},
	}
	for _, tv := range invalid {
		if _, err := fiTimevalDuration(tv); err == nil {
			t.Fatalf("accepted invalid timeval %+v", tv)
		}
	}
}

func TestFIProcessResourceReadOnlySmoke(t *testing.T) {
	first, err := fiCaptureProcessResources()
	if err != nil {
		t.Fatal(err)
	}
	if first.At.IsZero() || first.LifetimePeakRSSBytes == 0 {
		t.Fatalf("invalid runtime snapshot: %+v", first)
	}
	second, err := fiCaptureProcessResources()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fiSummarizeProcessResources(first, second); err != nil {
		t.Fatal(err)
	}
}
