// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const benchmarkScopeID = "benchmark"

func BenchmarkCollectPathPlainFile(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "plain.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CollectPath(context.Background(), benchmarkScopeID, root, target); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCollectPathADSHeavy(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "ads-heavy.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}
	createBenchmarkADS(b, target, 32)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CollectPath(context.Background(), benchmarkScopeID, root, target); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryNativeState(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "state.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}

	handle := openBenchmarkHandle(b, target)
	defer syscall.CloseHandle(handle)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := queryNativeState(handle); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryStreamsDefaultOnly(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "streams.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}

	handle := openBenchmarkHandle(b, target)
	defer syscall.CloseHandle(handle)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := queryStreams(handle); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryStreamsADSHeavy(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "streams-ads.bin")
	if err := os.WriteFile(target, []byte("fi benchmark"), 0o600); err != nil {
		b.Fatal(err)
	}
	createBenchmarkADS(b, target, 32)

	handle := openBenchmarkHandle(b, target)
	defer syscall.CloseHandle(handle)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := queryStreams(handle); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCollectPathSiblingEscape(b *testing.B) {
	parent := b.TempDir()
	root := filepath.Join(parent, "governed")
	sibling := filepath.Join(parent, "sibling")
	if err := os.Mkdir(root, 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.Mkdir(sibling, 0o700); err != nil {
		b.Fatal(err)
	}
	target := filepath.Join(sibling, "outside.bin")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CollectPath(context.Background(), benchmarkScopeID, root, target); err == nil {
			b.Fatal("expected governed-root rejection")
		}
	}
}

func BenchmarkWalkGovernedRoot1000Files(b *testing.B) {
	root := b.TempDir()
	const directoryCount = 10
	const filesPerDirectory = 100
	const expectedObjects = 1 + directoryCount + directoryCount*filesPerDirectory

	for directoryIndex := 0; directoryIndex < directoryCount; directoryIndex++ {
		directory := filepath.Join(root, fmt.Sprintf("d-%02d", directoryIndex))
		if err := os.Mkdir(directory, 0o700); err != nil {
			b.Fatal(err)
		}
		for fileIndex := 0; fileIndex < filesPerDirectory; fileIndex++ {
			path := filepath.Join(directory, fmt.Sprintf("f-%03d.bin", fileIndex))
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				b.Fatal(err)
			}
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		observed := 0
		err := WalkGovernedRoot(
			context.Background(),
			benchmarkScopeID,
			root,
			func(_ string, _ Observation, objectErr error) error {
				if objectErr != nil {
					return objectErr
				}
				observed++
				return nil
			},
		)
		if err != nil {
			b.Fatal(err)
		}
		if observed != expectedObjects {
			b.Fatalf("observed %d objects, expected %d", observed, expectedObjects)
		}
	}
	elapsed := time.Since(start)
	b.StopTimer()

	b.ReportMetric(expectedObjects, "objects/op")
	if elapsed > 0 {
		b.ReportMetric(float64(expectedObjects*b.N)/elapsed.Seconds(), "objects/s")
	}
}

func createBenchmarkADS(b *testing.B, target string, count int) {
	b.Helper()
	for i := 0; i < count; i++ {
		streamPath := target + ":" + fmt.Sprintf("ads-%02d", i)
		if err := os.WriteFile(streamPath, []byte("x"), 0o600); err != nil {
			b.Fatalf("create ADS %d: %v", i, err)
		}
	}
}

func openBenchmarkHandle(b *testing.B, path string) syscall.Handle {
	b.Helper()
	units, err := syscall.UTF16FromString(path)
	if err != nil {
		b.Fatal(err)
	}
	handle, err := openPath(units)
	if err != nil {
		b.Fatal(err)
	}
	return handle
}
