// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedBatchQueueAdvanceRejectsWrongManifest(t *testing.T) {
	spoolDir := t.TempDir()
	writeQueueTestFile(t, spoolDir, "batch-20260913T120000.000000000Z-a.manifest.json")

	queue, err := NewPublishedBatchQueue(spoolDir)
	if err != nil {
		t.Fatalf("NewPublishedBatchQueue() error = %v", err)
	}
	current, found, err := queue.Next()
	if err != nil || !found {
		t.Fatalf("Next() = %q, %v, %v", current, found, err)
	}

	wrong := filepath.Join(spoolDir, "batch-wrong.manifest.json")
	if err := queue.Advance(wrong); err == nil {
		t.Fatal("Advance(wrong) error = nil")
	}

	after, found, err := queue.Next()
	if err != nil || !found {
		t.Fatalf("Next() after rejected advance = %q, %v, %v", after, found, err)
	}
	if after != current {
		t.Fatalf("Next() after rejected advance = %q, want %q", after, current)
	}
}

func TestPublishedBatchQueueDrainsSnapshotBeforeRefresh(t *testing.T) {
	spoolDir := t.TempDir()
	firstName := "batch-20260913T120000.000000000Z-a.manifest.json"
	secondName := "batch-20260913T120100.000000000Z-b.manifest.json"
	thirdName := "batch-20260913T120200.000000000Z-c.manifest.json"

	writeQueueTestFile(t, spoolDir, secondName)
	writeQueueTestFile(t, spoolDir, firstName)
	writeQueueTestFile(t, spoolDir, "batch-20260913T120000.000000000Z-a.jsonl")
	writeQueueTestFile(t, spoolDir, "unrelated.txt")
	if err := os.Mkdir(
		filepath.Join(spoolDir, "batch-20260913T115900.000000000Z-directory.manifest.json"),
		0o700,
	); err != nil {
		t.Fatalf("os.Mkdir(manifest-like directory) error = %v", err)
	}

	queue, err := NewPublishedBatchQueue(spoolDir)
	if err != nil {
		t.Fatalf("NewPublishedBatchQueue() error = %v", err)
	}

	first, found, err := queue.Next()
	if err != nil || !found {
		t.Fatalf("Next(first) = %q, %v, %v", first, found, err)
	}
	wantFirst := filepath.Join(spoolDir, firstName)
	if first != wantFirst {
		t.Fatalf("Next(first) = %q, want %q", first, wantFirst)
	}

	writeQueueTestFile(t, spoolDir, thirdName)

	retry, found, err := queue.Next()
	if err != nil || !found {
		t.Fatalf("Next(retry) = %q, %v, %v", retry, found, err)
	}
	if retry != first {
		t.Fatalf("Next(retry) = %q, want held current %q", retry, first)
	}

	if err := os.Remove(first); err != nil {
		t.Fatalf("os.Remove(first) error = %v", err)
	}
	if err := queue.Advance(first); err != nil {
		t.Fatalf("Advance(first) error = %v", err)
	}

	second, found, err := queue.Next()
	if err != nil || !found {
		t.Fatalf("Next(second) = %q, %v, %v", second, found, err)
	}
	wantSecond := filepath.Join(spoolDir, secondName)
	if second != wantSecond {
		t.Fatalf("Next(second) = %q, want %q", second, wantSecond)
	}

	if err := os.Remove(second); err != nil {
		t.Fatalf("os.Remove(second) error = %v", err)
	}
	if err := queue.Advance(second); err != nil {
		t.Fatalf("Advance(second) error = %v", err)
	}

	third, found, err := queue.Next()
	if err != nil || !found {
		t.Fatalf("Next(third) = %q, %v, %v", third, found, err)
	}
	wantThird := filepath.Join(spoolDir, thirdName)
	if third != wantThird {
		t.Fatalf("Next(third) = %q, want refreshed %q", third, wantThird)
	}
}

func TestPublishedBatchQueueEmptySnapshot(t *testing.T) {
	queue, err := NewPublishedBatchQueue(t.TempDir())
	if err != nil {
		t.Fatalf("NewPublishedBatchQueue() error = %v", err)
	}

	manifestPath, found, err := queue.Next()
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if found || manifestPath != "" {
		t.Fatalf("Next() = %q, %v, want empty", manifestPath, found)
	}
}

func TestNewPublishedBatchQueueRejectsInvalidPaths(t *testing.T) {
	if _, err := NewPublishedBatchQueue(""); err == nil {
		t.Fatal("NewPublishedBatchQueue(empty) error = nil")
	}
	if _, err := NewPublishedBatchQueue("relative"); err == nil {
		t.Fatal("NewPublishedBatchQueue(relative) error = nil")
	}

	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	writeQueueTestFile(t, filepath.Dir(filePath), filepath.Base(filePath))
	if _, err := NewPublishedBatchQueue(filePath); err == nil {
		t.Fatal("NewPublishedBatchQueue(file) error = nil")
	}
}

func writeQueueTestFile(t *testing.T, dir string, name string) {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("test\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}
