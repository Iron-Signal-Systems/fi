// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestM1ProtectedLockLegacyStillWorks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.lock")
	lock, err := m1AcquireWorkerSingleton(workerConfig{LockFile: path})
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if lock.Path() != path {
		t.Fatalf("unexpected legacy lock path: %q", lock.Path())
	}
	other, err := m1AcquireWorkerSingleton(workerConfig{LockFile: path})
	if other != nil {
		defer other.Close()
	}
	if err == nil {
		t.Fatal("second legacy lock accepted while first held")
	}
}

func TestM1ProtectedLockNeverUsesLegacyForNamespaces(t *testing.T) {
	root := t.TempDir()
	// Even a valid worker-owned path must be rejected in namespaced mode.
	path := filepath.Join(root, "legacy.lock")
	config := workerConfig{SourceNamespaces: true, LockFile: path}
	if lock, err := m1AcquireWorkerSingleton(config); err == nil {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("namespaced worker acquired a replaceable legacy lock")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("legacy lock path unexpectedly created: %v", err)
	}
	config.LockFile = ""
	if _, err := m1AcquireWorkerSingleton(config); err == nil {
		t.Fatal("namespaced worker accepted missing lock path")
	}
}

func TestM1ProtectedLockIsWiredToStartup(t *testing.T) {
	data, err := os.ReadFile("main_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(data)
	if strings.Count(code, "singleton, err := m1AcquireWorkerSingleton(config)") != 1 ||
		strings.Contains(code, "singleton, err := workerlock.Acquire(config.LockFile)") {
		t.Fatal("operational startup bypasses protected singleton selection")
	}
}
