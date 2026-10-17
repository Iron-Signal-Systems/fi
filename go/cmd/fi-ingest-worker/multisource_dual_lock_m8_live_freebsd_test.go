// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

// TestM8CrossUIDIntegration is deliberately inert in routine go test runs.
// Run the compiled test executable as the fi-ingest account after the test
// operator has provisioned the real, isolated fi-dev legacy and keeper locks.
// No PostgreSQL connections or ingest runtime are started by this test.
func TestM8CrossUIDIntegration(t *testing.T) {
	mode := os.Getenv("FI_M8_LIVE_CASE")
	if mode == "" {
		t.Skip("explicit FI_M8_LIVE_CASE required for cross-UID acceptance")
	}
	if os.Geteuid() != 61232 || os.Getegid() != 61232 {
		t.Fatalf("wrong development ingest identity: euid=%d egid=%d", os.Geteuid(), os.Getegid())
	}

	dual := func() (*m8WorkerSingleton, error) {
		return m1AcquireWorkerSingleton(workerConfig{
			LockFile:           m8LegacyLockPath,
			DualLockTransition: true,
		})
	}
	legacy := func() (*workerlock.Lock, error) {
		return workerlock.Acquire(m8LegacyLockPath)
	}
	protected := func() (*workerlock.Lock, error) {
		policy, err := m1PinnedKeeperWorkerIdentity()
		if err != nil {
			return nil, err
		}
		return workerlock.AcquireProtected(policy)
	}

	switch mode {
	case "hold-dual", "allow-dual", "deny-dual-legacy", "deny-dual-protected":
		lock, err := dual()
		if strings.HasPrefix(mode, "deny-") {
			expectContention(t, mode, err, lock != nil)
			if lock != nil {
				_ = lock.Close()
			}
			if mode == "deny-dual-legacy" && !strings.Contains(err.Error(), "legacy") {
				t.Fatalf("wrong dual-lock contention authority: %v", err)
			}
			if mode == "deny-dual-protected" && !strings.Contains(err.Error(), "keeper-protected") {
				t.Fatalf("wrong dual-lock contention authority: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer func() { if err := lock.Close(); err != nil { t.Error(err) } }()
		if mode == "hold-dual" {
			holdUntilSignal()
		}
	case "hold-legacy", "allow-legacy", "deny-legacy":
		lock, err := legacy()
		if mode == "deny-legacy" {
			expectContention(t, mode, err, lock != nil)
			if lock != nil { _ = lock.Close() }
			return
		}
		if err != nil { t.Fatal(err) }
		defer func() { if err := lock.Close(); err != nil { t.Error(err) } }()
		if mode == "hold-legacy" { holdUntilSignal() }
	case "hold-protected", "allow-protected", "deny-protected":
		lock, err := protected()
		if mode == "deny-protected" {
			expectContention(t, mode, err, lock != nil)
			if lock != nil { _ = lock.Close() }
			return
		}
		if err != nil { t.Fatal(err) }
		defer func() { if err := lock.Close(); err != nil { t.Error(err) } }()
		if mode == "hold-protected" { holdUntilSignal() }
	default:
		t.Fatalf("unsupported FI_M8_LIVE_CASE %q", mode)
	}
	fmt.Println("M8_PASS " + mode)
}

func expectContention(t *testing.T, mode string, err error, nonnil bool) {
	t.Helper()
	if nonnil || !errors.Is(err, workerlock.ErrAlreadyHeld) {
		t.Fatalf("%s should be blocked by actual lock contention, got lock=%t err=%v", mode, nonnil, err)
	}
	fmt.Println("M8_PASS " + mode)
}

func holdUntilSignal() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	fmt.Println("M8_HOLD_READY")
	select {
	case <-signals:
	case <-time.After(90 * time.Second):
	}
}
