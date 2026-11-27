// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

func TestM8DualLockHoldsLegacyAndProtected(t *testing.T) {
	root := t.TempDir()
	legacyPath := filepath.Join(root, "legacy.lock")
	protectedPath := filepath.Join(root, "protected.lock")

	pair, err := m8AcquireDual(legacyPath, func() (*workerlock.Lock, error) {
		return workerlock.Acquire(protectedPath)
	})
	if err != nil {
		t.Fatal(err)
	}
	if pair.Path() != legacyPath {
		t.Fatalf("dual-lock primary path = %q", pair.Path())
	}
	for _, path := range []string{legacyPath, protectedPath} {
		competitor, err := workerlock.Acquire(path)
		if competitor != nil {
			_ = competitor.Close()
		}
		if !errors.Is(err, workerlock.ErrAlreadyHeld) {
			_ = pair.Close()
			t.Fatalf("second worker acquired %q or unexpected error: %v", path, err)
		}
	}
	if err := pair.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{legacyPath, protectedPath} {
		competitor, err := workerlock.Acquire(path)
		if err != nil {
			t.Fatalf("lock not released after worker exit %q: %v", path, err)
		}
		if err := competitor.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestM8DualLockRollsBackLegacyOnProtectedFailure(t *testing.T) {
	legacyPath := filepath.Join(t.TempDir(), "legacy.lock")
	injected := errors.New("keeper offline")
	lock, err := m8AcquireDual(legacyPath, func() (*workerlock.Lock, error) {
		return nil, injected
	})
	if lock != nil || !errors.Is(err, injected) {
		t.Fatalf("dual-lock did not fail closed: lock=%v err=%v", lock, err)
	}
	competitor, err := workerlock.Acquire(legacyPath)
	if err != nil {
		t.Fatalf("legacy lock remained held after rollback: %v", err)
	}
	if err := competitor.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestM8DualLockRejectsNilProtectedAuthority(t *testing.T) {
	legacyPath := filepath.Join(t.TempDir(), "legacy.lock")
	pair, err := m8AcquireDual(legacyPath, func() (*workerlock.Lock, error) {
		return nil, nil
	})
	if err == nil || pair != nil {
		if pair != nil {
			_ = pair.Close()
		}
		t.Fatal("nil protected authority accepted")
	}
	competitor, err := workerlock.Acquire(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = competitor.Close()
}

func TestM8DualLockRejectsNamespaceAndAlternateLegacyPath(t *testing.T) {
	wrongPath := filepath.Join(t.TempDir(), "worker.lock")
	configs := []workerConfig{
		{SourceNamespaces: true, DualLockTransition: true, LockFile: m8LegacyLockPath},
		{DualLockTransition: true, LockFile: wrongPath},
		{DualLockTransition: true},
	}
	for _, config := range configs {
		if pair, err := m1AcquireWorkerSingleton(config); err == nil {
			if pair != nil {
				_ = pair.Close()
			}
			t.Fatalf("unsafe dual-lock configuration accepted: %+v", config)
		}
	}
	if _, err := os.Lstat(wrongPath); !os.IsNotExist(err) {
		t.Fatalf("unexpected worker-owned inode created: %v", err)
	}
}

func TestM8DualLockFlagAndGateRemainInStartup(t *testing.T) {
	code, err := os.ReadFile("main_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"lock-migration-dual"`,
		"DualLockTransition:     *dualLockTransition,",
		"if err := m1ValidateQuarantineAuthorityReady(config); err != nil",
		"singleton, err := m1AcquireWorkerSingleton(config)",
	} {
		if !strings.Contains(string(code), required) {
			t.Fatalf("required startup path absent: %s", required)
		}
	}
}
