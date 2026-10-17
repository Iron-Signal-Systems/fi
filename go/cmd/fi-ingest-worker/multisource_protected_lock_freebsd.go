// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

const m8LegacyLockPath = "/var/run/fi/fi-ingest-worker.lock"

// m8WorkerSingleton owns all locks acquired for one worker lifetime.
// In dual-lock mode the legacy lock is acquired first, then the protected
// lock; both remain held until the worker exits. The protected lock is
// always released first, then the legacy lock.
type m8WorkerSingleton struct {
	primary   *workerlock.Lock
	protected *workerlock.Lock
}

func (value *m8WorkerSingleton) Close() error {
	if value == nil {
		return nil
	}
	var result error
	if value.protected != nil {
		result = errors.Join(result, value.protected.Close())
		value.protected = nil
	}
	if value.primary != nil {
		result = errors.Join(result, value.primary.Close())
		value.primary = nil
	}
	return result
}

func (value *m8WorkerSingleton) Path() string {
	if value == nil || value.primary == nil {
		return ""
	}
	return value.primary.Path()
}

// m8AcquireDual keeps the legacy inode locked while it attempts the
// keeper-owned lock. If the latter fails, the legacy lock is closed
// before startup is rejected; no protected-only fallback is permitted.
// The callback is supplied by the pinned identity path, never a CLI value.
func m8AcquireDual(
	legacyPath string,
	acquireProtected func() (*workerlock.Lock, error),
) (*m8WorkerSingleton, error) {
	if acquireProtected == nil {
		return nil, errors.New("M8 protected lock acquisition is absent")
	}
	legacy, err := workerlock.Acquire(legacyPath)
	if err != nil {
		return nil, fmt.Errorf("acquire M8 legacy worker lock: %w", err)
	}
	protected, err := acquireProtected()
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("acquire M8 keeper-protected lock: %w", err),
			legacy.Close(),
		)
	}
	if protected == nil {
		return nil, errors.Join(
			errors.New("M8 protected lock returned nil authority"),
			legacy.Close(),
		)
	}
	return &m8WorkerSingleton{primary: legacy, protected: protected}, nil
}

// m1AcquireWorkerSingleton keeps legacy operation unchanged by default.
// The transitional flat-layout mode is an explicit opt-in and pins both
// paths. Namespaced ingest remains protected-only and independently gated.
// The admin release path must not be installed on a host that can still
// run legacy-only workers: old binaries never acquire the protected inode.
func m1AcquireWorkerSingleton(config workerConfig) (*m8WorkerSingleton, error) {
	if config.DualLockTransition {
		if config.SourceNamespaces || config.LockFile != m8LegacyLockPath {
			return nil, errors.New("M8 dual-lock mode requires flat-layout ingest and the pinned legacy lock path")
		}
		policy, err := m1PinnedKeeperWorkerIdentity()
		if err != nil {
			return nil, fmt.Errorf("resolve M8 keeper-owned singleton identities: %w", err)
		}
		return m8AcquireDual(config.LockFile, func() (*workerlock.Lock, error) {
			return workerlock.AcquireProtected(policy)
		})
	}
	if !config.SourceNamespaces {
		lock, err := workerlock.Acquire(config.LockFile)
		if err != nil {
			return nil, err
		}
		return &m8WorkerSingleton{primary: lock}, nil
	}
	if config.LockFile != workerlock.ProtectedLockPath {
		return nil, fmt.Errorf(
			"namespaced FI worker requires keeper-owned singleton %q, got %q",
			workerlock.ProtectedLockPath, config.LockFile,
		)
	}
	policy, err := m1PinnedKeeperWorkerIdentity()
	if err != nil {
		return nil, fmt.Errorf("resolve keeper-owned singleton identities: %w", err)
	}
	lock, err := workerlock.AcquireProtected(policy)
	if err != nil {
		return nil, err
	}
	return &m8WorkerSingleton{primary: lock}, nil
}
