// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package objraw

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func TestObserveObjectHonorsCanceledContextBeforePrivilegeScope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ObserveObject(
		ctx,
		"canceled-context-test",
		`C:\`,
		records.NTFSObjectIdentity{},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestObserveObjectMarksBackupAuthority(t *testing.T) {
	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "backup-authority.txt")

	if err := os.WriteFile(
		targetPath,
		[]byte("FIObjReader backup-authority observation"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	seed, err := ntfs.CollectPath(
		context.Background(),
		"objraw-backup-authority-test",
		rootPath,
		targetPath,
	)
	if err != nil {
		t.Fatal(err)
	}

	observation, err := ObserveObject(
		context.Background(),
		"objraw-backup-authority-test",
		rootPath,
		seed.ObjectIdentity,
	)
	if errors.Is(err, ErrBackupPrivilegeUnavailable) {
		t.Skip("SeBackupPrivilege is not assigned to the test process token")
	}
	if err != nil {
		t.Fatal(err)
	}

	if observation.CollectionMethod != records.CollectionBackupAuthorityWindowsNTFS {
		t.Fatalf(
			"collection method = %q, want %q",
			observation.CollectionMethod,
			records.CollectionBackupAuthorityWindowsNTFS,
		)
	}
	if observation.ObjectIdentity != seed.ObjectIdentity {
		t.Fatalf(
			"object identity = %+v, want %+v",
			observation.ObjectIdentity,
			seed.ObjectIdentity,
		)
	}
	if err := ntfs.ValidateObservation(observation); err != nil {
		t.Fatalf("backup-authority observation validation failed: %v", err)
	}
}
