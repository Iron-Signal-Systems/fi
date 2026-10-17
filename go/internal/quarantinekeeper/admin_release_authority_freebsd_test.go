// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

func TestProtectedAdminReleaseDeniedWhenLockAuthorityAbsent(t *testing.T) {
	store, root, history := keeperReleaseFixture(t)
	markerPath := filepath.Join(root, releaseFixtureSource+".json")
	before, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	handler := ProtectedAdminReleaseHandler(store, history, workerlock.ProtectedLockPolicy{
		KeeperUID: uid, WorkerUID: uid + 1, WorkerGID: gid,
	}, gid)
	if _, err := handler(context.Background(), validKeeperReleaseFixture()); err == nil {
		t.Fatal("release succeeded without keeper protected lock")
	}
	after, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("marker changed despite missing lock authority")
	}
	historyEntries, err := os.ReadDir(history)
	if err != nil {
		t.Fatal(err)
	}
	if len(historyEntries) != 0 {
		t.Fatal("release audit written without protected lock")
	}
}

func TestProtectedAdminReleaseRejectsStoreIdentityMismatch(t *testing.T) {
	store, _, history := keeperReleaseFixture(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	handler := ProtectedAdminReleaseHandler(store, history, workerlock.ProtectedLockPolicy{
		KeeperUID: uid + 1, WorkerUID: uid + 2, WorkerGID: gid,
	}, gid)
	if _, err := handler(context.Background(), validKeeperReleaseFixture()); err == nil {
		t.Fatal("release authorized with mismatched keeper UID")
	}
}
