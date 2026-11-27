// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package workerlock

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProtectedLockRejectsUnpinnedIdentities(t *testing.T) {
	for _, policy := range []ProtectedLockPolicy{
		{},
		{KeeperUID: 10, WorkerUID: 10, WorkerGID: 20},
		{KeeperUID: 0, WorkerUID: 10, WorkerGID: 20},
		{KeeperUID: 11, WorkerUID: 0, WorkerGID: 20},
		{KeeperUID: 11, WorkerUID: 10, WorkerGID: 0},
		{KeeperUID: 11, WorkerUID: uint32(os.Geteuid()) + 1, WorkerGID: uint32(os.Getegid())},
	} {
		if err := validateProtectedIdentity(policy); err == nil {
			t.Fatalf("accepted unpinned policy: %+v", policy)
		}
	}
}

func TestProtectedLockDirectoryRequiresKeeperOwnership(t *testing.T) {
	policy := ProtectedLockPolicy{KeeperUID: 201, WorkerUID: 202, WorkerGID: 203}
	valid := unix.Stat_t{Uid: 201, Gid: 203, Mode: unix.S_IFDIR | 0710}
	if !isProtectedDirectory(valid, policy) {
		t.Fatal("rejected exact 0710 keeper directory")
	}
	for _, bad := range []unix.Stat_t{
		{Uid: 202, Gid: 203, Mode: unix.S_IFDIR | 0710},
		{Uid: 201, Gid: 203, Mode: unix.S_IFDIR | 0770},
		{Uid: 201, Gid: 203, Mode: unix.S_IFDIR | 0750},
		{Uid: 201, Gid: 203, Mode: unix.S_IFREG | 0710},
		{Uid: 201, Gid: 204, Mode: unix.S_IFDIR | 0710},
	} {
		if isProtectedDirectory(bad, policy) {
			t.Fatalf("accepted unsafe keeper directory: %+v", bad)
		}
	}
}

func TestProtectedLockInodeRequiresKeeperOwnership(t *testing.T) {
	policy := ProtectedLockPolicy{KeeperUID: 201, WorkerUID: 202, WorkerGID: 203}
	valid := unix.Stat_t{
		Uid: 201, Gid: 203, Mode: unix.S_IFREG | 0640, Nlink: 1,
	}
	if !isProtectedLockFile(valid, policy) {
		t.Fatal("rejected keeper-owned read-only lock inode")
	}
	for _, bad := range []unix.Stat_t{
		{Uid: 202, Gid: 203, Mode: unix.S_IFREG | 0640, Nlink: 1},
		{Uid: 201, Gid: 203, Mode: unix.S_IFREG | 0660, Nlink: 1},
		{Uid: 201, Gid: 203, Mode: unix.S_IFLNK | 0640, Nlink: 1},
		{Uid: 201, Gid: 203, Mode: unix.S_IFREG | 0640, Nlink: 2},
		{Uid: 201, Gid: 203, Mode: unix.S_IFREG | 0640, Nlink: 1, Size: 1},
		{Uid: 201, Gid: 204, Mode: unix.S_IFREG | 0640, Nlink: 1},
	} {
		if isProtectedLockFile(bad, policy) {
			t.Fatalf("accepted unsafe keeper lock inode: %+v", bad)
		}
	}
}

func TestProtectedLockParentRequiresTrustedDirectory(t *testing.T) {
	good := unix.Stat_t{Uid: 0, Mode: unix.S_IFDIR | 0755}
	if !isProtectedParent(good, 201) {
		t.Fatal("rejected protected root-owned parent")
	}
	for _, bad := range []unix.Stat_t{
		{Uid: 202, Mode: unix.S_IFDIR | 0755},
		{Uid: 0, Mode: unix.S_IFDIR | 0775},
		{Uid: 0, Mode: unix.S_IFREG | 0755},
	} {
		if isProtectedParent(bad, 201) {
			t.Fatalf("accepted unsafe keeper lock parent: %+v", bad)
		}
	}
}

func TestProtectedLockDoesNotFallbackToWorkerCreatedLock(t *testing.T) {
	// The development account cannot impersonate the keeper. A failed
	// authority check must not invoke the legacy Acquire path instead.
	policy := ProtectedLockPolicy{
		KeeperUID: uint32(os.Geteuid()),
		WorkerUID: uint32(os.Geteuid()),
		WorkerGID: uint32(os.Getegid()),
	}
	if _, err := AcquireProtected(policy); err == nil {
		t.Fatal("protected lock accepted a worker-owned keeper identity")
	}
}
