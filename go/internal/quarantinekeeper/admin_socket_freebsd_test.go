// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func adminSocketFixture(t *testing.T) AdminSocketAuthority {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("admin fixture requires non-root keeper identity")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "admin")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return AdminSocketAuthority{Directory: directory, KeeperUID: uint32(os.Geteuid()), KeeperGID: uint32(os.Getegid())}
}

func TestAdminSocketPrivateDirectoryAndEndpoint(t *testing.T) {
	policy := adminSocketFixture(t)
	if err := VerifyAdminSocketAuthority(policy, false); err != nil {
		t.Fatal(err)
	}
	listener, err := BindAdminSocket(policy)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := VerifyAdminSocketAuthority(policy, true); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAdminSocketAuthority(policy, false); err == nil {
		t.Fatal("occupied endpoint accepted as vacant")
	}
	if err := os.Chmod(filepath.Join(policy.Directory, AdminSocketName), 0660); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAdminSocketAuthority(policy, true); err == nil {
		t.Fatal("exposed admin socket accepted")
	}
}

func TestAdminSocketRejectsUnsafeParentAndDirectory(t *testing.T) {
	policy := adminSocketFixture(t)
	parent := filepath.Dir(policy.Directory)
	if err := os.Chmod(parent, 0770); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAdminSocketAuthority(policy, false); err == nil {
		t.Fatal("writable admin socket parent accepted")
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(policy.Directory, 0710); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAdminSocketAuthority(policy, false); err == nil {
		t.Fatal("worker-traversable admin socket directory accepted")
	}
}

func TestAdminSocketDoesNotUnlinkOnClose(t *testing.T) {
	policy := adminSocketFixture(t)
	listener, err := BindAdminSocket(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAdminSocketAuthority(policy, true); err != nil {
		t.Fatal(err)
	}
	if _, err := BindAdminSocket(policy); err == nil {
		t.Fatal("rebound occupied stale endpoint")
	}
}

func TestAdminSocketRejectsNonRootPeer(t *testing.T) {
	policy := adminSocketFixture(t)
	listener, err := BindAdminSocket(policy)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: filepath.Join(policy.Directory, AdminSocketName), Net: "unix",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := VerifyRootAdminPeer(server); err == nil {
		t.Fatal("keeper accepted an unprivileged peer as a root administrator")
	}
	calls := 0
	if err := HandleAdminReleaseConnection(server, func(_ context.Context, _ KeeperReleaseRequest) (string, error) {
		calls++
		return "", nil
	}); err == nil || calls != 0 {
		t.Fatalf("unprivileged release handler dispatch: calls=%d error=%v", calls, err)
	}
}
