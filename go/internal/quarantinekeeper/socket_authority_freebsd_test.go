// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package quarantinekeeper

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func keeperSocketTestPolicy(t *testing.T) SocketAuthority {
	t.Helper()

	if os.Geteuid() == 0 {
		t.Skip("socket authority fixtures require non-root execution")
	}

	parent := t.TempDir()

	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}

	directory := filepath.Join(parent, "fi-keeper")

	if err := os.Mkdir(directory, 0710); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(directory, 0710); err != nil {
		t.Fatal(err)
	}

	// FreeBSD may inherit a directory's GID from its parent.
	// Inspect the actual fixture rather than assuming Getegid().
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("unsupported socket directory stat")
	}

	t.Logf(
		"fixture UID=%d GID=%d mode=%#o EUID=%d EGID=%d",
		stat.Uid,
		stat.Gid,
		info.Mode().Perm(),
		os.Geteuid(),
		os.Getegid(),
	)

	if !info.IsDir() ||
		info.Mode().Perm() != 0710 ||
		stat.Uid != uint32(os.Geteuid()) {
		t.Fatal("socket fixture does not satisfy keeper root contract")
	}

	return SocketAuthority{
		Directory: directory,
		KeeperUID: uint32(os.Geteuid()),
		WorkerUID: uint32(os.Geteuid() + 1),
		WorkerGID: stat.Gid,
	}
}

func TestKeeperSocketAuthorityRequiresVacantPath(
	t *testing.T,
) {
	policy := keeperSocketTestPolicy(t)

	if err := VerifySocketAuthority(
		policy, false,
	); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(
		policy.Directory,
		KeeperSocketName,
	)

	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: path, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}

	if err := VerifySocketAuthority(
		policy, false,
	); err == nil {
		t.Fatal("occupied socket pathname accepted for creation")
	}

	if err := VerifySocketAuthority(
		policy, true,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}

	if err := VerifySocketAuthority(
		policy, true,
	); err == nil {
		t.Fatal("exposed keeper socket accepted")
	}

	t.Log("PASS: Vacant path required before binding")
	t.Log("PASS: Exact socket ownership and mode verified")
	t.Log("PASS: Exposed socket rejected")
}

func TestKeeperSocketAuthorityRejectsDirectoryDrift(
	t *testing.T,
) {
	policy := keeperSocketTestPolicy(t)

	if err := os.Chmod(
		policy.Directory, 0770,
	); err != nil {
		t.Fatal(err)
	}

	if err := VerifySocketAuthority(
		policy, false,
	); err == nil {
		t.Fatal("worker-writable socket directory accepted")
	}

	if err := os.Chmod(
		policy.Directory, 0710,
	); err != nil {
		t.Fatal(err)
	}

	policy.KeeperUID++

	if err := VerifySocketAuthority(
		policy, false,
	); err == nil {
		t.Fatal("wrong keeper owner accepted")
	}

	t.Log("PASS: Worker directory-write access rejected")
	t.Log("PASS: Keeper ownership drift rejected")
}

func TestKeeperSocketAuthorityRejectsUnsafeObjects(
	t *testing.T,
) {
	policy := keeperSocketTestPolicy(t)

	path := filepath.Join(
		policy.Directory,
		KeeperSocketName,
	)

	if err := os.Symlink(
		"foreign.sock", path,
	); err != nil {
		t.Fatal(err)
	}

	if err := VerifySocketAuthority(
		policy, true,
	); err == nil {
		t.Fatal("symlink accepted as keeper socket")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		path,
		[]byte("foreign"),
		0600,
	); err != nil {
		t.Fatal(err)
	}

	if err := VerifySocketAuthority(
		policy, true,
	); err == nil {
		t.Fatal("regular file accepted as keeper socket")
	}

	policy.WorkerUID = policy.KeeperUID

	if err := VerifySocketAuthority(
		policy, false,
	); err == nil {
		t.Fatal("shared worker/keeper UID accepted")
	}

	t.Log("PASS: Foreign socket objects rejected")
	t.Log("PASS: Worker and keeper identity separation enforced")
}
