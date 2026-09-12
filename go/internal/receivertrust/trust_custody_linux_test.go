//go:build linux

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestValidateCustodyDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "trust")
	if err := os.Mkdir(directory, 0750); err != nil {
		t.Fatalf("os.Mkdir() error = %v", err)
	}

	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatalf("os.Lstat() error = %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)

	service := custodyIdentity{
		GIDs: map[uint32]struct{}{stat.Gid: {}},
		UID:  stat.Uid + 100000,
	}

	if err := validateCustodyDirectory(
		directory,
		stat.Uid,
		stat.Gid,
		service,
	); err != nil {
		t.Fatalf("validateCustodyDirectory() error = %v", err)
	}

	if err := os.Chmod(directory, 0770); err != nil {
		t.Fatalf("os.Chmod() error = %v", err)
	}

	if err := validateCustodyDirectory(
		directory,
		stat.Uid,
		stat.Gid,
		service,
	); err == nil {
		t.Fatal("validateCustodyDirectory() error = nil, want writable error")
	}
}

func TestValidateCustodyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.pem")
	if err := os.WriteFile(path, []byte("test"), 0640); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("os.Lstat() error = %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)

	service := custodyIdentity{
		GIDs: map[uint32]struct{}{stat.Gid: {}},
		UID:  stat.Uid + 100000,
	}

	if err := validateCustodyFile(
		path,
		stat.Uid,
		stat.Gid,
		service,
		true,
	); err != nil {
		t.Fatalf("validateCustodyFile() error = %v", err)
	}

	if err := os.Chmod(path, 0660); err != nil {
		t.Fatalf("os.Chmod() error = %v", err)
	}

	if err := validateCustodyFile(
		path,
		stat.Uid,
		stat.Gid,
		service,
		true,
	); err == nil {
		t.Fatal("validateCustodyFile() error = nil, want writable error")
	}
}

func TestValidateCustodyRestrictedFileRejectsOtherAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.pem")
	if err := os.WriteFile(path, []byte("secret"), 0644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("os.Lstat() error = %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)

	service := custodyIdentity{
		GIDs: map[uint32]struct{}{stat.Gid: {}},
		UID:  stat.Uid + 100000,
	}

	if err := validateCustodyFile(
		path,
		stat.Uid,
		stat.Gid,
		service,
		true,
	); err == nil {
		t.Fatal("validateCustodyFile() error = nil, want other-access error")
	}
}

func TestValidateNoCustodySymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")

	if err := os.WriteFile(target, []byte("test"), 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink() error = %v", err)
	}

	if err := validateNoCustodySymlinks(root); err == nil {
		t.Fatal("validateNoCustodySymlinks() error = nil, want symlink error")
	}
}
