// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestComposeNTFSFileID(t *testing.T) {
	identity := records.NTFSObjectIdentity{
		MethodVersion:       IdentityMethodVersion,
		FileReferenceNumber: "144588",
		SequenceNumber:      "8",
	}
	got, err := composeNTFSFileID(identity)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(144588) | uint64(8)<<48
	if got != want {
		t.Fatalf("file ID = %#x, want %#x", got, want)
	}
}

func TestComposeNTFSFileIDRejectsOtherMethod(t *testing.T) {
	_, err := composeNTFSFileID(records.NTFSObjectIdentity{
		MethodVersion:       "other/1",
		FileReferenceNumber: "1",
		SequenceNumber:      "1",
	})
	if !errors.Is(err, ErrUnsupportedIdentityMethod) {
		t.Fatalf("error = %v, want ErrUnsupportedIdentityMethod", err)
	}
}

func TestOpenFileByObjectIdentityReturnsSameObject(t *testing.T) {
	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "object.txt")
	if err := os.WriteFile(targetPath, []byte("file id"), 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := CollectPath(context.Background(), "scope-test", rootPath, targetPath)
	if err != nil {
		t.Fatal(err)
	}

	rootUnits, err := syscall.UTF16FromString(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := openGovernedRoot("scope-test", rootUnits[:len(rootUnits)-1])
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	handle, err := openFileByObjectIdentity(root.handle, observation.ObjectIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	state, err := queryNativeState(handle)
	if err != nil {
		t.Fatal(err)
	}
	_, gotIdentity, err := buildObjectIdentity(state.ID.VolumeSerialNumber, state.ID.FileID)
	if err != nil {
		t.Fatal(err)
	}
	if gotIdentity != observation.ObjectIdentity {
		t.Fatalf("identity = %+v, want %+v", gotIdentity, observation.ObjectIdentity)
	}

	resolved, err := finalVolumePath(handle)
	if err != nil {
		t.Fatal(err)
	}
	if !pathContainedBy(root.finalPath, resolved) {
		t.Fatalf("ID-opened path is outside governed root")
	}
}
