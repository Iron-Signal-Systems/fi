// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package policyroot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/policyassociation"
	"golang.org/x/sys/windows"
)

func tempNativeSerial(t *testing.T, path string) uint64 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil { t.Fatal(err) }
	h, err := windows.CreateFile(
		p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(h)
	native, err := queryNativeDirectoryIdentity(h)
	if err != nil { t.Fatal(err) }
	return native.VolumeSerial
}

func TestNativePolicyRootReadOnlyDirectoryChain(t *testing.T) {
	base := t.TempDir() // Windows runner fixture, never an FI install path
	first := filepath.Join(base, "one")
	last := filepath.Join(first, "two")
	if err := os.MkdirAll(last, 0700); err != nil { t.Fatal(err) }
	serial := tempNativeSerial(t, base)
	paths := []string{base, first, last}
	id, err := attestNativeDirectoryChain(context.Background(), paths, serial)
	if err != nil || id == (policyassociation.FileID{}) {
		t.Fatalf("native directory identity failed: %v %v", id, err)
	}
	if _, err := attestNativeDirectoryChain(context.Background(), paths, serial+1); !errors.Is(err, ErrUnattestedRoot) {
		t.Fatalf("changed full-width serial accepted: %v", err)
	}
	if _, err := attestNativeDirectoryChain(context.Background(), []string{base, last}, serial); !errors.Is(err, ErrUnattestedRoot) {
		t.Fatalf("skipped ancestor accepted: %v", err)
	}
	if _, err := attestNativeDirectoryChain(context.Background(), nil, serial); !errors.Is(err, ErrUnattestedRoot) {
		t.Fatalf("empty native chain accepted: %v", err)
	}
	if _, err := attestNativeDirectoryChain(context.Background(), paths, 0); !errors.Is(err, ErrUnattestedRoot) {
		t.Fatalf("zero serial accepted: %v", err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := attestNativeDirectoryChain(cancelled, paths, serial); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled chain entered Windows I/O: %v", err)
	}
}

func TestNativePolicyRootDeniesFileAndReparse(t *testing.T) {
	base := t.TempDir()
	serial := tempNativeSerial(t, base)
	file := filepath.Join(base, "not-a-directory")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil { t.Fatal(err) }
	if _, err := attestNativeDirectoryChain(context.Background(), []string{base, file}, serial); !errors.Is(err, ErrUnattestedRoot) {
		t.Fatalf("regular file accepted as policy root: %v", err)
	}
	actual := filepath.Join(base, "real-directory")
	alias := filepath.Join(base, "junction-alias")
	if err := os.Mkdir(actual, 0700); err != nil { t.Fatal(err) }
	if err := os.Symlink(actual, alias); err != nil {
		t.Skipf("isolated Windows test runner cannot create directory symlink: %v", err)
	}
	if _, err := attestNativeDirectoryChain(context.Background(), []string{base, alias}, serial); !errors.Is(err, ErrUnattestedRoot) {
		t.Fatalf("reparse-point policy root accepted: %v", err)
	}
}
