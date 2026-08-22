// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestCollectOpenedTargetMatchesCollectPathIdentity(t *testing.T) {
	rootPath := t.TempDir()
	targetPath := filepath.Join(rootPath, "opened.txt")
	if err := os.WriteFile(targetPath, []byte("opened"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootUnitsWithNUL, err := syscall.UTF16FromString(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	targetUnitsWithNUL, err := syscall.UTF16FromString(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	rootUnits := rootUnitsWithNUL[:len(rootUnitsWithNUL)-1]
	targetUnits := targetUnitsWithNUL[:len(targetUnitsWithNUL)-1]

	root, err := openGovernedRoot("opened-test", rootUnits)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root.handle)

	handle, err := openPath(nulTerminate(targetUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	openedObservation, err := collectOpenedTarget(context.Background(), root, CollectionEntryPath, targetUnits, handle, nil)
	if err != nil {
		t.Fatal(err)
	}
	pathObservation, err := CollectPath(context.Background(), "opened-test", rootPath, targetPath)
	if err != nil {
		t.Fatal(err)
	}

	if openedObservation.CollectionEntryMethod != CollectionEntryPath || pathObservation.CollectionEntryMethod != CollectionEntryPath {
		t.Fatalf("unexpected collection entry methods: opened=%q path=%q", openedObservation.CollectionEntryMethod, pathObservation.CollectionEntryMethod)
	}
	if !reflect.DeepEqual(openedObservation.ObjectIdentity, pathObservation.ObjectIdentity) {
		t.Fatalf("opened identity = %+v, path identity = %+v", openedObservation.ObjectIdentity, pathObservation.ObjectIdentity)
	}
	if !reflect.DeepEqual(openedObservation.ParentBinding, pathObservation.ParentBinding) {
		t.Fatalf("opened parent = %+v, path parent = %+v", openedObservation.ParentBinding, pathObservation.ParentBinding)
	}
}
