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
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectPathRecordsParentObjectBinding(t *testing.T) {
	root := t.TempDir()
	parentPath := filepath.Join(root, "parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	childPath := filepath.Join(parentPath, "child.txt")
	if err := os.WriteFile(childPath, []byte("child"), 0o600); err != nil {
		t.Fatal(err)
	}

	parentObservation, err := CollectPath(context.Background(), "parent-test", root, parentPath)
	if err != nil {
		t.Fatal(err)
	}
	childObservation, err := CollectPath(context.Background(), "parent-test", root, childPath)
	if err != nil {
		t.Fatal(err)
	}

	if childObservation.ParentBinding.State != records.ParentBindingPresent {
		t.Fatalf("parent binding state = %q, want %q", childObservation.ParentBinding.State, records.ParentBindingPresent)
	}
	if childObservation.ParentBinding.ObjectIdentity == nil {
		t.Fatal("parent binding omitted object identity")
	}
	if !reflect.DeepEqual(*childObservation.ParentBinding.ObjectIdentity, parentObservation.ObjectIdentity) {
		t.Fatalf("parent identity = %+v, want %+v", *childObservation.ParentBinding.ObjectIdentity, parentObservation.ObjectIdentity)
	}
}

func TestCollectPathGovernedRootParentBinding(t *testing.T) {
	root := t.TempDir()
	observation, err := CollectPath(context.Background(), "root-parent-test", root, root)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ParentBinding.State != records.ParentBindingGovernedRoot {
		t.Fatalf("parent binding state = %q, want %q", observation.ParentBinding.State, records.ParentBindingGovernedRoot)
	}
	if observation.ParentBinding.ObjectIdentity != nil {
		t.Fatal("governed-root parent binding must not expose an object outside the governed scope")
	}
}

func TestDirectParentVolumePath(t *testing.T) {
	path := asciiUTF16(`\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\one\two`)
	got, err := directParentVolumePath(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\one`
	if stringFromASCIIUTF16(got) != want {
		t.Fatalf("parent = %q, want %q", stringFromASCIIUTF16(got), want)
	}
}
