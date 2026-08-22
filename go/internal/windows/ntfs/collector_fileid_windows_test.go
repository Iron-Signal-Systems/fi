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
)

func TestCollectFileReferenceMatchesPathObservation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")
	if err := os.WriteFile(target, []byte("same object"), 0o600); err != nil {
		t.Fatal(err)
	}

	pathObservation, err := CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}
	idObservation, err := CollectFileReference(
		context.Background(),
		"scope-test",
		root,
		pathObservation.ObjectIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}

	if pathObservation.CollectionEntryMethod != CollectionEntryPath {
		t.Fatalf("path collection entry = %q", pathObservation.CollectionEntryMethod)
	}
	if idObservation.CollectionEntryMethod != CollectionEntryNTFSFileID {
		t.Fatalf("ID collection entry = %q", idObservation.CollectionEntryMethod)
	}
	if !reflect.DeepEqual(idObservation.VolumeIdentity, pathObservation.VolumeIdentity) {
		t.Fatalf("ID volume = %+v, path volume = %+v", idObservation.VolumeIdentity, pathObservation.VolumeIdentity)
	}
	if !reflect.DeepEqual(idObservation.ObjectIdentity, pathObservation.ObjectIdentity) {
		t.Fatalf("ID identity = %+v, path identity = %+v", idObservation.ObjectIdentity, pathObservation.ObjectIdentity)
	}
	if !reflect.DeepEqual(idObservation.ParentBinding, pathObservation.ParentBinding) {
		t.Fatalf("ID parent = %+v, path parent = %+v", idObservation.ParentBinding, pathObservation.ParentBinding)
	}
	if idObservation.PathBinding.ResolvedPathUTF16LEBase64URL != pathObservation.PathBinding.ResolvedPathUTF16LEBase64URL {
		t.Fatalf("ID resolved path differs from path collection")
	}
	if idObservation.PathBinding.RequestedPathUTF16LEBase64URL != idObservation.PathBinding.ResolvedPathUTF16LEBase64URL {
		t.Fatalf("ID-open path binding should be handle-resolved current path")
	}
}
