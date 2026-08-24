// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectContentHashesKnownValues(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "abc.txt")
	if err := os.WriteFile(target, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	observation, err := CollectPath(context.Background(), "hash-test", root, target)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := CollectContentHashes(context.Background(), "hash-test", root, observation.ObjectIdentity, observation.SubjectKind)
	if err != nil {
		t.Fatal(err)
	}
	if hashes.State != records.ContentHashPresent || hashes.BytesHashed != "3" {
		t.Fatalf("hash state = %+v", hashes)
	}
	if hashes.MD5 != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("md5 = %q", hashes.MD5)
	}
	if hashes.SHA1 != "a9993e364706816aba3e25717850c26c9cd0d89d" {
		t.Fatalf("sha1 = %q", hashes.SHA1)
	}
	if hashes.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256 = %q", hashes.SHA256)
	}
}

func TestCollectContentHashesDirectoryNotApplicable(t *testing.T) {
	root := t.TempDir()
	observation, err := CollectPath(context.Background(), "hash-test", root, root)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := CollectContentHashes(context.Background(), "hash-test", root, observation.ObjectIdentity, observation.SubjectKind)
	if err != nil {
		t.Fatal(err)
	}
	if hashes.State != records.ContentHashNotApplicable {
		t.Fatalf("hash state = %+v", hashes)
	}
}
