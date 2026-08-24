// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectPathIncludesIntegratedContentHashes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "integrated-hash.txt")
	content := []byte("FI integrated content hash\r\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := CollectPath(context.Background(), "test", root, path)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ContentHashes == nil {
		t.Fatal("CollectPath returned nil ContentHashes")
	}
	assertIntegratedHashes(t, *observation.ContentHashes, content)
}

func TestCollectFileReferenceIncludesIntegratedContentHashes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fileid-hash.txt")
	content := []byte("FI File-ID integrated content hash\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := CollectPath(context.Background(), "test", root, path)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := CollectFileReference(context.Background(), "test", root, first.ObjectIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ContentHashes == nil {
		t.Fatal("CollectFileReference returned nil ContentHashes")
	}
	assertIntegratedHashes(t, *observation.ContentHashes, content)
}

func TestCollectPathDirectoryIntegratedHashNotApplicable(t *testing.T) {
	root := t.TempDir()

	observation, err := CollectPath(context.Background(), "test", root, root)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ContentHashes == nil {
		t.Fatal("directory observation returned nil ContentHashes")
	}
	if observation.ContentHashes.State != records.ContentHashNotApplicable {
		t.Fatalf("directory content hash state = %q, want %q", observation.ContentHashes.State, records.ContentHashNotApplicable)
	}
}

func assertIntegratedHashes(t *testing.T, hashes records.ContentHashObservation, content []byte) {
	t.Helper()

	md5Sum := md5.Sum(content)
	sha1Sum := sha1.Sum(content)
	sha256Sum := sha256.Sum256(content)

	if hashes.State != records.ContentHashPresent {
		t.Fatalf("content hash state = %q, want %q; reason=%q detail=%q", hashes.State, records.ContentHashPresent, hashes.ReasonCode, hashes.Detail)
	}
	if hashes.BytesHashed != strconv.Itoa(len(content)) {
		t.Fatalf("bytes_hashed = %q, want %d", hashes.BytesHashed, len(content))
	}
	if hashes.MD5 != hex.EncodeToString(md5Sum[:]) {
		t.Fatalf("md5 = %q", hashes.MD5)
	}
	if hashes.SHA1 != hex.EncodeToString(sha1Sum[:]) {
		t.Fatalf("sha1 = %q", hashes.SHA1)
	}
	if hashes.SHA256 != hex.EncodeToString(sha256Sum[:]) {
		t.Fatalf("sha256 = %q", hashes.SHA256)
	}
}

func TestCollectPathStructuralDoesNotHashContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "structural-only.txt")
	if err := os.WriteFile(path, []byte("do not hash in focused diagnostic mode"), 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := CollectPathStructural(context.Background(), "test", root, path)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ContentHashes != nil {
		t.Fatalf("structural collection unexpectedly returned content hashes: %+v", observation.ContentHashes)
	}
}
