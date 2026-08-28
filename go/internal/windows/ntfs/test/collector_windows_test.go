// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package test

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func TestCollectPathIncludesIntegratedContentHashes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "integrated-hash.txt")
	content := []byte("FI integrated content hash\r\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := ntfs.CollectPath(context.Background(), "test", root, path)
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

	first, err := ntfs.CollectPath(context.Background(), "test", root, path)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := ntfs.CollectFileReference(context.Background(), "test", root, first.ObjectIdentity)
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

	observation, err := ntfs.CollectPath(context.Background(), "test", root, root)
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

func TestCollectPathStructuralDoesNotHashContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "structural-only.txt")
	if err := os.WriteFile(path, []byte("do not hash in focused diagnostic mode"), 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := ntfs.CollectPathStructural(context.Background(), "test", root, path)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ContentHashes != nil {
		t.Fatalf("structural collection unexpectedly returned content hashes: %+v", observation.ContentHashes)
	}
}

func TestCollectFileReferenceMatchesPathObservation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")
	if err := os.WriteFile(target, []byte("same object"), 0o600); err != nil {
		t.Fatal(err)
	}

	pathObservation, err := ntfs.CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}
	idObservation, err := ntfs.CollectFileReference(
		context.Background(),
		"scope-test",
		root,
		pathObservation.ObjectIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}

	if pathObservation.CollectionEntryMethod != ntfs.CollectionEntryPath {
		t.Fatalf("path collection entry = %q", pathObservation.CollectionEntryMethod)
	}
	if idObservation.CollectionEntryMethod != ntfs.CollectionEntryNTFSFileID {
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
		t.Fatal("ID resolved path differs from path collection")
	}
	if idObservation.PathBinding.RequestedPathUTF16LEBase64URL != idObservation.PathBinding.ResolvedPathUTF16LEBase64URL {
		t.Fatal("ID-open path binding should be handle-resolved current path")
	}
}

func TestCollectPathObservedAt(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")
	if err := os.WriteFile(target, []byte("time"), 0o600); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC()
	observation, err := ntfs.CollectPath(context.Background(), "scope-test", root, target)
	after := time.Now().UTC()
	if err != nil {
		t.Fatal(err)
	}

	observedAt, err := time.Parse("2006-01-02T15:04:05.000000000Z", observation.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if observedAt.Before(before) || observedAt.After(after) {
		t.Fatalf("observed_at = %s outside [%s, %s]", observedAt, before, after)
	}
}

// Native Windows integration test: create a real NTFS file and ADS, collect it,
// and verify the returned source facts.
func TestCollectPathOnWindowsNTFS(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")

	if err := os.WriteFile(target, []byte("file intelligence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+`:payload`, []byte("hidden stream"), 0o600); err != nil {
		t.Fatal(err)
	}

	observation, err := ntfs.CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}

	if observation.SubjectKind != records.SubjectFile {
		t.Fatalf("subject kind = %s", observation.SubjectKind)
	}
	if observation.Metadata.LogicalSize != strconv.Itoa(len("file intelligence")) {
		t.Fatalf("logical size = %s", observation.Metadata.LogicalSize)
	}
	if observation.VolumeIdentity.VolumeGUID == "" ||
		observation.ObjectIdentity.FileReferenceNumber == "" {
		t.Fatalf("identity is incomplete: %+v %+v", observation.VolumeIdentity, observation.ObjectIdentity)
	}
	if observation.GovernedRoot.ScopeID != "scope-test" ||
		observation.GovernedRoot.ObjectIdentity.FileReferenceNumber == "" ||
		observation.Containment.MethodVersion == "" {
		t.Fatalf("scope result is incomplete: %+v %+v", observation.GovernedRoot, observation.Containment)
	}
	if observation.ObservedAt == "" {
		t.Fatal("observed_at is empty")
	}

	switch observation.ObservationStatus {
	case records.ObservationComplete:
		if observation.SACL.State != records.ObservationStatePresent {
			t.Fatalf("complete observation has SACL state %q", observation.SACL.State)
		}
	case records.ObservationPartial:
		if observation.SACL.State != records.ObservationStateError {
			t.Fatalf("partial observation has unexpected SACL state %q", observation.SACL.State)
		}
		if observation.SACL.ReasonCode != "SACLPrivilegeUnavailable" &&
			observation.SACL.ReasonCode != "SACLDescriptorReadFailed" {
			t.Fatalf("partial observation has unexpected SACL reason %q", observation.SACL.ReasonCode)
		}
	default:
		t.Fatalf("status = %s", observation.ObservationStatus)
	}

	foundDefault := false
	foundADS := false
	for _, stream := range observation.StreamInventory.Streams {
		if stream.Identity.Kind == records.StreamDefaultData {
			foundDefault = true
		}
		if stream.Identity.Kind == records.StreamNamedData {
			foundADS = true
		}
	}
	if !foundDefault || !foundADS {
		t.Fatalf("stream inventory missing default or named data stream: %+v", observation.StreamInventory.Streams)
	}
}

func TestCollectPathRejectsFileGovernedRoot(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-root.txt")
	if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ntfs.CollectPath(context.Background(), "scope-test", file, file)
	if !errors.Is(err, ntfs.ErrGovernedRootNotDirectory) {
		t.Fatalf("error = %v, want ErrGovernedRootNotDirectory", err)
	}
}

func TestCollectPathRejectsSiblingEscape(t *testing.T) {
	root := t.TempDir()
	outsideRoot := t.TempDir()
	target := filepath.Join(outsideRoot, "outside.txt")

	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ntfs.CollectPath(context.Background(), "scope-test", root, target)
	if !errors.Is(err, ntfs.ErrOutsideGovernedRoot) {
		t.Fatalf("error = %v, want ErrOutsideGovernedRoot", err)
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
