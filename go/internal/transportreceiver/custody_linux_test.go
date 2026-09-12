// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests.

func TestCustodyObjectNameDistinguishesEmbeddedSeparators(t *testing.T) {
	first := custodyObjectName("a", "b\x00c")
	second := custodyObjectName("a\x00b", "c")

	if first == second {
		t.Fatalf(
			"custody object names collide across distinct length-delimited identities: %q",
			first,
		)
	}
}

func TestCustodyObjectNameDoesNotExposePathMaterial(t *testing.T) {
	name := custodyObjectName(
		`source/../../unexpected`,
		`batch/../../unexpected`,
	)

	if strings.ContainsAny(name, `/\\`) {
		t.Fatalf("custody object name %q contains a path separator", name)
	}
	if !strings.HasPrefix(name, "batch-") || !strings.HasSuffix(name, ".fiwb") {
		t.Fatalf("custody object name = %q, want batch-<digest>.fiwb", name)
	}
	if len(name) != len("batch-")+64+len(".fiwb") {
		t.Fatalf("custody object name length = %d, want %d", len(name), len("batch-")+64+len(".fiwb"))
	}
}

func TestReceiveToDurableCustody(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	reader := bytes.NewReader(append(frame, []byte("NEXT")...))
	root := t.TempDir()

	result, err := ReceiveToDurableCustody(
		reader,
		CustodyConfig{
			Intake:  fixture.config,
			RootDir: root,
		},
	)
	if err != nil {
		t.Fatalf("ReceiveToDurableCustody() error = %v", err)
	}

	descriptor := fixture.signedBatch.Descriptor
	if result.SourceID != descriptor.SourceID {
		t.Fatalf("SourceID = %q, want %q", result.SourceID, descriptor.SourceID)
	}
	if result.BatchID != descriptor.BatchID {
		t.Fatalf("BatchID = %q, want %q", result.BatchID, descriptor.BatchID)
	}
	if result.DataBytes != descriptor.DataBytes {
		t.Fatalf("DataBytes = %d, want %d", result.DataBytes, descriptor.DataBytes)
	}
	if result.DataSHA256 != descriptor.DataSHA256 {
		t.Fatalf("DataSHA256 = %q, want %q", result.DataSHA256, descriptor.DataSHA256)
	}
	if result.ManifestSHA256 != descriptor.ManifestSHA256 {
		t.Fatalf(
			"ManifestSHA256 = %q, want %q",
			result.ManifestSHA256,
			descriptor.ManifestSHA256,
		)
	}
	if result.FrameBytes != uint64(len(frame)) {
		t.Fatalf("FrameBytes = %d, want %d", result.FrameBytes, len(frame))
	}

	frameDigest := sha256.Sum256(frame)
	wantFrameSHA256 := hex.EncodeToString(frameDigest[:])
	if result.FrameSHA256 != wantFrameSHA256 {
		t.Fatalf(
			"FrameSHA256 = %q, want %q",
			result.FrameSHA256,
			wantFrameSHA256,
		)
	}

	wantPath := filepath.Join(
		root,
		custodyObjectName(descriptor.SourceID, descriptor.BatchID),
	)
	if result.FramePath != wantPath {
		t.Fatalf("FramePath = %q, want %q", result.FramePath, wantPath)
	}

	stored, err := os.ReadFile(result.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, frame) {
		t.Fatal("durable custody object does not equal exact received FI wire frame")
	}

	info, err := os.Stat(result.FramePath)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("custody object mode = %04o, want 0400", info.Mode().Perm())
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("custody root contains %d entries, want 1", len(entries))
	}
	if entries[0].Name() != filepath.Base(result.FramePath) {
		t.Fatalf(
			"custody root entry = %q, want %q",
			entries[0].Name(),
			filepath.Base(result.FramePath),
		)
	}

	remaining := make([]byte, len("NEXT"))
	if _, err := reader.Read(remaining); err != nil {
		t.Fatalf("read following bytes: %v", err)
	}
	if string(remaining) != "NEXT" {
		t.Fatalf("remaining bytes = %q, want NEXT", remaining)
	}
}

func TestReceiveToDurableCustodyDoesNotReplaceExistingObject(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	root := t.TempDir()
	descriptor := fixture.signedBatch.Descriptor
	finalPath := filepath.Join(
		root,
		custodyObjectName(descriptor.SourceID, descriptor.BatchID),
	)
	original := []byte("existing durable object")
	if err := os.WriteFile(finalPath, original, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	_, err := ReceiveToDurableCustody(
		bytes.NewReader(frame),
		CustodyConfig{
			Intake:  fixture.config,
			RootDir: root,
		},
	)
	if err == nil {
		t.Fatal("ReceiveToDurableCustody() error = nil, want existing-object rejection")
	}
	if !errors.Is(err, ErrCustodyAlreadyExists) {
		t.Fatalf(
			"ReceiveToDurableCustody() error = %v, want ErrCustodyAlreadyExists",
			err,
		)
	}

	stored, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, original) {
		t.Fatalf("existing custody object changed to %q", stored)
	}

	assertNoCustodyOpenFiles(t, root)
}

func TestReceiveToDurableCustodyRejectsInvalidBatchWithoutPublishing(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	badData := append([]byte(nil), fixture.data...)
	badData[0] ^= 0x01
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		badData,
	)
	root := t.TempDir()

	_, err := ReceiveToDurableCustody(
		bytes.NewReader(frame),
		CustodyConfig{
			Intake:  fixture.config,
			RootDir: root,
		},
	)
	if err == nil {
		t.Fatal("ReceiveToDurableCustody() error = nil, want data-hash rejection")
	}
	if !strings.Contains(err.Error(), "data SHA-256") {
		t.Fatalf(
			"ReceiveToDurableCustody() error = %q, want data-hash rejection",
			err,
		)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("custody root contains %d entries after rejected batch, want 0", len(entries))
	}
}

func TestReceiveToDurableCustodyRejectsNilReader(t *testing.T) {
	fixture := newIntakeTestFixture(t)

	_, err := ReceiveToDurableCustody(
		nil,
		CustodyConfig{
			Intake:  fixture.config,
			RootDir: t.TempDir(),
		},
	)
	if err == nil {
		t.Fatal("ReceiveToDurableCustody() error = nil, want nil-reader rejection")
	}
	if !strings.Contains(err.Error(), "batch reader is required") {
		t.Fatalf("ReceiveToDurableCustody() error = %q, want nil-reader rejection", err)
	}
}

func TestValidateCustodyConfigRejectsGroupWritableRoot(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatalf("os.Chmod() error = %v", err)
	}

	err := validateCustodyConfig(CustodyConfig{
		Intake:  fixture.config,
		RootDir: root,
	})
	if err == nil {
		t.Fatal("validateCustodyConfig() error = nil, want writable-root rejection")
	}
	if !strings.Contains(err.Error(), "must not be group- or other-writable") {
		t.Fatalf(
			"validateCustodyConfig() error = %q, want writable-root rejection",
			err,
		)
	}
}

func TestValidateCustodyConfigRejectsRelativeRoot(t *testing.T) {
	fixture := newIntakeTestFixture(t)

	err := validateCustodyConfig(CustodyConfig{
		Intake:  fixture.config,
		RootDir: "relative/custody",
	})
	if err == nil {
		t.Fatal("validateCustodyConfig() error = nil, want relative-root rejection")
	}
	if !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf(
			"validateCustodyConfig() error = %q, want absolute-root requirement",
			err,
		)
	}
}

func TestValidateCustodyConfigRejectsSymlinkRoot(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("os.Mkdir() error = %v", err)
	}
	link := filepath.Join(parent, "custody-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink() error = %v", err)
	}

	err := validateCustodyConfig(CustodyConfig{
		Intake:  fixture.config,
		RootDir: link,
	})
	if err == nil {
		t.Fatal("validateCustodyConfig() error = nil, want symlink-root rejection")
	}
	if !strings.Contains(err.Error(), "must not traverse symlinks") {
		t.Fatalf(
			"validateCustodyConfig() error = %q, want symlink-root rejection",
			err,
		)
	}
}

// Test helpers.

func assertNoCustodyOpenFiles(t *testing.T, root string) {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".open") {
			t.Fatalf("provisional custody file remains after operation: %s", entry.Name())
		}
	}
}
