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
	if result.Disposition != CustodyDispositionNew {
		t.Fatalf(
			"Disposition = %q, want %q",
			result.Disposition,
			CustodyDispositionNew,
		)
	}

	descriptor := fixture.signedBatch.Descriptor
	assertCustodyResultMatchesFrame(t, result, descriptor.SourceID, descriptor.BatchID, frame)

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

func TestReceiveToDurableCustodyClassifiesConcurrentExactRetry(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	root := t.TempDir()
	config := CustodyConfig{
		Intake:  fixture.config,
		RootDir: root,
	}

	type response struct {
		result DurableCustodyResult
		err    error
	}
	start := make(chan struct{})
	responses := make(chan response, 2)
	for range 2 {
		go func() {
			<-start
			result, err := ReceiveToDurableCustody(bytes.NewReader(frame), config)
			responses <- response{result: result, err: err}
		}()
	}
	close(start)

	first := <-responses
	second := <-responses
	for index, value := range []response{first, second} {
		if value.err != nil {
			t.Fatalf("concurrent ReceiveToDurableCustody() result %d error = %v", index, value.err)
		}
	}

	dispositions := map[CustodyDisposition]int{
		first.result.Disposition:  1,
		second.result.Disposition: 1,
	}
	if first.result.Disposition == second.result.Disposition {
		dispositions[first.result.Disposition] = 2
	}
	if dispositions[CustodyDispositionNew] != 1 ||
		dispositions[CustodyDispositionDuplicate] != 1 {
		t.Fatalf(
			"concurrent dispositions = %q and %q, want one NEW and one DUPLICATE",
			first.result.Disposition,
			second.result.Disposition,
		)
	}

	assertNoCustodyOpenFiles(t, root)
	assertSingleCustodyObject(t, root)
}

func TestReceiveToDurableCustodyRejectsConflict(t *testing.T) {
	firstFixture := newIntakeTestFixture(t)
	firstFrame := encodeIntakeTestFrame(
		t,
		firstFixture.signedBatch,
		firstFixture.manifest,
		firstFixture.data,
	)
	root := t.TempDir()

	firstResult, err := ReceiveToDurableCustody(
		bytes.NewReader(firstFrame),
		CustodyConfig{
			Intake:  firstFixture.config,
			RootDir: root,
		},
	)
	if err != nil {
		t.Fatalf("first ReceiveToDurableCustody() error = %v", err)
	}

	secondFixture := newIntakeTestFixture(t)
	secondFrame := encodeIntakeTestFrame(
		t,
		secondFixture.signedBatch,
		secondFixture.manifest,
		secondFixture.data,
	)
	if bytes.Equal(firstFrame, secondFrame) {
		t.Fatal("independent signed frames unexpectedly match exactly")
	}

	_, err = ReceiveToDurableCustody(
		bytes.NewReader(secondFrame),
		CustodyConfig{
			Intake:  secondFixture.config,
			RootDir: root,
		},
	)
	if err == nil {
		t.Fatal("second ReceiveToDurableCustody() error = nil, want custody conflict")
	}
	if !errors.Is(err, ErrCustodyConflict) {
		t.Fatalf(
			"second ReceiveToDurableCustody() error = %v, want ErrCustodyConflict",
			err,
		)
	}

	stored, err := os.ReadFile(firstResult.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, firstFrame) {
		t.Fatal("custody conflict replaced the original durable object")
	}
	assertNoCustodyOpenFiles(t, root)
	assertSingleCustodyObject(t, root)
}

func TestReceiveToDurableCustodyReturnsDuplicateForExactRetry(t *testing.T) {
	fixture := newIntakeTestFixture(t)
	frame := encodeIntakeTestFrame(
		t,
		fixture.signedBatch,
		fixture.manifest,
		fixture.data,
	)
	root := t.TempDir()
	config := CustodyConfig{
		Intake:  fixture.config,
		RootDir: root,
	}

	first, err := ReceiveToDurableCustody(bytes.NewReader(frame), config)
	if err != nil {
		t.Fatalf("first ReceiveToDurableCustody() error = %v", err)
	}
	second, err := ReceiveToDurableCustody(bytes.NewReader(frame), config)
	if err != nil {
		t.Fatalf("second ReceiveToDurableCustody() error = %v", err)
	}

	if first.Disposition != CustodyDispositionNew {
		t.Fatalf("first Disposition = %q, want NEW", first.Disposition)
	}
	if second.Disposition != CustodyDispositionDuplicate {
		t.Fatalf("second Disposition = %q, want DUPLICATE", second.Disposition)
	}
	if second.FramePath != first.FramePath {
		t.Fatalf("duplicate FramePath = %q, want %q", second.FramePath, first.FramePath)
	}
	if second.FrameSHA256 != first.FrameSHA256 {
		t.Fatalf("duplicate FrameSHA256 = %q, want %q", second.FrameSHA256, first.FrameSHA256)
	}

	stored, err := os.ReadFile(first.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if !bytes.Equal(stored, frame) {
		t.Fatal("exact retry changed durable custody bytes")
	}
	assertNoCustodyOpenFiles(t, root)
	assertSingleCustodyObject(t, root)
}

func TestReceiveToDurableCustodyRejectsExistingMutableObject(t *testing.T) {
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
	if err := os.WriteFile(finalPath, frame, 0o600); err != nil {
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
		t.Fatal("ReceiveToDurableCustody() error = nil, want mutable-object rejection")
	}
	if !strings.Contains(err.Error(), "mode must be 0400") {
		t.Fatalf(
			"ReceiveToDurableCustody() error = %q, want immutable-mode rejection",
			err,
		)
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

func assertCustodyResultMatchesFrame(
	t *testing.T,
	result DurableCustodyResult,
	sourceID string,
	batchID string,
	frame []byte,
) {
	t.Helper()

	if result.SourceID != sourceID {
		t.Fatalf("SourceID = %q, want %q", result.SourceID, sourceID)
	}
	if result.BatchID != batchID {
		t.Fatalf("BatchID = %q, want %q", result.BatchID, batchID)
	}
	if result.FrameBytes != uint64(len(frame)) {
		t.Fatalf("FrameBytes = %d, want %d", result.FrameBytes, len(frame))
	}
	frameDigest := sha256.Sum256(frame)
	wantFrameSHA256 := hex.EncodeToString(frameDigest[:])
	if result.FrameSHA256 != wantFrameSHA256 {
		t.Fatalf("FrameSHA256 = %q, want %q", result.FrameSHA256, wantFrameSHA256)
	}
}

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

func assertSingleCustodyObject(t *testing.T, root string) {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("custody root contains %d entries, want 1", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name(), "batch-") ||
		!strings.HasSuffix(entries[0].Name(), ".fiwb") {
		t.Fatalf("custody root entry = %q, want batch-<digest>.fiwb", entries[0].Name())
	}
}
