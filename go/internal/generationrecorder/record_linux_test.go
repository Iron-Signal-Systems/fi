// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package generationrecorder

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationsealer"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func TestRecordCanonicalDurablyNewAndAlreadyRecorded(t *testing.T) {
	fixture := newDurableRecorderFixture(t)

	first := recordDurableFixture(t, fixture, fixture.transfer, nil)
	if first.Disposition != RecordedDispositionNew {
		t.Fatalf("first disposition = %q, want NEW", first.Disposition)
	}

	info, err := os.Lstat(first.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
		t.Fatalf("recorded receipt mode = %v, want read-only regular 0400", info.Mode())
	}

	raw, err := os.ReadFile(first.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := UnmarshalRecordedReceipt(raw)
	if err != nil {
		t.Fatalf("UnmarshalRecordedReceipt() error = %v", err)
	}
	if decoded != first.Receipt {
		t.Fatalf("decoded receipt = %#v, want %#v", decoded, first.Receipt)
	}

	second := recordDurableFixture(t, fixture, fixture.transfer, nil)
	if second.Disposition != RecordedDispositionAlreadyRecorded {
		t.Fatalf("second disposition = %q, want ALREADY_RECORDED", second.Disposition)
	}
	if second.ReceiptPath != first.ReceiptPath || second.ReceiptSHA256 != first.ReceiptSHA256 {
		t.Fatal("exact recorder retry changed durable receipt identity")
	}

	entries, err := os.ReadDir(fixture.recordedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("recorded root contains %d entries, want 1", len(entries))
	}
}

func TestRecordCanonicalDurablyConflictFailsClosed(t *testing.T) {
	fixture := newDurableRecorderFixture(t)

	first := recordDurableFixture(t, fixture, fixture.transfer, nil)
	original, err := os.ReadFile(first.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}

	conflicting := fixture.transfer
	conflicting.TransferSHA256 = strings.Repeat("c", 64)

	_, err = recordDurableFixtureResult(t, fixture, conflicting, nil)
	if !errors.Is(err, ErrRecordedGenerationConflict) {
		t.Fatalf("conflicting retry error = %v, want ErrRecordedGenerationConflict", err)
	}

	after, err := os.ReadFile(first.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("recorder conflict changed original durable receipt")
	}
}

func TestRecordCanonicalDurablyRejectsCanonicalHashMismatchWithoutPublication(t *testing.T) {
	fixture := newDurableRecorderFixture(t)

	invalid := fixture.transfer
	invalid.Descriptor.CanonicalSHA256 = strings.Repeat("0", 64)

	_, err := recordDurableFixtureResult(t, fixture, invalid, nil)
	if err == nil {
		t.Fatal("RecordCanonicalDurably() error = nil, want canonical hash rejection")
	}

	assertRecordedRootEmpty(t, fixture.recordedRoot)
}

func TestRecordCanonicalDurablyRejectsTrailingCanonicalBytesWithoutPublication(t *testing.T) {
	fixture := newDurableRecorderFixture(t)

	_, err := recordDurableFixtureResult(
		t,
		fixture,
		fixture.transfer,
		func(reader io.Reader) io.Reader {
			return io.MultiReader(reader, strings.NewReader("unexpected"))
		},
	)
	if err == nil {
		t.Fatal("RecordCanonicalDurably() error = nil, want trailing canonical rejection")
	}

	assertRecordedRootEmpty(t, fixture.recordedRoot)
}

func TestRecordCanonicalDurablyRejectsWritableRoot(t *testing.T) {
	fixture := newDurableRecorderFixture(t)

	if err := os.Chmod(fixture.recordedRoot, 0o770); err != nil {
		t.Fatal(err)
	}

	_, err := recordDurableFixtureResult(t, fixture, fixture.transfer, nil)
	if err == nil {
		t.Fatal("RecordCanonicalDurably() error = nil, want writable-root rejection")
	}
}

func TestRecordedObjectNameSeparatesIdentities(t *testing.T) {
	first := recordedObjectName("ab", "c")
	second := recordedObjectName("a", "bc")

	if first == second {
		t.Fatalf("recorded object names collided: %q", first)
	}

	if filepath.Ext(first) != ".json" || strings.ContainsAny(first, "/\\") {
		t.Fatalf("recorded object name = %q, want safe .record.json basename", first)
	}
}

type durableRecorderFixture struct {
	recordedRoot string
	sealedPath   string
	transfer     transportgeneration.TransferResult
}

func assertRecordedRootEmpty(t *testing.T, root string) {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid generation left %d recorder artifacts, want 0", len(entries))
	}
}

func newDurableRecorderFixture(t *testing.T) durableRecorderFixture {
	t.Helper()

	frozen := t.TempDir()
	writeRecorderBatch(
		t,
		frozen,
		"20260918T163000.000000000Z-0011223344556677",
		[]byte("{\"record\":1}\n{\"record\":2}\n"),
		"",
	)

	sealed := filepath.Join(t.TempDir(), "sealed")
	seal, err := generationsealer.Seal(
		context.Background(),
		generationsealer.Config{
			FrozenDir:    frozen,
			GenerationID: "20260918T163500.000000000Z-0123456789abcdef",
			SealedDir:    sealed,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	descriptor, err := transportgeneration.DescriptorFromSeal(
		"iss-fs-01.iss.local",
		seal,
	)
	if err != nil {
		t.Fatal(err)
	}

	metadataBytes := uint64(512)
	transfer := transportgeneration.TransferResult{
		Descriptor:     descriptor,
		MetadataBytes:  metadataBytes,
		MetadataSHA256: strings.Repeat("a", 64),
		PayloadBytes:   descriptor.EncodedDataBytes,
		PayloadSHA256:  descriptor.EncodedDataSHA256,
		TransferBytes:  generationTransferHeaderBytes + metadataBytes + descriptor.EncodedDataBytes,
		TransferSHA256: strings.Repeat("b", 64),
	}

	recordedRoot := filepath.Join(t.TempDir(), "recorded")
	if err := os.Mkdir(recordedRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	return durableRecorderFixture{
		recordedRoot: recordedRoot,
		sealedPath:   seal.SealedPath,
		transfer:     transfer,
	}
}

func recordDurableFixture(
	t *testing.T,
	fixture durableRecorderFixture,
	transfer transportgeneration.TransferResult,
	wrap func(io.Reader) io.Reader,
) DurableResult {
	t.Helper()

	result, err := recordDurableFixtureResult(t, fixture, transfer, wrap)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func recordDurableFixtureResult(
	t *testing.T,
	fixture durableRecorderFixture,
	transfer transportgeneration.TransferResult,
	wrap func(io.Reader) io.Reader,
) (DurableResult, error) {
	t.Helper()

	encoded, err := os.Open(fixture.sealedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer encoded.Close()

	decoder, err := transportencoding.NewZstdDecoder(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()

	var reader io.Reader = decoder
	if wrap != nil {
		reader = wrap(reader)
	}

	return RecordCanonicalDurably(
		reader,
		transfer,
		DurableConfig{
			RootDir: fixture.recordedRoot,
			Semantic: Config{
				MaxManifestBytes: 1 << 20,
			},
		},
	)
}
