// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func provisionTestSourceNamespace(
	t *testing.T,
	fixture durableRecorderFixture,
) string {
	t.Helper()

	parent := filepath.Join(fixture.recordedRoot, "sources")

	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	sourceRoot, err := RecordedSourceDirectory(
		fixture.recordedRoot,
		fixture.transfer.Descriptor.SourceID,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	return sourceRoot
}

func TestRecordedSourcePublicationOptIn(t *testing.T) {
	fixture := newDurableRecorderFixture(t)
	fixture.sourceNamespaces = true

	sourceRoot := provisionTestSourceNamespace(t, fixture)

	first := recordDurableFixture(
		t,
		fixture,
		fixture.transfer,
		nil,
	)

	if first.Disposition != RecordedDispositionNew {
		t.Fatalf("first disposition=%q", first.Disposition)
	}

	expected := filepath.Join(
		sourceRoot,
		RecordedReceiptObjectName(
			fixture.transfer.Descriptor.SourceID,
			fixture.transfer.Descriptor.GenerationID,
		),
	)

	if first.ReceiptPath != expected {
		t.Fatalf(
			"receipt path=%q expected=%q",
			first.ReceiptPath,
			expected,
		)
	}

	original, err := os.ReadFile(first.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(first.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}

	if !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o400 {
		t.Fatal("published receipt is not immutable 0400")
	}

	if _, err := os.Lstat(filepath.Join(
		fixture.recordedRoot,
		filepath.Base(expected),
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected flat receipt publication: %v", err)
	}

	second := recordDurableFixture(
		t,
		fixture,
		fixture.transfer,
		nil,
	)

	if second.Disposition != RecordedDispositionAlreadyRecorded {
		t.Fatalf("retry disposition=%q", second.Disposition)
	}

	if second.ReceiptPath != first.ReceiptPath ||
		second.ReceiptSHA256 != first.ReceiptSHA256 {
		t.Fatal("recorder retry changed receipt identity")
	}

	after, err := os.ReadFile(first.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(original, after) {
		t.Fatal("recorder retry changed immutable receipt bytes")
	}

	entries, err := os.ReadDir(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 1 {
		t.Fatalf("source namespace entries=%d, want 1", len(entries))
	}
}

func TestRecordedSourcePublicationRequiresNamespace(t *testing.T) {
	fixture := newDurableRecorderFixture(t)
	fixture.sourceNamespaces = true

	_, err := recordDurableFixtureResult(
		t,
		fixture,
		fixture.transfer,
		nil,
	)

	if err == nil {
		t.Fatal("missing namespace accepted")
	}

	assertRecordedRootEmpty(t, fixture.recordedRoot)
}

func TestRecordedSourcePublicationRejectsWritableDirectory(t *testing.T) {
	fixture := newDurableRecorderFixture(t)
	fixture.sourceNamespaces = true

	sourceRoot := provisionTestSourceNamespace(t, fixture)

	if err := os.Chmod(sourceRoot, 0o770); err != nil {
		t.Fatal(err)
	}

	_, err := recordDurableFixtureResult(
		t,
		fixture,
		fixture.transfer,
		nil,
	)

	if err == nil {
		t.Fatal("writable source namespace accepted")
	}

	entries, err := os.ReadDir(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed publication left source receipt artifacts")
	}
}

func TestRecordedSourcePublicationRejectsSymlink(t *testing.T) {
	fixture := newDurableRecorderFixture(t)
	fixture.sourceNamespaces = true

	parent := filepath.Join(fixture.recordedRoot, "sources")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	sourceRoot, err := RecordedSourceDirectory(
		fixture.recordedRoot,
		fixture.transfer.Descriptor.SourceID,
	)
	if err != nil {
		t.Fatal(err)
	}

	external := t.TempDir()
	if err := os.Symlink(external, sourceRoot); err != nil {
		t.Fatal(err)
	}

	_, err = recordDurableFixtureResult(
		t,
		fixture,
		fixture.transfer,
		nil,
	)

	if err == nil {
		t.Fatal("symlinked source namespace accepted")
	}

	entries, err := os.ReadDir(external)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed publication wrote outside source namespace")
	}
}
