// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package transportreceiver

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestRecoverGenerationStartupDefersDisabledSourceCustody(t *testing.T) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)
	custody := writeStartupGenerationCustody(t, fixture)

	source := config.Source
	source.Enabled = false
	config.Source = transporttrust.SourceAuthorization{}
	config.LookupSource = func(id string) (transporttrust.SourceAuthorization, bool) {
		if id != source.SourceID {
			return transporttrust.SourceAuthorization{}, false
		}
		return source, true
	}

	result, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Discovered != 1 || result.DeferredDisabled != 1 ||
		result.RecordedNew != 0 || result.AlreadyRecorded != 0 ||
		result.ReadyPublished != 0 {
		t.Fatalf("unexpected deferred startup result: %+v", result)
	}

	if _, err := os.Lstat(custody.CustodyPath); err != nil {
		t.Fatalf("disabled custody was removed: %v", err)
	}

	// Unrecorded disabled custody must not be accepted, silently recorded,
	// or scheduled for ingest by an ordinary receiver restart.
	recorded, err := os.ReadDir(fixture.config.Recorder.RootDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 0 {
		t.Fatalf("disabled custody created %d recorded receipts", len(recorded))
	}
	ready, err := os.ReadDir(config.GenerationReadyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(ready) != 0 {
		t.Fatalf("disabled custody created %d READY entries", len(ready))
	}
}

func TestRecoverGenerationStartupRetirementPreservesRecordedCustody(t *testing.T) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)
	custody := writeStartupGenerationCustody(t, fixture)

	first, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.RecordedNew != 1 || first.DeferredDisabled != 0 {
		t.Fatalf("initial recording failed: %+v", first)
	}

	source := config.Source
	source.Enabled = false
	config.Source = transporttrust.SourceAuthorization{}
	config.LookupSource = func(id string) (transporttrust.SourceAuthorization, bool) {
		return source, id == source.SourceID
	}

	second, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	if second.Discovered != 1 || second.DeferredDisabled != 1 ||
		second.RecordedNew != 0 || second.ReadyPublished != 0 {
		t.Fatalf("historical custody was reprocessed: %+v", second)
	}
	if _, err := os.Lstat(custody.CustodyPath); err != nil {
		t.Fatalf("historical custody missing: %v", err)
	}

	receiptPath := filepath.Join(
		fixture.config.Recorder.RootDir,
		generationrecorder.RecordedReceiptObjectName(
			source.SourceID,
			fixture.transfer.Descriptor.GenerationID,
		),
	)
	receipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("immutable recorded receipt missing: %v", err)
	}
	if !bytes.Contains(receipt, []byte(source.SourceID)) {
		t.Fatal("historical receipt lost its source identity")
	}
}
