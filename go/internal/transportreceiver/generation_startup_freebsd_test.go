// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package transportreceiver

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

func TestRecoverGenerationStartupDisabledNoOp(
	t *testing.T,
) {
	config := validTestConfig(t)

	result, err := RecoverGenerationStartup(
		config,
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if result != (GenerationStartupResult{}) {
		t.Fatalf(
			"disabled startup result = %#v, want zero",
			result,
		)
	}
}

func TestRecoverGenerationStartupRecordsDiscoveredCustodyAndReplaysIdempotently(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)

	custody := writeStartupGenerationCustody(
		t,
		fixture,
	)

	first, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}

	if first.Discovered != 1 ||
		first.RecordedNew != 1 ||
		first.AlreadyRecorded != 0 ||
		first.ReadyPublished != 1 ||
		first.ReadyWarnings != 0 ||
		first.ReadyWarning != "" {
		t.Fatalf(
			"first startup result = %#v, want discovered=1 new=1 already=0 ready=1 warnings=0",
			first,
		)
	}

	if _, err := os.Lstat(custody.CustodyPath); err != nil {
		t.Fatalf(
			"startup recording removed durable custody: %v",
			err,
		)
	}

	sourceReadyRoot := filepath.Join(
		config.GenerationReadyRoot,
		fixture.config.Custody.Receive.Source.SourceID,
	)

	readyEntries, err := os.ReadDir(sourceReadyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(readyEntries) != 1 {
		t.Fatalf(
			"first startup ready entry count = %d, want 1",
			len(readyEntries),
		)
	}
	if err := os.Remove(
		filepath.Join(
			sourceReadyRoot,
			readyEntries[0].Name(),
		),
	); err != nil {
		t.Fatal(err)
	}

	// Prove the restart does NOT decompress and parse the collector
	// manifest again: this intentionally tiny semantic bound would reject
	// the old full-replay recovery path, but a valid receipt-bound outer
	// transfer must still recover successfully.
	config.GenerationMaxManifestBytes = 1
	var progressCalls int
	second, err := RecoverGenerationStartupWithContext(
		context.Background(),
		config,
		fixture.config.Custody.Receive.CurrentTime,
		func(progress GenerationStartupResult) {
			progressCalls++
			if progress.Discovered != 1 ||
				progress.AlreadyRecorded != 1 ||
				progress.RecordedNew != 0 {
				t.Errorf("unexpected receipt-first recovery progress: %#v", progress)
			}
		},
	)
	if progressCalls != 1 {
		t.Fatalf("receipt-first recovery progress calls = %d, want 1", progressCalls)
	}
	if err != nil {
		t.Fatal(err)
	}

	if second.Discovered != 1 ||
		second.RecordedNew != 0 ||
		second.AlreadyRecorded != 1 ||
		second.ReadyPublished != 0 ||
		second.ReadyWarnings != 0 {
		t.Fatalf(
			"second startup result = %#v, want discovered=1 new=0 already=1 ready=0",
			second,
		)
	}

	readyEntries, err = os.ReadDir(sourceReadyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(readyEntries) != 0 {
		t.Fatalf(
			"already-recorded startup republished %d ready entries",
			len(readyEntries),
		)
	}
}


// TestRecoverGenerationStartupRejectsCorruptRecordedReceipt ensures that a
// present but conflicting receipt is never treated like a missing receipt.
func TestRecoverGenerationStartupRejectsCorruptRecordedReceipt(t *testing.T) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)
	writeStartupGenerationCustody(t, fixture)
	if _, err := RecoverGenerationStartup(config, fixture.config.Custody.Receive.CurrentTime); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(
		fixture.config.Recorder.RootDir,
		generationrecorder.RecordedReceiptObjectName(
			fixture.transfer.Descriptor.SourceID,
			fixture.transfer.Descriptor.GenerationID,
		),
	)
	original, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(receiptPath, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), original...)
	changed[0] ^= 1
	if err := os.WriteFile(receiptPath, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(receiptPath, 0o400); err != nil {
		t.Fatal(err)
	}
	result, err := RecoverGenerationStartup(config, fixture.config.Custody.Receive.CurrentTime)
	if err == nil {
		t.Fatal("corrupt recorded receipt did not block receiver startup")
	}
	if result.AlreadyRecorded != 0 || result.RecordedNew != 0 {
		t.Fatalf("corrupt receipt was incorrectly recorded: %#v", result)
	}
}

// TestRecoverGenerationStartupRejectsMutatedOuterTransfer ensures the stored
// FIGT SHA-256 is checked, even when an apparently valid receipt is present.
func TestRecoverGenerationStartupRejectsMutatedOuterTransfer(t *testing.T) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)
	custody := writeStartupGenerationCustody(t, fixture)
	if _, err := RecoverGenerationStartup(config, fixture.config.Custody.Receive.CurrentTime); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(custody.CustodyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(custody.CustodyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(custody.CustodyPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xaa}, info.Size()-1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(custody.CustodyPath, 0o400); err != nil {
		t.Fatal(err)
	}
	result, err := RecoverGenerationStartup(config, fixture.config.Custody.Receive.CurrentTime)
	if err == nil {
		t.Fatal("mutated compressed transfer did not block receiver startup")
	}
	if result.AlreadyRecorded != 0 || result.RecordedNew != 0 {
		t.Fatalf("corrupt transfer was incorrectly recorded: %#v", result)
	}
}

func TestRecoverGenerationStartupCancellation(t *testing.T) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)
	writeStartupGenerationCustody(t, fixture)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := RecoverGenerationStartupWithContext(
		ctx, config, fixture.config.Custody.Receive.CurrentTime, nil,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("startup cancellation = %v, want context.Canceled", err)
	}
}

func TestRecoverGenerationStartupReadyFailureIsWarningOnly(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)
	config.GenerationReadyRoot = filepath.Join(t.TempDir(), "missing")

	writeStartupGenerationCustody(t, fixture)

	result, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.RecordedNew != 1 ||
		result.ReadyPublished != 0 ||
		result.ReadyWarnings != 1 ||
		result.ReadyWarning == "" {
		t.Fatalf(
			"startup ready failure result = %#v, want recorded new with one warning",
			result,
		)
	}
}

func TestRecoverGenerationStartupSemanticFailureBlocksStartup(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, true)
	config := listenerGenerationConfigFromFixture(t, fixture)

	writeStartupGenerationCustody(
		t,
		fixture,
	)

	result, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err == nil {
		t.Fatal(
			"semantically invalid durable generation did not block startup",
		)
	}

	if result.Discovered != 1 ||
		result.RecordedNew != 0 ||
		result.AlreadyRecorded != 0 {
		t.Fatalf(
			"failed startup result = %#v, want discovered=1 and no recorded state",
			result,
		)
	}

	entries, readErr := os.ReadDir(
		fixture.config.Recorder.RootDir,
	)
	if readErr != nil {
		t.Fatal(readErr)
	}

	if len(entries) != 0 {
		t.Fatalf(
			"semantic startup failure published %d recorder entries",
			len(entries),
		)
	}

	readyEntries, readErr := os.ReadDir(config.GenerationReadyRoot)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(readyEntries) != 0 {
		t.Fatalf(
			"semantic startup failure published %d ready entries",
			len(readyEntries),
		)
	}
}

func TestRecoverGenerationStartupRequiresCurrentTime(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(t, false)
	config := listenerGenerationConfigFromFixture(t, fixture)

	_, err := RecoverGenerationStartup(
		config,
		time.Time{},
	)
	if err == nil {
		t.Fatal("zero startup current time was accepted")
	}
}

func writeStartupGenerationCustody(
	t *testing.T,
	fixture generationTransactionFixture,
) transportgeneration.CustodyResult {
	t.Helper()

	reader := bytes.NewReader(
		fixture.transactionBytes,
	)

	offer, err := transportgeneration.ReadOffer(reader)
	if err != nil {
		t.Fatal(err)
	}

	custody, err := transportgeneration.ReceiveToDurableCustody(
		reader,
		offer,
		fixture.config.Custody,
	)
	if err != nil {
		t.Fatal(err)
	}

	return custody
}

func TestRecoverGenerationStartupUsesSourceLookup(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(
		t,
		false,
	)

	config := listenerGenerationConfigFromFixture(
		t,
		fixture,
	)

	expected := config.Source

	config.Source =
		transporttrust.SourceAuthorization{}

	lookupCount := 0

	config.LookupSource = func(
		sourceID string,
	) (
		transporttrust.SourceAuthorization,
		bool,
	) {
		lookupCount++

		if sourceID != expected.SourceID {
			t.Fatalf(
				"LookupSource sourceID = %q, want %q",
				sourceID,
				expected.SourceID,
			)
		}

		return expected, true
	}

	writeStartupGenerationCustody(
		t,
		fixture,
	)

	result, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Discovered != 1 ||
		result.RecordedNew != 1 {
		t.Fatalf(
			"startup result = %#v, want discovered=1 recorded=1",
			result,
		)
	}

	if lookupCount == 0 {
		t.Fatal(
			"startup recovery did not use source lookup",
		)
	}
}

func TestRecoverGenerationStartupRejectsUnknownSource(
	t *testing.T,
) {
	fixture := newGenerationTransactionFixture(
		t,
		false,
	)

	config := listenerGenerationConfigFromFixture(
		t,
		fixture,
	)

	config.Source =
		transporttrust.SourceAuthorization{}

	config.LookupSource = func(
		sourceID string,
	) (
		transporttrust.SourceAuthorization,
		bool,
	) {
		return transporttrust.SourceAuthorization{},
			false
	}

	writeStartupGenerationCustody(
		t,
		fixture,
	)

	result, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
	if err == nil {
		t.Fatal(
			"unknown restart source was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"is not enrolled",
	) {
		t.Fatalf(
			"startup error = %q, want enrollment rejection",
			err,
		)
	}

	if result.Discovered != 1 ||
		result.RecordedNew != 0 {
		t.Fatalf(
			"startup result = %#v, want discovered=1 recorded=0",
			result,
		)
	}
}
