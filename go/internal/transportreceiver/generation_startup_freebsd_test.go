// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package transportreceiver

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	readyEntries, err := os.ReadDir(config.GenerationReadyRoot)
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
			config.GenerationReadyRoot,
			readyEntries[0].Name(),
		),
	); err != nil {
		t.Fatal(err)
	}

	second, err := RecoverGenerationStartup(
		config,
		fixture.config.Custody.Receive.CurrentTime,
	)
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

	readyEntries, err = os.ReadDir(config.GenerationReadyRoot)
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
