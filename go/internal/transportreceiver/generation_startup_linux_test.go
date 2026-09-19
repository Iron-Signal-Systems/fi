// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
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
		first.AlreadyRecorded != 0 {
		t.Fatalf(
			"first startup result = %#v, want discovered=1 new=1 already=0",
			first,
		)
	}

	if _, err := os.Lstat(custody.CustodyPath); err != nil {
		t.Fatalf(
			"startup recording removed durable custody: %v",
			err,
		)
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
		second.AlreadyRecorded != 1 {
		t.Fatalf(
			"second startup result = %#v, want discovered=1 new=0 already=1",
			second,
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
