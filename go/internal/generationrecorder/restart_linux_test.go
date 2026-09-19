// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package generationrecorder

import (
	"os"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func TestRecordDiscoveredCustodyDurablyNewAndAlreadyRecorded(
	t *testing.T,
) {
	fixture := newCustodyRecorderFixture(t, false)

	recovery, err := transportgeneration.RecoverDurableCustodyRoot(
		fixture.custodyConfig,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(recovery.Objects) != 1 {
		t.Fatalf("objects = %d, want 1", len(recovery.Objects))
	}

	first, err := RecordDiscoveredCustodyDurably(
		recovery.Objects[0],
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err != nil {
		t.Fatal(err)
	}

	if first.Disposition != RecordedDispositionNew {
		t.Fatalf(
			"first disposition = %q, want NEW",
			first.Disposition,
		)
	}

	second, err := RecordDiscoveredCustodyDurably(
		recovery.Objects[0],
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err != nil {
		t.Fatal(err)
	}

	if second.Disposition != RecordedDispositionAlreadyRecorded {
		t.Fatalf(
			"second disposition = %q, want ALREADY_RECORDED",
			second.Disposition,
		)
	}

	if second.ReceiptSHA256 != first.ReceiptSHA256 ||
		second.ReceiptPath != first.ReceiptPath {
		t.Fatal("restart replay changed durable recorder receipt identity")
	}

	if _, err := os.Lstat(fixture.custody.CustodyPath); err != nil {
		t.Fatalf("restart recording removed durable custody object: %v", err)
	}
}

func TestRecordDiscoveredCustodyDurablyRejectsSemanticFailureWithoutReceipt(
	t *testing.T,
) {
	fixture := newCustodyRecorderFixture(t, true)

	recovery, err := transportgeneration.RecoverDurableCustodyRoot(
		fixture.custodyConfig,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = RecordDiscoveredCustodyDurably(
		recovery.Objects[0],
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err == nil {
		t.Fatal("restart-discovered generation with invalid collector semantics was recorded")
	}

	assertRecordedRootEmpty(t, fixture.recorderConfig.RootDir)
}

func TestRecordDiscoveredCustodyDurablyRejectsMutationAfterDiscoveryWithoutReceipt(
	t *testing.T,
) {
	fixture := newCustodyRecorderFixture(t, false)

	recovery, err := transportgeneration.RecoverDurableCustodyRoot(
		fixture.custodyConfig,
	)
	if err != nil {
		t.Fatal(err)
	}

	candidate := recovery.Objects[0]

	if err := os.Chmod(candidate.Path, 0o600); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(candidate.Path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := file.WriteAt([]byte{0xff}, 0); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(candidate.Path, 0o400); err != nil {
		t.Fatal(err)
	}

	_, err = RecordDiscoveredCustodyDurably(
		candidate,
		fixture.custodyConfig,
		fixture.recorderConfig,
	)
	if err == nil {
		t.Fatal("mutated restart-discovered custody object was recorded")
	}

	assertRecordedRootEmpty(t, fixture.recorderConfig.RootDir)
}
