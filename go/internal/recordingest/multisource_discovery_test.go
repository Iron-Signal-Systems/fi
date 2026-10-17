// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

func TestMultiSourceDiscoveryFiltersValidOtherSource(
	t *testing.T,
) {
	root := t.TempDir()

	sources := []string{
		"iss-fs-01.iss.local",
		"iss-fs-02.iss.local",
	}

	for _, sourceID := range sources {
		raw := []byte(strings.Replace(
			reconcileTestReceipt,
			"iss-fs-01.iss.local",
			sourceID,
			1,
		))

		receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
		if err != nil {
			t.Fatal(err)
		}

		name := generationrecorder.RecordedReceiptObjectName(
			receipt.Descriptor.SourceID,
			receipt.Descriptor.GenerationID,
		)

		if err := os.WriteFile(
			filepath.Join(root, name),
			raw,
			0o400,
		); err != nil {
			t.Fatal(err)
		}
	}

	candidates, err := DiscoverRecordedReceipts(
		root,
		sources[1],
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(candidates) != 1 ||
		candidates[0].SourceID != sources[1] {
		t.Fatalf(
			"source-filtered candidates = %+v",
			candidates,
		)
	}
}

func TestMultiSourceDiscoveryMalformedReceiptFailsClosed(
	t *testing.T,
) {
	root := t.TempDir()

	raw := []byte(reconcileTestReceipt)
	receipt, err := generationrecorder.UnmarshalRecordedReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}

	validName := generationrecorder.RecordedReceiptObjectName(
		receipt.Descriptor.SourceID,
		receipt.Descriptor.GenerationID,
	)

	if err := os.WriteFile(
		filepath.Join(root, validName),
		raw,
		0o400,
	); err != nil {
		t.Fatal(err)
	}

	malformedName := "generation-" +
		strings.Repeat("0", 64) +
		".record.json"

	if err := os.WriteFile(
		filepath.Join(root, malformedName),
		[]byte("{invalid-json"),
		0o400,
	); err != nil {
		t.Fatal(err)
	}

	_, err = DiscoverRecordedReceipts(
		root,
		receipt.Descriptor.SourceID,
	)
	if err == nil {
		t.Fatal(
			"unattributable malformed receipt was silently skipped",
		)
	}

	if !strings.Contains(
		err.Error(),
		"decode FI Phase 3 recorded receipt",
	) {
		t.Fatalf("unexpected discovery failure: %v", err)
	}
}
