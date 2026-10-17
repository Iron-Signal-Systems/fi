// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func TestM1WorkerRejectsMisplacedValidReceipt(t *testing.T) {
	if os.Getenv("FI_M1_NAMESPACE_READ_TEST") != "1" {
		t.Skip("verified receipt fixture not requested")
	}

	const (
		fs19 = "iss-fs-2019.iss.local"
		fs22 = "iss-fs-22.iss.local"
	)

	original := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-receipts-20261012",
		"namespaced",
		"sources",
		fs19,
	)

	entries, err := os.ReadDir(original)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 104 {
		t.Fatalf("fixture receipts=%d, want 104", len(entries))
	}

	name := entries[0].Name()

	raw, err := os.ReadFile(filepath.Join(original, name))
	if err != nil {
		t.Fatal(err)
	}

	config := provisionWorkerNamespace(t)
	config.SourceID = fs22

	destination := filepath.Join(
		config.RecordedRoot,
		"sources",
		fs22,
		name,
	)

	if err := os.WriteFile(destination, raw, 0400); err != nil {
		t.Fatal(err)
	}

	_, err = workerDiscoverReceiptNames(
		config,
		[]string{name},
	)

	var discovery *recordingest.SourceReceiptDiscoveryError

	if !errors.As(err, &discovery) {
		t.Fatalf(
			"cross-source receipt not classified as discovery failure: %v",
			err,
		)
	}

	if discovery.SourceID != fs22 {
		t.Fatalf(
			"quarantine source=%q, want %q",
			discovery.SourceID,
			fs22,
		)
	}

	config.QuarantineRoot = m1PrivateQuarantineTestDir(t)
	state := &sourceSessionState{
		Config: config,
		QuarantineStore: &m1QuarantineStore{
			Root: config.QuarantineRoot,
		},
	}

	if err := quarantineSourceConflict(state, err); err != nil {
		t.Fatal(err)
	}

	if !state.Quarantined {
		t.Fatal("misplaced receipt did not quarantine FS22")
	}

	t.Log("PASS: READY/retry lookup quarantines receiving namespace")
}
