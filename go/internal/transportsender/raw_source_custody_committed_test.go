// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// Synthetic proof comparison tests the exact sender-receipt contract.
// The separate usncapture tests establish real committed-ledger verification.
func TestRawUSNCommittedReceiptMatchesVerifiedProof(t *testing.T) {
	sealedDir, proof := sourceCustodyTestFixture(t)

	receipt, err := recordVerifiedGenerationCustody(sealedDir, proof)
	if err != nil {
		t.Fatal(err)
	}

	if err := matchCommittedRawCustodyReceipt(
		receipt, proof,
	); err != nil {
		t.Fatalf("matching preflight receipt rejected: %v", err)
	}

	for _, tc := range []struct {
		name   string
		change func(*usncapture.CommittedGenerationPreflight)
	}{
		{
			"signed-metadata",
			func(p *usncapture.CommittedGenerationPreflight) {
				p.SignedMetadataSHA256 = strings.Repeat("f", 64)
			},
		},
		{
			"canonical",
			func(p *usncapture.CommittedGenerationPreflight) {
				p.CanonicalSHA256 = strings.Repeat("f", 64)
			},
		},
		{
			"encoded",
			func(p *usncapture.CommittedGenerationPreflight) {
				p.EncodedSHA256 = strings.Repeat("f", 64)
			},
		},
		{
			"source-set",
			func(p *usncapture.CommittedGenerationPreflight) {
				p.SourceBatchSHA256 = []string{strings.Repeat("f", 64)}
			},
		},
		{
			"ledger-set",
			func(p *usncapture.CommittedGenerationPreflight) {
				p.SourceLedgerSHA256 = []string{strings.Repeat("f", 64)}
			},
		},
		{
			"source-id",
			func(p *usncapture.CommittedGenerationPreflight) {
				p.SourceID = "another-source"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := proof
			tc.change(&changed)

			err := matchCommittedRawCustodyReceipt(
				receipt, changed,
			)
			if !errors.Is(
				err, ErrGenerationSourceCustodyConflict,
			) {
				t.Fatalf(
					"changed committed proof accepted: %v",
					err,
				)
			}
		})
	}
}

func TestRawUSNCommittedRecoveryFailsClosedWithoutLedgers(
	t *testing.T,
) {
	raw, sealedDir, receipt := rawUSNTombstoneFixture(t)

	if _, err := tombstoneVerifiedRawUSNSource(
		context.Background(), raw, sealedDir, receipt,
	); err != nil {
		t.Fatal(err)
	}

	stageRoot := filepath.Dir(filepath.Dir(sealedDir))
	rawRoot := filepath.Dir(raw.GenerationDir)

	_, err := InspectRawUSNCustodyRecoveryWithCommittedState(
		context.Background(),
		rawRoot,
		stageRoot,
		t.TempDir(),
		receipt.SourceID,
	)
	if !errors.Is(err, ErrSourceCustodyHandoffRequired) {
		t.Fatalf(
			"missing real committed ledgers accepted: %v", err,
		)
	}

	// Failed reconciliation must preserve both custody copies.
	tombstone := filepath.Join(
		rawRoot,
		rawUSNSourceRetiredPrefix+raw.GenerationID,
	)

	if _, err := os.Stat(tombstone); err != nil {
		t.Fatalf(
			"raw tombstone lost after failed verification: %v",
			err,
		)
	}
	if _, err := os.Stat(sealedDir); err != nil {
		t.Fatalf(
			"private sealed generation lost after failed verification: %v",
			err,
		)
	}

	_, err = InspectRawUSNCustodyRecoveryWithCommittedState(
		context.Background(),
		rawRoot,
		stageRoot,
		"",
		receipt.SourceID,
	)
	if !errors.Is(err, ErrSourceCustodyHandoffRequired) {
		t.Fatalf(
			"missing configured state directory accepted: %v",
			err,
		)
	}
}

func TestRawUSNCommittedRecoveryEmptyNamespace(t *testing.T) {
	root := t.TempDir()

	rawRoot := filepath.Join(root, "raw")
	stageRoot := filepath.Join(root, "stage")

	if err := os.Mkdir(rawRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	states, err := InspectRawUSNCustodyRecoveryWithCommittedState(
		context.Background(),
		rawRoot,
		stageRoot,
		"",
		"test-source",
	)

	if err != nil || len(states) != 0 {
		t.Fatalf(
			"empty recovery states=%+v err=%v",
			states, err,
		)
	}
}
