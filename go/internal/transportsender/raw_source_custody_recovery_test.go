// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// recoveryTombstoneFixture exercises the existing signed-generation and
// custody receipt fixture, then crosses the real raw tombstone boundary.
func recoveryTombstoneFixture(
	t *testing.T,
) (RawGeneration, string, string, string) {
	t.Helper()

	raw, sealedDir, receipt := rawUSNTombstoneFixture(t)

	_, err := tombstoneVerifiedRawUSNSource(
		context.Background(), raw, sealedDir, receipt,
	)
	if err != nil {
		t.Fatal(err)
	}

	return raw, sealedDir,
		filepath.Dir(raw.GenerationDir),
		filepath.Dir(filepath.Dir(sealedDir))
}

func TestRawUSNCustodyRecoveryInspectsPrivateReplacement(t *testing.T) {
	raw, sealedDir, rawRoot, stageRoot := recoveryTombstoneFixture(t)

	states, err := InspectRawUSNCustodyRecovery(
		context.Background(), rawRoot, stageRoot,
		"fi-custody-test-source",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 ||
		states[0].GenerationID != raw.GenerationID ||
		states[0].SealedDir != sealedDir ||
		states[0].SealedState != "PRIVATE" {
		t.Fatalf("unexpected recovery state: %+v", states)
	}

	if _, err := os.Stat(states[0].TombstoneDir); err != nil {
		t.Fatalf("tombstone removed during inspection: %v", err)
	}
	if _, err := os.Stat(sealedDir); err != nil {
		t.Fatalf("sealed replacement removed during inspection: %v", err)
	}
}

func TestRawUSNCustodyRecoveryInspectsActiveReplacement(t *testing.T) {
	_, sealedDir, rawRoot, stageRoot := recoveryTombstoneFixture(t)

	active := filepath.Join(stageRoot, filepath.Base(sealedDir))
	if err := os.Rename(sealedDir, active); err != nil {
		t.Fatal(err)
	}

	states, err := InspectRawUSNCustodyRecovery(
		context.Background(), rawRoot, stageRoot,
		"fi-custody-test-source",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 ||
		states[0].SealedDir != active ||
		states[0].SealedState != "ACTIVE" {
		t.Fatalf("unexpected promoted recovery state: %+v", states)
	}
}

func TestRawUSNCustodyRecoveryRejectsDuplicateNamespaces(t *testing.T) {
	raw, sealedDir, rawRoot, stageRoot := recoveryTombstoneFixture(t)

	if err := os.Mkdir(raw.GenerationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRawUSNCustodyRecovery(
		context.Background(), rawRoot, stageRoot,
		"fi-custody-test-source",
	); !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("raw and tombstone coexistence accepted: %v", err)
	}

	if err := os.Remove(raw.GenerationDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(
		filepath.Join(stageRoot, filepath.Base(sealedDir)), 0o700,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRawUSNCustodyRecovery(
		context.Background(), rawRoot, stageRoot,
		"fi-custody-test-source",
	); !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("active and private coexistence accepted: %v", err)
	}
}

func TestRawUSNCustodyRecoveryRejectsMissingReceipt(t *testing.T) {
	_, sealedDir, rawRoot, stageRoot := recoveryTombstoneFixture(t)

	receiptPath, err := generationSourceCustodyPath(
		sealedDir, "custody-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(receiptPath); err != nil {
		t.Fatal(err)
	}

	if _, err := InspectRawUSNCustodyRecovery(
		context.Background(), rawRoot, stageRoot,
		"fi-custody-test-source",
	); !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("missing durable receipt accepted: %v", err)
	}
}

func TestRawUSNCustodyRecoveryRejectsMissingOrChangedSealed(
	t *testing.T,
) {
	for _, mode := range []string{"missing", "tampered"} {
		t.Run(mode, func(t *testing.T) {
			_, sealedDir, rawRoot, stageRoot := recoveryTombstoneFixture(t)

			switch mode {
			case "missing":
				if err := os.Rename(
					sealedDir, sealedDir+".missing",
				); err != nil {
					t.Fatal(err)
				}
			case "tampered":
				sealed, err := transportgeneration.LoadSealedGeneration(
					sealedDir,
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(
					sealed.PayloadPath,
					[]byte("modified"), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			}

			if _, err := InspectRawUSNCustodyRecovery(
				context.Background(), rawRoot, stageRoot,
				"fi-custody-test-source",
			); err == nil {
				t.Fatal("missing or altered sealed replacement accepted")
			}
		})
	}
}

func TestRawUSNCustodyRecoveryBlocksPrematurePromotion(t *testing.T) {
	_, sealedDir, rawRoot, stageRoot := recoveryTombstoneFixture(t)

	err := RecoverTransportGenerationBuildsWithCustody(
		context.Background(),
		rawRoot,
		stageRoot,
		"fi-custody-test-source",
		64<<20,
		t.TempDir(),
	)
	if !errors.Is(err, ErrSourceCustodyHandoffRequired) {
		t.Fatalf(
			"incomplete tombstone recovery permitted promotion: %v",
			err,
		)
	}

	if _, err := os.Stat(sealedDir); err != nil {
		t.Fatalf("private sealed generation lost: %v", err)
	}
	if _, err := os.Stat(filepath.Join(
		rawRoot, rawUSNSourceRetiredPrefix+"custody-test",
	)); err != nil {
		t.Fatalf("raw tombstone lost: %v", err)
	}
}
