// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// sourceCustodyTestFixture provides a synthetic preflight solely to test
// receipt storage. Production obtains this proof through full verification.
func sourceCustodyTestFixture(
	t *testing.T,
) (string, usncapture.CommittedGenerationPreflight) {
	t.Helper()

	stageRoot := t.TempDir()
	buildRoot := filepath.Join(
		stageRoot,
		generationTransportBuildRootDirectoryName,
	)

	if err := os.Mkdir(buildRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	sealedDir := filepath.Join(
		buildRoot,
		"generation-custody-test",
	)

	if err := os.Mkdir(sealedDir, 0o700); err != nil {
		t.Fatal(err)
	}

	return sealedDir, usncapture.CommittedGenerationPreflight{
		GenerationID:         "custody-test",
		SourceID:             "fi-test-source",
		SignedMetadataSHA256: strings.Repeat("a", 64),
		CanonicalSHA256:      strings.Repeat("b", 64),
		EncodedSHA256:        strings.Repeat("c", 64),
		SourceBatchSHA256:    []string{strings.Repeat("d", 64)},
		SourceLedgerSHA256:   []string{strings.Repeat("e", 64)},
	}
}

func TestGenerationSourceCustodyReceiptSurvivesPrivateToActive(
	t *testing.T,
) {
	sealed, proof := sourceCustodyTestFixture(t)

	first, err := recordVerifiedGenerationCustody(sealed, proof)
	if err != nil {
		t.Fatal(err)
	}

	if first.Version != generationSourceCustodyVersion ||
		first.SHA256 == "" {
		t.Fatalf("invalid recorded custody identity: %+v", first)
	}

	duplicate, err := recordVerifiedGenerationCustody(sealed, proof)
	if err != nil || !reflect.DeepEqual(first, duplicate) {
		t.Fatalf(
			"non-idempotent custody replay: %+v %v",
			duplicate, err,
		)
	}

	active := filepath.Join(
		filepath.Dir(filepath.Dir(sealed)),
		filepath.Base(sealed),
	)

	if err := os.Rename(sealed, active); err != nil {
		t.Fatal(err)
	}

	again, err := recordVerifiedGenerationCustody(active, proof)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatalf(
			"custody lost on promotion: %+v %v",
			again, err,
		)
	}
}

func TestGenerationSourceCustodyReceiptRejectsConflictingIdentity(
	t *testing.T,
) {
	sealed, proof := sourceCustodyTestFixture(t)

	first, err := recordVerifiedGenerationCustody(sealed, proof)
	if err != nil {
		t.Fatal(err)
	}

	changed := proof
	changed.EncodedSHA256 = strings.Repeat("f", 64)

	if _, err := recordVerifiedGenerationCustody(
		sealed, changed,
	); !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("different signed payload accepted: %v", err)
	}

	stored, err := recordVerifiedGenerationCustody(sealed, proof)
	if err != nil || !reflect.DeepEqual(first, stored) {
		t.Fatalf(
			"conflicting replay replaced original receipt: %+v %v",
			stored, err,
		)
	}
}

func TestGenerationSourceCustodyReceiptRejectsCorruption(t *testing.T) {
	sealed, proof := sourceCustodyTestFixture(t)

	if _, err := recordVerifiedGenerationCustody(sealed, proof); err != nil {
		t.Fatal(err)
	}

	path, err := generationSourceCustodyPath(
		sealed, proof.GenerationID,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		path,
		[]byte(`{"version":"altered"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := recordVerifiedGenerationCustody(
		sealed, proof,
	); !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("damaged receipt accepted: %v", err)
	}
}

func TestGenerationSourceCustodyReceiptRejectsInvalidProof(
	t *testing.T,
) {
	sealed, proof := sourceCustodyTestFixture(t)
	proof.SourceLedgerSHA256[0] = "not-a-digest"

	if _, err := recordVerifiedGenerationCustody(
		sealed, proof,
	); !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("invalid ledger digest accepted: %v", err)
	}
}
