// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// removeRawGenerationWithCustody is the single prospective deletion boundary
// for the normal generation builder and both restart-recovery paths.
//
// Unrelated non-USN generations retain their existing retirement behavior.
// USN generations must pass complete committed-ledger and sealed-payload
// verification, but still fail closed until the durable authorization and
// interrupted-deletion transaction are implemented. A successful preflight
// is deliberately NOT a retirement authorization.
func removeRawGenerationWithCustody(
	ctx context.Context,
	raw RawGeneration,
	stateDir, sealedDir, sourceID string,
) error {
	if ctx == nil {
		return errors.New("FI generation custody context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	info, err := os.Lstat(raw.GenerationDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI raw generation path is not a real directory")
	}

	err = guardRawGenerationRetirement(raw.GenerationDir)
	switch {
	case err == nil:
		return os.RemoveAll(raw.GenerationDir)
	case !errors.Is(err, ErrSourceCustodyHandoffRequired):
		return fmt.Errorf("verify frozen FI generation before retirement: %w", err)
	}

	if strings.TrimSpace(stateDir) == "" ||
		strings.TrimSpace(sealedDir) == "" ||
		strings.TrimSpace(sourceID) == "" {
		return fmt.Errorf(
			"%w: sender custody state, sealed generation, and source identity are required",
			ErrSourceCustodyHandoffRequired,
		)
	}

	proof, err := usncapture.VerifyDiscoveredCommittedGeneration(
		ctx, stateDir, raw.GenerationDir, sealedDir, sourceID,
	)
	if err != nil {
		return fmt.Errorf(
			"verify committed FI source-to-sealed custody: %w", err,
		)
	}
	if proof.GenerationID != raw.GenerationID ||
		proof.SourceID != sourceID {
		return fmt.Errorf(
			"%w: preflight generation/source identity differs from frozen source",
			ErrSourceCustodyHandoffRequired,
		)
	}

	if _, err := recordVerifiedGenerationCustody(sealedDir, proof); err != nil {
		return fmt.Errorf("record verified FI generation custody: %w", err)
	}

	// A persisted verification receipt is not a deletion authorization.
	// Raw tombstone and interrupted-deletion recovery are not integrated.
	return fmt.Errorf(
		"%w: generation %s verified but durable retirement authorization is not integrated",
		ErrSourceCustodyHandoffRequired,
		raw.GenerationID,
	)
}
