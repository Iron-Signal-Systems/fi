// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// InspectRawUSNCustodyRecoveryWithCommittedState independently verifies
// collector custody for every interrupted raw USN retirement.
//
// The configured storage.state_dir supplies the original committed source
// inventories. The verifier compares the complete retired generation with
// its sealed replacement and the sender's durable custody receipt.
//
// This operation is read-only. Successful inspection does not authorize
// promotion, raw reclamation, or any cursor modification.
func InspectRawUSNCustodyRecoveryWithCommittedState(
	ctx context.Context,
	rawRoot, stageRoot, stateDir, sourceID string,
) ([]RawUSNCustodyRecoveryState, error) {
	states, err := InspectRawUSNCustodyRecovery(
		ctx, rawRoot, stageRoot, sourceID,
	)
	if err != nil {
		return nil, err
	}

	if len(states) == 0 {
		return states, nil
	}

	if !filepath.IsAbs(stateDir) {
		return nil, fmt.Errorf(
			"%w: absolute collector custody state directory required",
			ErrSourceCustodyHandoffRequired,
		)
	}

	for _, state := range states {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Recheck the original committed ledger identities, tombstoned
		// raw bytes, and entire signed sealed-generation payload.
		proof, err := usncapture.VerifyDiscoveredRetiredCommittedGeneration(
			ctx,
			stateDir,
			state.TombstoneDir,
			state.SealedDir,
			sourceID,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: verify committed tombstone %s: %w",
				ErrSourceCustodyHandoffRequired,
				state.GenerationID,
				err,
			)
		}

		// The sender receipt must describe exactly the same verified
		// source set and signed replacement.
		receiptPath, err := generationSourceCustodyPath(
			state.SealedDir,
			state.GenerationID,
		)
		if err != nil {
			return nil, err
		}

		receipt, found, err := readSourceCustodyReceipt(receiptPath)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf(
				"%w: source custody receipt absent for %s",
				ErrGenerationSourceCustodyConflict,
				state.GenerationID,
			)
		}

		if err := matchCommittedRawCustodyReceipt(
			receipt, proof,
		); err != nil {
			return nil, fmt.Errorf(
				"compare committed tombstone %s with sender receipt: %w",
				state.GenerationID,
				err,
			)
		}
	}

	return states, nil
}

// matchCommittedRawCustodyReceipt compares every persisted identity and
// digest with the independently reconstructed committed-generation proof.
//
// Neither a locally valid receipt hash nor a signed payload alone proves
// original collector custody. Both must describe the same source set.
func matchCommittedRawCustodyReceipt(
	receipt GenerationSourceCustodyReceipt,
	proof usncapture.CommittedGenerationPreflight,
) error {
	if err := validateSourceCustodyReceipt(receipt); err != nil {
		return err
	}

	expected := GenerationSourceCustodyReceipt{
		Version:              generationSourceCustodyVersion,
		GenerationID:         proof.GenerationID,
		SourceID:             proof.SourceID,
		SignedMetadataSHA256: proof.SignedMetadataSHA256,
		CanonicalSHA256:      proof.CanonicalSHA256,
		EncodedSHA256:        proof.EncodedSHA256,
		SourceBatchSHA256: append(
			[]string(nil), proof.SourceBatchSHA256...,
		),
		SourceLedgerSHA256: append(
			[]string(nil), proof.SourceLedgerSHA256...,
		),
	}

	var err error
	expected.SHA256, err = sourceCustodyReceiptHash(expected)
	if err != nil {
		return err
	}

	if err := validateSourceCustodyReceipt(expected); err != nil {
		return err
	}

	if !reflect.DeepEqual(receipt, expected) {
		return ErrGenerationSourceCustodyConflict
	}

	return nil
}
