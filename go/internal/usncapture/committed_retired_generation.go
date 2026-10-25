// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import "context"

// VerifyDiscoveredRetiredCommittedGeneration verifies captured USN source
// ownership directly from a raw retirement tombstone.
//
// The committed source ledgers are read without opening a capture Store.
// The physical tombstone must match the signed generation ID, while ledger
// ownership remains bound to the original generation-<ID> identity.
//
// This function is read-only. A successful result cannot authorize deletion,
// generation promotion, cursor advancement, or receiver acknowledgement.
func VerifyDiscoveredRetiredCommittedGeneration(
	ctx context.Context,
	stateDir, retiredDir, sealedDir, sourceID string,
) (CommittedGenerationPreflight, error) {
	ledgers, err := DiscoverCommittedGenerationLedgers(
		ctx, stateDir, retiredDir,
	)
	if err != nil {
		return CommittedGenerationPreflight{}, err
	}

	return VerifyCommittedRetiredGenerationPreflight(
		ctx, retiredDir, sealedDir, sourceID, ledgers,
	)
}
