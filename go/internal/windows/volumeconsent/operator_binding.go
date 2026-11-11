// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumeconsent

import (
	"encoding/json"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumereview"
)

// VerifyFreshInstallForOperator verifies the entire signed fresh-install
// approval, then binds its signed ApproverSID to an independently observed
// installer process-token user SID. The caller MUST obtain operatorSID from
// the actual Windows primary token, never from the receipt, an environment
// variable, a command-line option, or user-writable configuration.
//
// This is a read-only identity-consistency check. It does NOT authenticate
// operator presence or affirmative consent, prove token elevation, establish
// a trusted signing-key issuer, reserve ProgramData, or authorize any write.
// The native caller must separately enforce those security gates.
func VerifyFreshInstallForOperator(
	encoded []byte,
	expected Expected,
	requested config.VolumeConfig,
	review volumereview.Review,
	freshNative []volumediscovery.Snapshot,
	operatorSID string,
) error {
	if !validSID(operatorSID) {
		return fmt.Errorf("%w: missing or malformed independently observed operator SID", ErrUnauthorizedReceipt)
	}
	// Authenticate the entire signed receipt, host, generation, canonical
	// review and fresh native discovery BEFORE trusting its approver field.
	if err := VerifyFreshInstall(encoded, expected, requested, review, freshNative); err != nil {
		return err
	}
	// VerifyFreshInstall already established the canonical, bounded and
	// signature-authenticated envelope. This second decode is solely to
	// compare its signed subject to independent native process-token data.
	var receipt Receipt
	if err := json.Unmarshal(encoded, &receipt); err != nil {
		return fmt.Errorf("%w: authenticated receipt cannot be decoded", ErrInvalidReceipt)
	}
	if receipt.Payload.ApproverSID != operatorSID {
		return fmt.Errorf("%w: verified approver does not match actual installer process user", ErrUnauthorizedReceipt)
	}
	return nil
}
