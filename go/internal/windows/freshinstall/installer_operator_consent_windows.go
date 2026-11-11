// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeconsent"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumereview"
)

// verifyNativeInstallerOperatorReceipt is a PRIVATE, read-only development
// seam. The SID comes only from the actual current primary Windows process
// token, never a caller-selected string. A token query failure, impersonation,
// insufficient elevation, or signed receipt mismatch must fail closed.
//
// Matching a verified approval to this process token is necessary but NOT
// sufficient for authority to install. A future approved transaction still
// needs a trusted issuer and key lifecycle, interactive approval at issuance,
// independently protected installer state, a retained-handle create-only
// journal, write-boundary rechecks and fault/recovery acceptance.
//
// No installer entry point invokes this function. It does not sign a receipt,
// reserve paths, write files, change ACLs, enable privileges, or start services.
func verifyNativeInstallerOperatorReceipt(
	encoded []byte,
	expected volumeconsent.Expected,
	requested config.VolumeConfig,
	review volumereview.Review,
	freshNative []volumediscovery.Snapshot,
) error {
	token, err := inspectNativeInstallerProcessToken()
	if err != nil {
		return fmt.Errorf("%w: native process-token identity unavailable: %v", ErrUnqualifiedInstallerToken, err)
	}
	if err := AssessInstallerTokenEvidence(token); err != nil {
		return fmt.Errorf("%w: actual installer process is ineligible: %v", ErrUnqualifiedInstallerToken, err)
	}
	return volumeconsent.VerifyFreshInstallForOperator(
		encoded, expected, requested, review, freshNative, token.UserSID,
	)
}
