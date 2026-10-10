// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"strings"
)

func verifyApproval2ServiceStartBoundary(
	contract approval2ServiceContract,
	identities DesiredFIIdentities,
) error {
	identity, found :=
		desiredFIIdentityByAccount(
			identities,
			contract.Account,
		)
	if !found {
		return fmt.Errorf(
			"service %s account %s is not present in the sealed FI identity set",
			contract.Name,
			contract.Account,
		)
	}

	sid, err :=
		authoritativeDesiredFIIdentitySID(
			identity,
		)
	if err != nil {
		return fmt.Errorf(
			"service %s identity revalidation: %w",
			contract.Name,
			err,
		)
	}

	executable := strings.TrimSpace(
		contract.Executable,
	)
	if executable == "" {
		return fmt.Errorf(
			"service %s executable path is empty",
			contract.Name,
		)
	}

	state, err :=
		discoverACL(
			executable,
			"Approval 2 pre-start "+contract.Name+" executable",
		)
	if err != nil {
		return fmt.Errorf(
			"discover executable ACL for service %s path=%s: %w",
			contract.Name,
			executable,
			err,
		)
	}

	sealedSID := strings.ToUpper(
		strings.TrimSpace(
			sid.String(),
		),
	)

	for _, entry := range state.Entries {
		if entry.Type != "DENY" ||
			!strings.EqualFold(
				strings.TrimSpace(
					entry.SID,
				),
				sealedSID,
			) {
			continue
		}

		if entry.Mask&
			fileReadExecuteMask != 0 {
			return fmt.Errorf(
				"service %s executable ACL contains a DENY ACE for sealed_sid=%s mask=0x%08X path=%s",
				contract.Name,
				sealedSID,
				entry.Mask,
				executable,
			)
		}
	}

	if !hasAllowMaskSID(
		state,
		sealedSID,
		fileReadExecuteMask,
		0,
	) {
		return fmt.Errorf(
			"service %s executable does not grant sealed_sid=%s required read/execute mask=0x%08X path=%s",
			contract.Name,
			sealedSID,
			fileReadExecuteMask,
			executable,
		)
	}

	return nil
}
