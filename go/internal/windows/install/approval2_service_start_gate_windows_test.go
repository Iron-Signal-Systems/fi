// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestApproval2ServiceStartBoundaryRejectsMissingSealedIdentity(
	t *testing.T,
) {
	t.Parallel()

	err :=
		verifyApproval2ServiceStartBoundary(
			approval2ServiceContract{
				Account:    `ISS\gFI-USN-ADMINBOX$`,
				Executable: `C:\Program Files\FI\fi-usn-reader.exe`,
				Name:       "FIUSNReader",
			},
			DesiredFIIdentities{},
		)

	if err == nil {
		t.Fatal(
			"missing sealed service identity unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"not present in the sealed FI identity set",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestApproval2ServiceStartBoundaryRejectsIdentityWithoutSID(
	t *testing.T,
) {
	t.Parallel()

	account :=
		`ISS\gFI-USN-ADMINBOX$`

	err :=
		verifyApproval2ServiceStartBoundary(
			approval2ServiceContract{
				Account:    account,
				Executable: `C:\Program Files\FI\fi-usn-reader.exe`,
				Name:       "FIUSNReader",
			},
			DesiredFIIdentities{
				USNReader: DesiredFIIdentity{
					Account:        account,
					Role:           "FIUSNReader",
					SAMAccountName: `gFI-USN-ADMINBOX$`,
				},
			},
		)

	if err == nil {
		t.Fatal(
			"service identity without sealed SID unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"sealed SID is unavailable",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}
