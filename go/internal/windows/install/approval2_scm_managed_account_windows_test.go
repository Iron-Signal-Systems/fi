// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestValidateApproval2ManagedServiceAccount(t *testing.T) {
	t.Parallel()

	valid := []string{
		`ISS\gFI-ADMINBOX$`,
		`ISS\gFI-USN-ADMINBOX$`,
		`ISS\gFI-OBJ-ADMINBOX$`,
	}

	for _, account := range valid {
		account := account
		t.Run(
			account,
			func(t *testing.T) {
				t.Parallel()

				if err := validateApproval2ManagedServiceAccount(
					account,
				); err != nil {
					t.Fatalf(
						"validateApproval2ManagedServiceAccount(%q): %v",
						account,
						err,
					)
				}
			},
		)
	}

	invalid := []string{
		"",
		`gFI-ADMINBOX$`,
		`ISS\gFI-ADMINBOX`,
		`\gFI-ADMINBOX$`,
		`ISS\`,
	}

	for _, account := range invalid {
		account := account
		t.Run(
			"reject_"+account,
			func(t *testing.T) {
				t.Parallel()

				if err := validateApproval2ManagedServiceAccount(
					account,
				); err == nil {
					t.Fatalf(
						"validateApproval2ManagedServiceAccount(%q) unexpectedly succeeded",
						account,
					)
				}
			},
		)
	}
}
