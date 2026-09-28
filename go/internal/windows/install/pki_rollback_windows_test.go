// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestValidateCNGKeyLocatorAcceptsExactFIProvider(
	t *testing.T,
) {
	t.Parallel()

	err := validateCNGKeyLocator(
		cngKeyLocator{
			KeyName:      "fi-test-key",
			KeySpec:      0,
			MachineKey:   true,
			ProviderName: fiPKICNGProviderName,
		},
	)

	if err != nil {
		t.Fatalf(
			"exact FI CNG locator rejected: %v",
			err,
		)
	}
}

func TestValidateCNGKeyLocatorRejectsNonMachineKey(
	t *testing.T,
) {
	t.Parallel()

	err := validateCNGKeyLocator(
		cngKeyLocator{
			KeyName:      "fi-test-key",
			KeySpec:      0,
			MachineKey:   false,
			ProviderName: fiPKICNGProviderName,
		},
	)

	if err == nil {
		t.Fatal(
			"non-machine key unexpectedly accepted",
		)
	}
}

func TestValidateCNGKeyLocatorRejectsWrongProvider(
	t *testing.T,
) {
	t.Parallel()

	err := validateCNGKeyLocator(
		cngKeyLocator{
			KeyName:      "fi-test-key",
			KeySpec:      0,
			MachineKey:   true,
			ProviderName: "Unexpected Provider",
		},
	)

	if err == nil {
		t.Fatal(
			"unexpected CNG provider was accepted",
		)
	}
}

func TestValidateOwnedPKIRollbackMutationRejectsUnowned(
	t *testing.T,
) {
	t.Parallel()

	err := validateOwnedPKIRollbackMutation(
		pkiEnrollmentMutation{
			Certificate: localMachinePKICertificate{
				CertificateSHA256: strings.Repeat(
					"a",
					64,
				),
			},
			Owned: false,
		},
	)

	if err == nil {
		t.Fatal(
			"unowned certificate unexpectedly authorized for rollback",
		)
	}
}

func TestValidateOwnedPKIRollbackMutationAcceptsOwned(
	t *testing.T,
) {
	t.Parallel()

	err := validateOwnedPKIRollbackMutation(
		pkiEnrollmentMutation{
			Certificate: localMachinePKICertificate{
				CertificateSHA256: strings.Repeat(
					"a",
					64,
				),
			},
			Owned: true,
		},
	)

	if err != nil {
		t.Fatalf(
			"owned certificate rejected for rollback: %v",
			err,
		)
	}
}
