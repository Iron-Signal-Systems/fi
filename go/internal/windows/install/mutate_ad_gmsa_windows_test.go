// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestBuildGMSAPasswordRetrievalDescriptorMatchesObservedFIContract(
	t *testing.T,
) {
	t.Parallel()

	const computerSID = "S-1-5-21-2096275705-3984399647-1579629934-1104"

	descriptor, err := buildGMSAPasswordRetrievalDescriptor(
		computerSID,
	)
	if err != nil {
		t.Fatalf(
			"build descriptor: %v",
			err,
		)
	}

	// The characterized ISS domain computer SID shape produces the same
	// 80-byte self-relative descriptor observed on every accepted FI gMSA.
	if len(descriptor) != 80 {
		t.Fatalf(
			"descriptor length=%d, want 80",
			len(descriptor),
		)
	}

	trustees, err := decodeGMSAMembershipDescriptor(
		descriptor,
	)
	if err != nil {
		t.Fatalf(
			"decode descriptor: %v",
			err,
		)
	}
	if err := verifyExactFIGMSAMembershipTrustee(
		trustees,
		computerSID,
	); err != nil {
		t.Fatalf(
			"verify descriptor: %v",
			err,
		)
	}

	trustee := trustees[0]
	if trustee.Mask != 0x000F01FF {
		t.Fatalf(
			"ACE mask=0x%08X, want 0x000F01FF",
			trustee.Mask,
		)
	}
	if trustee.Flags != 0 {
		t.Fatalf(
			"ACE flags=0x%02X, want 0",
			trustee.Flags,
		)
	}
}

func TestBuildDesiredGMSACreateContractMatchesCharacterizedServer2016State(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		AD: ActiveDirectoryState{
			ComputerObjectKnown:  true,
			ComputerSID:          "S-1-5-21-2096275705-3984399647-1579629934-1104",
			DefaultNamingContext: "DC=iss,DC=local",
			KDSRootKeyCount:      1,
			KDSRootKeyKnown:      true,
		},
		Host: HostState{
			DomainDNS: "iss.local",
		},
	}
	identity := DesiredFIIdentity{
		Account:        `ISS\gFI-USN-ADMINBOX$`,
		Role:           "FIUSNReader",
		SAMAccountName: `gFI-USN-ADMINBOX$`,
	}

	contract, err := buildDesiredGMSACreateContract(
		report,
		identity,
	)
	if err != nil {
		t.Fatalf(
			"build contract: %v",
			err,
		)
	}

	if contract.DistinguishedName !=
		"CN=gFI-USN-ADMINBOX,CN=Managed Service Accounts,DC=iss,DC=local" {
		t.Fatalf(
			"DN=%q",
			contract.DistinguishedName,
		)
	}
	if contract.DNSHostName != "gFI-USN-ADMINBOX.iss.local" {
		t.Fatalf(
			"DNS=%q",
			contract.DNSHostName,
		)
	}
	if contract.ManagedPasswordIntervalDays != 30 {
		t.Fatalf(
			"password interval=%d, want 30",
			contract.ManagedPasswordIntervalDays,
		)
	}
	if contract.SupportedEncryptionTypes != 28 {
		t.Fatalf(
			"encryption types=%d, want 28",
			contract.SupportedEncryptionTypes,
		)
	}
	if contract.UserAccountControl != 4096 {
		t.Fatalf(
			"userAccountControl=%d, want 4096",
			contract.UserAccountControl,
		)
	}
}

func TestVerifyGMSACreateContractAcceptsExactCharacterizedState(
	t *testing.T,
) {
	t.Parallel()

	const computerSID = "S-1-5-21-2096275705-3984399647-1579629934-1104"

	contract := GMSACreateContract{
		ComputerSID:                 computerSID,
		DNSHostName:                 "gFI-USN-ADMINBOX.iss.local",
		DistinguishedName:           "CN=gFI-USN-ADMINBOX,CN=Managed Service Accounts,DC=iss,DC=local",
		ManagedPasswordIntervalDays: 30,
		Role:                        "FIUSNReader",
		SAMAccountName:              "gFI-USN-ADMINBOX$",
		SupportedEncryptionTypes:    28,
		UserAccountControl:          4096,
	}
	observed := ActiveDirectoryGMSAState{
		DNSHostName:                 "gFI-USN-ADMINBOX.iss.local",
		DistinguishedName:           "CN=gFI-USN-ADMINBOX,CN=Managed Service Accounts,DC=iss,DC=local",
		ManagedPasswordIntervalDays: "30",
		PasswordRetrievalTrustees: []GMSAMembershipTrustee{
			{
				Flags: 0,
				Mask:  0x000F01FF,
				SID:   computerSID,
				Type:  "ALLOW",
			},
		},
		Role:                     "FIUSNReader",
		SAMAccountName:           "gFI-USN-ADMINBOX$",
		ServicePrincipalNames:    []string{},
		SupportedEncryptionTypes: "28",
		UserAccountControl:       "4096",
	}

	if err := verifyGMSACreateContract(
		contract,
		observed,
	); err != nil {
		t.Fatalf(
			"verify exact state: %v",
			err,
		)
	}
}

func TestVerifyGMSACreateContractRejectsBroadOrDifferentTrusteeState(
	t *testing.T,
) {
	t.Parallel()

	const computerSID = "S-1-5-21-2096275705-3984399647-1579629934-1104"

	contract := GMSACreateContract{
		ComputerSID:                 computerSID,
		DNSHostName:                 "gFI-USN-ADMINBOX.iss.local",
		DistinguishedName:           "CN=gFI-USN-ADMINBOX,CN=Managed Service Accounts,DC=iss,DC=local",
		ManagedPasswordIntervalDays: 30,
		SAMAccountName:              "gFI-USN-ADMINBOX$",
		SupportedEncryptionTypes:    28,
		UserAccountControl:          4096,
	}
	observed := ActiveDirectoryGMSAState{
		DNSHostName:                 contract.DNSHostName,
		DistinguishedName:           contract.DistinguishedName,
		ManagedPasswordIntervalDays: "30",
		PasswordRetrievalTrustees: []GMSAMembershipTrustee{
			{
				Flags: 0,
				Mask:  adsRightDSReadProperty,
				SID:   computerSID,
				Type:  "ALLOW",
			},
		},
		SAMAccountName:           contract.SAMAccountName,
		ServicePrincipalNames:    []string{},
		SupportedEncryptionTypes: "28",
		UserAccountControl:       "4096",
	}

	err := verifyGMSACreateContract(
		contract,
		observed,
	)
	if err == nil {
		t.Fatal(
			"verify accepted a descriptor that did not match the exact characterized FI ACE mask",
		)
	}
	if !strings.Contains(
		err.Error(),
		"mask=0x000F01FF",
	) {
		t.Fatalf(
			"unexpected verification error: %v",
			err,
		)
	}
}
