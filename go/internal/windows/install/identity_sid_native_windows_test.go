// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestBindDesiredFIIdentitySIDsRejectsMissingAuthoritativeSID(
	t *testing.T,
) {
	t.Parallel()

	identities := DesiredFIIdentities{
		USNReader: DesiredFIIdentity{
			Account:        `ISS\gFI-USN-ADMINBOX$`,
			Role:           "FIUSNReader",
			SAMAccountName: `gFI-USN-ADMINBOX$`,
		},
	}

	report := Report{
		AD: ActiveDirectoryState{
			GMSADiscoveryKnown: true,
			GMSAs: []ActiveDirectoryGMSAState{
				{
					Role:           "FIUSNReader",
					SAMAccountName: `gFI-USN-ADMINBOX$`,
				},
			},
		},
	}

	_, err :=
		bindDesiredFIIdentitySIDs(
			report,
			identities,
		)
	if err == nil {
		t.Fatal(
			"missing authoritative gMSA objectSid unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"objectSid is unavailable",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestBindDesiredFIIdentitySIDsUsesAuthoritativeADObjectSID(
	t *testing.T,
) {
	t.Parallel()

	identities := DesiredFIIdentities{
		CRLRefresher: DesiredFIIdentity{
			Account:        `ISS\gFI-CRL-ADMINBOX$`,
			Role:           "FICRLRefresher",
			SAMAccountName: `gFI-CRL-ADMINBOX$`,
		},
		CollectorSender: DesiredFIIdentity{
			Account:        `ISS\gFI-ADMINBOX$`,
			Role:           "FICollector/FISender",
			SAMAccountName: `gFI-ADMINBOX$`,
		},
		ObjReader: DesiredFIIdentity{
			Account:        `ISS\gFI-OBJ-ADMINBOX$`,
			Role:           "FIObjReader",
			SAMAccountName: `gFI-OBJ-ADMINBOX$`,
		},
		USNReader: DesiredFIIdentity{
			Account:        `ISS\gFI-USN-ADMINBOX$`,
			Role:           "FIUSNReader",
			SAMAccountName: `gFI-USN-ADMINBOX$`,
		},
	}

	expected := map[string]string{
		`gFI-ADMINBOX$`:     "S-1-5-21-1-2-3-1101",
		`gFI-CRL-ADMINBOX$`: "S-1-5-21-1-2-3-1102",
		`gFI-USN-ADMINBOX$`: "S-1-5-21-1-2-3-1103",
		`gFI-OBJ-ADMINBOX$`: "S-1-5-21-1-2-3-1104",
	}

	report := Report{
		AD: ActiveDirectoryState{
			GMSADiscoveryKnown: true,
		},
	}

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		report.AD.GMSAs = append(
			report.AD.GMSAs,
			ActiveDirectoryGMSAState{
				Role:           identity.Role,
				SAMAccountName: identity.SAMAccountName,
				SID:            expected[identity.SAMAccountName],
			},
		)
	}

	bound, err :=
		bindDesiredFIIdentitySIDs(
			report,
			identities,
		)
	if err != nil {
		t.Fatalf(
			"bind identities: %v",
			err,
		)
	}

	for _, identity := range desiredFIIdentityList(
		bound,
	) {
		if identity.SID !=
			expected[identity.SAMAccountName] {
			t.Fatalf(
				"%s SID=%q want=%q",
				identity.SAMAccountName,
				identity.SID,
				expected[identity.SAMAccountName],
			)
		}
	}
}

func TestSealedDesiredFIIdentitySIDRequiresSID(
	t *testing.T,
) {
	t.Parallel()

	_, err :=
		sealedDesiredFIIdentitySID(
			DesiredFIIdentity{
				Account: `ISS\gFI-USN-ADMINBOX$`,
			},
		)

	if err == nil {
		t.Fatal(
			"missing sealed SID unexpectedly accepted",
		)
	}
}
