// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCRLRefresherFiveRuntimeSecurityContract(
	t *testing.T,
) {
	identities, err :=
		DeriveDesiredFIIdentities(
			"AdminBox",
			"ISS",
		)
	if err != nil {
		t.Fatal(err)
	}

	if identities.CRLRefresher.Account !=
		`ISS\gFI-CRL-ADMINBOX$` {
		t.Fatalf(
			"CRL refresher account=%q",
			identities.CRLRefresher.Account,
		)
	}

	if identities.CRLRefresher.Role !=
		"FICRLRefresher" {
		t.Fatalf(
			"CRL refresher role=%q",
			identities.CRLRefresher.Role,
		)
	}

	foundIdentity := false

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		if identity.Role ==
			"FICRLRefresher" {
			foundIdentity = true
		}
	}

	if !foundIdentity {
		t.Fatal(
			"FICRLRefresher is missing from desired FI identity list",
		)
	}

	contracts :=
		approval2Server2016ServiceContracts(
			identities,
		)

	if len(contracts) != 5 {
		t.Fatalf(
			"service contracts=%d want=5",
			len(contracts),
		)
	}

	foundService := false

	for _, contract := range contracts {
		if contract.Name !=
			"FICRLRefresher" {
			continue
		}

		foundService = true

		if contract.Account !=
			identities.CRLRefresher.Account {
			t.Fatalf(
				"service account=%q want=%q",
				contract.Account,
				identities.CRLRefresher.Account,
			)
		}

		if contract.Executable !=
			crlRefresherExecutablePath {
			t.Fatalf(
				"service executable=%q want=%q",
				contract.Executable,
				crlRefresherExecutablePath,
			)
		}

		if contract.SIDType !=
			windows.SERVICE_SID_TYPE_NONE {
			t.Fatalf(
				"service SID type=%d want=%d",
				contract.SIDType,
				windows.SERVICE_SID_TYPE_NONE,
			)
		}
	}

	if !foundService {
		t.Fatal(
			"FICRLRefresher SCM contract is missing",
		)
	}

	if approval1TransportCRLDestination !=
		`C:\ProgramData\FI\pki\crl\fi-transport-ca.crl.pem` {
		t.Fatalf(
			"CRL destination=%q",
			approval1TransportCRLDestination,
		)
	}

	if crlRefresherJournalPath !=
		`C:\ProgramData\FI\crl-refresh\crl-refresh.jsonl` {
		t.Fatalf(
			"journal=%q",
			crlRefresherJournalPath,
		)
	}

	wantAppend :=
		uint32(
			windows.FILE_APPEND_DATA |
				windows.FILE_READ_ATTRIBUTES |
				windows.SYNCHRONIZE,
		)

	if crlRefresherJournalMask !=
		wantAppend {
		t.Fatalf(
			"journal mask=0x%08X want=0x%08X",
			crlRefresherJournalMask,
			wantAppend,
		)
	}

	report :=
		Report{
			Host: HostState{
				Computer: "AdminBox",
			},
			Join: DomainJoinState{
				Name: "ISS",
			},
		}

	plan :=
		BuildPlan(
			report,
		)

	for _, action := range plan.Actions {
		if strings.EqualFold(
			action.Authority,
			"CRL REFRESHER",
		) {
			t.Fatalf(
				"temporary CRL REFRESHER blocker still exists: %+v",
				action,
			)
		}
	}
}

func TestCRLRefresherJournalMaskExcludesBroadWriteAuthority(
	t *testing.T,
) {
	forbidden :=
		uint32(
			windows.FILE_WRITE_DATA |
				windows.DELETE |
				windows.WRITE_DAC |
				windows.WRITE_OWNER,
		)

	if crlRefresherJournalMask&
		forbidden != 0 {
		t.Fatalf(
			"journal mask contains forbidden authority mask=0x%08X forbidden=0x%08X",
			crlRefresherJournalMask,
			forbidden,
		)
	}
}
