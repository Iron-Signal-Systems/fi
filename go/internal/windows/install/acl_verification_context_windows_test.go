// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestACLVerificationReportPreservesDesiredIdentityInputs(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Config: ConfigState{
			Path: `C:\ProgramData\FI\config\fi.conf`,
		},
		Host: HostState{
			Computer: "AdminBox",
		},
		Join: DomainJoinState{
			Name: "ISS",
		},
		Services: []ServiceState{
			{
				Account:  `ISS\gFI-ADMINBOX$`,
				Name:     "FICollector",
				Presence: presencePresent,
			},
			{
				Account:  `ISS\gFI-USN-ADMINBOX$`,
				Name:     "FIUSNReader",
				Presence: presencePresent,
			},
			{
				Account:  `ISS\gFI-OBJ-ADMINBOX$`,
				Name:     "FIObjReader",
				Presence: presencePresent,
			},
			{
				Name:     "FICRLRefresher",
				Presence: presenceAbsent,
			},
			{
				Account:  `ISS\gFI-ADMINBOX$`,
				Name:     "FISender",
				Presence: presencePresent,
			},
		},
		Trust: TransportTrustState{
			TransportCRLPath: `C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem`,
		},
	}

	verification :=
		aclVerificationReport(
			report,
		)

	if verification.Host.Computer !=
		report.Host.Computer {
		t.Fatalf(
			"verification computer=%q want=%q",
			verification.Host.Computer,
			report.Host.Computer,
		)
	}

	if verification.Join.Name !=
		report.Join.Name {
		t.Fatalf(
			"verification domain=%q want=%q",
			verification.Join.Name,
			report.Join.Name,
		)
	}

	if verification.Config.Path !=
		report.Config.Path {
		t.Fatalf(
			"verification config=%q want=%q",
			verification.Config.Path,
			report.Config.Path,
		)
	}

	if verification.Trust.TransportCRLPath !=
		report.Trust.TransportCRLPath {
		t.Fatalf(
			"verification CRL=%q want=%q",
			verification.Trust.TransportCRLPath,
			report.Trust.TransportCRLPath,
		)
	}

	if len(verification.Services) !=
		len(report.Services) {
		t.Fatalf(
			"verification services=%d want=%d",
			len(verification.Services),
			len(report.Services),
		)
	}

	_, crlRefresher, _, _, err :=
		desiredACLAccounts(
			verification,
		)
	if err != nil {
		t.Fatalf(
			"derive desired ACL accounts from verification report: %v",
			err,
		)
	}

	if crlRefresher !=
		`ISS\gFI-CRL-ADMINBOX$` {
		t.Fatalf(
			"CRL refresher=%q want=%q",
			crlRefresher,
			`ISS\gFI-CRL-ADMINBOX$`,
		)
	}
}
