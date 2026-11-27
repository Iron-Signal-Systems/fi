// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestACLVerificationAliasesBeforeContractEvaluation(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
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
		},
		ACLs: []ACLState{
			{
				Label:     "FI transport trust config",
				Owner:     `BUILTIN\Administrators`,
				Path:      crlRefresherTrustConfigPath,
				Protected: true,
				Entries: []ACLEntry{
					{
						Account: `BUILTIN\Administrators`,
						Mask:    fileFullControlMask,
						Type:    "ALLOW",
					},
					{
						Account: `NT AUTHORITY\SYSTEM`,
						Mask:    fileFullControlMask,
						Type:    "ALLOW",
					},
					{
						Account: `ISS\gFI-ADMINBOX$`,
						Mask:    fileReadExecuteMask,
						Type:    "ALLOW",
					},
					{
						Account: `ISS\gFI-USN-ADMINBOX$`,
						Mask:    fileReadExecuteMask,
						Type:    "ALLOW",
					},
					{
						Account: `ISS\gFI-OBJ-ADMINBOX$`,
						Mask:    fileReadExecuteMask,
						Type:    "ALLOW",
					},
					{
						Account: `ISS\gFI-CRL-ADMINBOX$`,
						Mask:    fileReadExecuteMask,
						Type:    "ALLOW",
					},
				},
			},
		},
	}

	evaluateServer2016ACLVerificationContracts(
		&report,
	)

	alias, found :=
		aclByLabel(
			&report,
			"FI CRL refresher trust config file",
		)
	if !found {
		t.Fatal(
			"CRL refresher trust-config semantic alias was not created before evaluation",
		)
	}

	if alias.Path !=
		crlRefresherTrustConfigPath {
		t.Fatalf(
			"alias path=%q want=%q",
			alias.Path,
			crlRefresherTrustConfigPath,
		)
	}

	check, found :=
		findCheck(
			report,
			"FI CRL refresher trust config file desired ACL contract",
		)
	if !found {
		t.Fatal(
			"CRL refresher trust-config ACL contract was not evaluated",
		)
	}

	if check.Status !=
		checkPass {
		t.Fatalf(
			"CRL trust-config contract status=%q detail=%q want=%q",
			check.Status,
			check.Detail,
			checkPass,
		)
	}
}
