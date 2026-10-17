// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestAliasACLStateForVerificationPreservesTrustConfigSemanticAlias(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		ACLs: []ACLState{
			{
				Label: "FI transport trust config",
				Path:  crlRefresherTrustConfigPath,
			},
		},
	}

	aliasACLStateForVerification(
		&report,
		"FI transport trust config",
		"FI CRL refresher trust config file",
		crlRefresherTrustConfigPath,
	)

	if len(report.ACLs) != 2 {
		t.Fatalf(
			"ACL state count=%d want=2",
			len(report.ACLs),
		)
	}

	state, found :=
		aclByLabel(
			&report,
			"FI CRL refresher trust config file",
		)
	if !found {
		t.Fatal(
			"CRL refresher trust-config ACL alias was not created",
		)
	}

	if state.Path !=
		crlRefresherTrustConfigPath {
		t.Fatalf(
			"alias path=%q want=%q",
			state.Path,
			crlRefresherTrustConfigPath,
		)
	}
}

func TestAliasACLStateForVerificationRejectsPathMismatch(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		ACLs: []ACLState{
			{
				Label: "FI transport trust config",
				Path:  `C:\unexpected\fi-transport-trust.conf`,
			},
		},
	}

	aliasACLStateForVerification(
		&report,
		"FI transport trust config",
		"FI CRL refresher trust config file",
		crlRefresherTrustConfigPath,
	)

	if len(report.ACLs) != 1 {
		t.Fatalf(
			"ACL state count=%d want=1",
			len(report.ACLs),
		)
	}

	if _, found :=
		aclByLabel(
			&report,
			"FI CRL refresher trust config file",
		); found {
		t.Fatal(
			"path mismatch must not create the CRL trust-config alias",
		)
	}
}

func TestAliasACLStateForVerificationDoesNotDuplicateExistingAlias(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		ACLs: []ACLState{
			{
				Label: "FI transport trust config",
				Path:  crlRefresherTrustConfigPath,
			},
			{
				Label: "FI CRL refresher trust config file",
				Path:  crlRefresherTrustConfigPath,
			},
		},
	}

	aliasACLStateForVerification(
		&report,
		"FI transport trust config",
		"FI CRL refresher trust config file",
		crlRefresherTrustConfigPath,
	)

	if len(report.ACLs) != 2 {
		t.Fatalf(
			"ACL state count=%d want=2",
			len(report.ACLs),
		)
	}
}
