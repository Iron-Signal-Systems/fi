// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestSelectApproval1TransportCRLDistributionPointAcceptsADLDAP(
	t *testing.T,
) {
	t.Parallel()

	const want = "ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint"

	got, err := selectApproval1TransportCRLDistributionPoint(
		[]string{want},
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Fatalf(
			"CRL distribution point=%q want=%q",
			got,
			want,
		)
	}
}

func TestApproval1SupportedCRLDistributionPointRejectsLDAPWithoutCRLAttribute(
	t *testing.T,
) {
	t.Parallel()

	if approval1SupportedCRLDistributionPoint(
		"ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?cACertificate?base?objectClass=certificationAuthority",
	) {
		t.Fatal(
			"LDAP AIA URL was incorrectly accepted as a CRL distribution point",
		)
	}
}

func TestApproval1SupportedCRLDistributionPointRejectsLDAPWithoutBaseScope(
	t *testing.T,
) {
	t.Parallel()

	if approval1SupportedCRLDistributionPoint(
		"ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?certificateRevocationList?sub?objectClass=cRLDistributionPoint",
	) {
		t.Fatal(
			"non-base LDAP CRL distribution point was unexpectedly accepted",
		)
	}
}
