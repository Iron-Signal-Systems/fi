// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"strings"
	"testing"
)

func TestPlanActiveDirectoryBlocksUnknownGMSADiscovery(t *testing.T) {
	t.Parallel()

	report := Report{
		AD: ActiveDirectoryState{
			DefaultNamingContext: "DC=iss,DC=local",
			DomainController:     "DC16.iss.local",
			KDSRootKeyCount:      1,
			KDSRootKeyKnown:      true,
		},
		Host: HostState{
			Computer: "ISS-FS-01",
		},
		Join: DomainJoinState{
			Name:   "ISS",
			Status: "domain",
		},
	}

	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		t.Fatal(err)
	}

	var plan InstallPlan
	planActiveDirectory(
		&plan,
		report,
		identities,
		nil,
	)

	createCount := 0
	blockedCount := 0
	for _, action := range plan.Actions {
		if action.Authority != "AD" {
			continue
		}
		if action.Action == planActionCreate &&
			action.Target != "KDS root key" {
			createCount++
		}
		if action.Action == planActionBlocked &&
			strings.Contains(
				action.Detail,
				"will not infer absence",
			) {
			blockedCount++
		}
	}

	if createCount != 0 {
		t.Fatalf(
			"unknown AD state produced %d CREATE actions: %+v",
			createCount,
			plan.Actions,
		)
	}
	if blockedCount != 4 {
		t.Fatalf(
			"blocked_gmsa_actions=%d want=4 actions=%+v",
			blockedCount,
			plan.Actions,
		)
	}
}

func TestPlanActiveDirectoryCreatesAuthoritativelyAbsentGMSAs(t *testing.T) {
	t.Parallel()

	report := Report{
		AD: ActiveDirectoryState{
			ComputerDN:           "CN=ISS-FS-01,CN=Computers,DC=iss,DC=local",
			ComputerObjectKnown:  true,
			ComputerSID:          "S-1-5-21-1-2-3-1107",
			DefaultNamingContext: "DC=iss,DC=local",
			DomainController:     "DC16.iss.local",
			GMSADiscoveryKnown:   true,
			KDSRootKeyCount:      1,
			KDSRootKeyKnown:      true,
		},
		Host: HostState{
			Computer: "ISS-FS-01",
		},
		Join: DomainJoinState{
			Name:   "ISS",
			Status: "domain",
		},
	}

	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		t.Fatal(err)
	}

	var plan InstallPlan
	planActiveDirectory(
		&plan,
		report,
		identities,
		nil,
	)

	created := 0
	for _, action := range plan.Actions {
		if action.Authority == "AD" &&
			action.Action == planActionCreate &&
			strings.Contains(
				action.Detail,
				"authoritative AD discovery confirmed",
			) {
			created++
		}
	}
	if created != 4 {
		t.Fatalf(
			"created_gmsa_actions=%d want=4 actions=%+v",
			created,
			plan.Actions,
		)
	}
}

func TestPlanActiveDirectoryDoesNotCreateGMSAWithUnknownKDSState(t *testing.T) {
	t.Parallel()

	report := Report{
		AD: ActiveDirectoryState{
			ComputerDN:           "CN=ISS-FS-01,CN=Computers,DC=iss,DC=local",
			ComputerObjectKnown:  true,
			ComputerSID:          "S-1-5-21-1-2-3-1107",
			DefaultNamingContext: "DC=iss,DC=local",
			DomainController:     "DC16.iss.local",
			GMSADiscoveryKnown:   true,
			KDSRootKeyKnown:      false,
		},
		Host: HostState{
			Computer: "ISS-FS-01",
		},
		Join: DomainJoinState{
			Name:   "ISS",
			Status: "domain",
		},
	}

	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		t.Fatal(err)
	}

	var plan InstallPlan
	planActiveDirectory(
		&plan,
		report,
		identities,
		nil,
	)

	gmsaCreates := 0
	gmsaBlocks := 0
	for _, action := range plan.Actions {
		if action.Authority != "AD" ||
			action.Target == "KDS root key" {
			continue
		}
		if action.Action == planActionCreate {
			gmsaCreates++
		}
		if action.Action == planActionBlocked &&
			strings.Contains(
				action.Detail,
				"KDS root-key state is unknown",
			) {
			gmsaBlocks++
		}
	}
	if gmsaCreates != 0 {
		t.Fatalf(
			"unknown KDS state produced %d gMSA CREATE actions: %+v",
			gmsaCreates,
			plan.Actions,
		)
	}
	if gmsaBlocks != 4 {
		t.Fatalf(
			"blocked_gmsa_actions=%d want=4 actions=%+v",
			gmsaBlocks,
			plan.Actions,
		)
	}
}

func TestLDAPNoEntriesIsDistinctFromLDAPFailure(t *testing.T) {
	t.Parallel()

	noEntries := &ldapSearchCardinalityError{
		Base:   "DC=iss,DC=local",
		Count:  0,
		Filter: "(objectClass=test)",
	}
	if !ldapSearchReturnedNoEntries(noEntries) {
		t.Fatal("zero-entry LDAP result was not recognized as authoritative absence")
	}

	multiple := &ldapSearchCardinalityError{
		Base:   "DC=iss,DC=local",
		Count:  2,
		Filter: "(objectClass=test)",
	}
	if ldapSearchReturnedNoEntries(multiple) {
		t.Fatal("multiple-entry LDAP result was incorrectly treated as absence")
	}

	if ldapSearchReturnedNoEntries(
		errors.New("LDAP operations error"),
	) {
		t.Fatal("unrelated LDAP/runtime error was incorrectly treated as absence")
	}
}
