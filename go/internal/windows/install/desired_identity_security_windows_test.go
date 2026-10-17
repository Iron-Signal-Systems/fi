// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestDesiredIdentitySecurityInputsRemainIndependentOfServicePresence(
	t *testing.T,
) {
	t.Parallel()

	identities, err :=
		DeriveDesiredFIIdentities(
			"AdminBox",
			"ISS",
		)
	if err != nil {
		t.Fatal(err)
	}

	report := Report{
		Host: HostState{
			Computer: "AdminBox",
		},

		Join: DomainJoinState{
			Name:   "ISS",
			Status: "domain",
		},

		GMSAs: []GMSAState{
			{
				Account:        identities.CollectorSender.Account,
				Role:           identities.CollectorSender.Role,
				SAMAccountName: identities.CollectorSender.SAMAccountName,
				State:          "installed",
			},
			{
				Account:        identities.CRLRefresher.Account,
				Role:           identities.CRLRefresher.Role,
				SAMAccountName: identities.CRLRefresher.SAMAccountName,
				State:          "installed",
			},
			{
				Account:        identities.USNReader.Account,
				Role:           identities.USNReader.Role,
				SAMAccountName: identities.USNReader.SAMAccountName,
				State:          "installed",
			},
			{
				Account:        identities.ObjReader.Account,
				Role:           identities.ObjReader.Role,
				SAMAccountName: identities.ObjReader.SAMAccountName,
				State:          "installed",
			},
		},

		Services: []ServiceState{
			{
				Account:  identities.CollectorSender.Account,
				Name:     "FICollector",
				Presence: presencePresent,
			},
			{
				Account:  identities.USNReader.Account,
				Name:     "FIUSNReader",
				Presence: presencePresent,
			},
			{
				Account:  identities.ObjReader.Account,
				Name:     "FIObjReader",
				Presence: presencePresent,
			},
			{
				Name:     "FICRLRefresher",
				Presence: presenceAbsent,
			},
			{
				Name:     "FISender",
				Presence: presenceAbsent,
			},
		},
	}

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		state, found :=
			findLocalGMSA(
				report.GMSAs,
				identity.SAMAccountName,
			)
		if !found {
			t.Fatalf(
				"missing local gMSA state for %s",
				identity.Account,
			)
		}

		if state.State !=
			"installed" {
			t.Fatalf(
				"%s state=%s want=installed",
				identity.Account,
				state.State,
			)
		}
	}

	sender, found :=
		findService(
			report.Services,
			"FISender",
		)
	if !found {
		t.Fatal(
			"FISender discovery result is missing",
		)
	}

	if sender.Presence !=
		presenceAbsent {
		t.Fatalf(
			"FISender presence=%s want=%s",
			sender.Presence,
			presenceAbsent,
		)
	}

	if identities.CollectorSender.Account == "" ||
		identities.CRLRefresher.Account == "" ||
		identities.USNReader.Account == "" ||
		identities.ObjReader.Account == "" {
		t.Fatal(
			"desired identity derivation unexpectedly depends on SCM presence",
		)
	}
}

func TestDesiredIdentitySecurityDefersUntilLocalGMSAInstallation(
	t *testing.T,
) {
	t.Parallel()

	identities, err :=
		DeriveDesiredFIIdentities(
			"AdminBox",
			"ISS",
		)
	if err != nil {
		t.Fatal(err)
	}

	report := Report{
		GMSAs: []GMSAState{
			{
				Account:        identities.CollectorSender.Account,
				Role:           identities.CollectorSender.Role,
				SAMAccountName: identities.CollectorSender.SAMAccountName,
				State:          "not_installed",
			},
			{
				Account:        identities.CRLRefresher.Account,
				Role:           identities.CRLRefresher.Role,
				SAMAccountName: identities.CRLRefresher.SAMAccountName,
				State:          "not_installed",
			},
			{
				Account:        identities.USNReader.Account,
				Role:           identities.USNReader.Role,
				SAMAccountName: identities.USNReader.SAMAccountName,
				State:          "not_installed",
			},
			{
				Account:        identities.ObjReader.Account,
				Role:           identities.ObjReader.Role,
				SAMAccountName: identities.ObjReader.SAMAccountName,
				State:          "not_installed",
			},
		},
	}

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		state, found :=
			findLocalGMSA(
				report.GMSAs,
				identity.SAMAccountName,
			)
		if !found {
			t.Fatalf(
				"missing local gMSA state for %s",
				identity.Account,
			)
		}

		if state.State !=
			"not_installed" {
			t.Fatalf(
				"%s state=%s want=not_installed",
				identity.Account,
				state.State,
			)
		}
	}
}
