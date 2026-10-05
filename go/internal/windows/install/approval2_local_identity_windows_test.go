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

type fakeApproval2LocalIdentityBackend struct {
	events               []string
	installErr           map[string]error
	installErrorPresents map[string]bool
	present              map[string]bool
	presentErr           map[string]error
	removeErr            map[string]error
}

func (backend *fakeApproval2LocalIdentityBackend) Install(
	samAccountName string,
) error {
	backend.events = append(
		backend.events,
		"install:"+samAccountName,
	)

	if err := backend.installErr[samAccountName]; err != nil {
		if backend.installErrorPresents[samAccountName] {
			backend.present[samAccountName] = true
		}
		return err
	}

	backend.present[samAccountName] = true
	return nil
}

func (backend *fakeApproval2LocalIdentityBackend) Present(
	samAccountName string,
) (bool, error) {
	backend.events = append(
		backend.events,
		"present:"+samAccountName,
	)

	if err := backend.presentErr[samAccountName]; err != nil {
		return false, err
	}

	return backend.present[samAccountName], nil
}

func (backend *fakeApproval2LocalIdentityBackend) Remove(
	samAccountName string,
) error {
	backend.events = append(
		backend.events,
		"remove:"+samAccountName,
	)

	if err := backend.removeErr[samAccountName]; err != nil {
		return err
	}

	backend.present[samAccountName] = false
	return nil
}

func TestApproval2LocalIdentityTransactionInstallsAndRollsBackExactTargets(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval2LocalIdentityTestState()
	identities := plan.Identities

	backend := newFakeApproval2LocalIdentityBackend(
		identities,
	)

	rollback, err := reconcileApproval2LocalIdentitiesWithBackend(
		report,
		plan,
		backend,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !backend.present[identities.USNReader.SAMAccountName] {
		t.Fatal(
			"USN-reader gMSA was not installed locally",
		)
	}

	if !backend.present[identities.ObjReader.SAMAccountName] {
		t.Fatal(
			"object-reader gMSA was not installed locally",
		)
	}

	if !backend.present[identities.CollectorSender.SAMAccountName] {
		t.Fatal(
			"preinstalled collector/sender gMSA was changed unexpectedly",
		)
	}

	for _, event := range backend.events {
		if event ==
			"install:"+identities.CollectorSender.SAMAccountName {
			t.Fatal(
				"NO CHANGE collector/sender identity was mutated",
			)
		}
	}

	if err := rollback(); err != nil {
		t.Fatal(err)
	}

	if backend.present[identities.USNReader.SAMAccountName] {
		t.Fatal(
			"USN-reader rollback did not restore local absence",
		)
	}

	if backend.present[identities.ObjReader.SAMAccountName] {
		t.Fatal(
			"object-reader rollback did not restore local absence",
		)
	}

	if !backend.present[identities.CollectorSender.SAMAccountName] {
		t.Fatal(
			"rollback changed preexisting collector/sender state",
		)
	}

	joined := strings.Join(
		backend.events,
		"|",
	)

	expectedRollback :=
		"present:" +
			identities.ObjReader.SAMAccountName +
			"|remove:" +
			identities.ObjReader.SAMAccountName +
			"|present:" +
			identities.ObjReader.SAMAccountName +
			"|present:" +
			identities.USNReader.SAMAccountName +
			"|remove:" +
			identities.USNReader.SAMAccountName +
			"|present:" +
			identities.USNReader.SAMAccountName

	if !strings.Contains(
		joined,
		expectedRollback,
	) {
		t.Fatalf(
			"rollback order is not reverse transaction order: %v",
			backend.events,
		)
	}
}

func TestApproval2LocalIdentityPreflightDriftPerformsNoMutation(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval2LocalIdentityTestState()
	identities := plan.Identities

	backend := newFakeApproval2LocalIdentityBackend(
		identities,
	)

	backend.present[identities.ObjReader.SAMAccountName] = true

	_, err := reconcileApproval2LocalIdentitiesWithBackend(
		report,
		plan,
		backend,
	)
	if err == nil {
		t.Fatal(
			"preflight state drift unexpectedly succeeded",
		)
	}

	for _, event := range backend.events {
		if strings.HasPrefix(
			event,
			"install:",
		) ||
			strings.HasPrefix(
				event,
				"remove:",
			) {
			t.Fatalf(
				"mutation occurred during failed preflight: %v",
				backend.events,
			)
		}
	}
}

func TestApproval2LocalIdentityRejectsWrongPasswordRetrievalTrustee(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval2LocalIdentityTestState()
	identities := plan.Identities

	for index := range report.AD.GMSAs {
		if !strings.EqualFold(
			report.AD.GMSAs[index].SAMAccountName,
			identities.USNReader.SAMAccountName,
		) {
			continue
		}

		report.AD.GMSAs[index].PasswordRetrievalTrustees =
			[]GMSAMembershipTrustee{
				{
					SID: "S-1-5-21-1-2-3-9999",
				},
			}
	}

	backend := newFakeApproval2LocalIdentityBackend(
		identities,
	)

	_, err := reconcileApproval2LocalIdentitiesWithBackend(
		report,
		plan,
		backend,
	)
	if err == nil {
		t.Fatal(
			"incorrect password-retrieval trustee unexpectedly succeeded",
		)
	}

	if len(backend.events) != 0 {
		t.Fatalf(
			"native local backend was touched before AD authorization validation: %v",
			backend.events,
		)
	}
}

func TestApproval2LocalIdentityLaterInstallFailureRollsBackOwnedState(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval2LocalIdentityTestState()
	identities := plan.Identities

	backend := newFakeApproval2LocalIdentityBackend(
		identities,
	)

	backend.installErr[identities.ObjReader.SAMAccountName] =
		errors.New(
			"synthetic install failure",
		)

	_, err := reconcileApproval2LocalIdentitiesWithBackend(
		report,
		plan,
		backend,
	)
	if err == nil {
		t.Fatal(
			"synthetic later install failure unexpectedly succeeded",
		)
	}

	if backend.present[identities.USNReader.SAMAccountName] {
		t.Fatal(
			"earlier transaction-owned USN identity was not rolled back",
		)
	}

	if backend.present[identities.ObjReader.SAMAccountName] {
		t.Fatal(
			"failed object-reader install changed local state unexpectedly",
		)
	}
}

func TestApproval2LocalIdentityAmbiguousFailedInstallIsRetained(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval2LocalIdentityTestState()
	identities := plan.Identities

	plan.Actions = []PlanAction{
		{
			Action:    planActionReconcile,
			Authority: "LOCAL ID",
			Target:    identities.USNReader.Account,
		},
	}

	backend := newFakeApproval2LocalIdentityBackend(
		identities,
	)

	backend.installErr[identities.USNReader.SAMAccountName] =
		errors.New(
			"synthetic native failure",
		)

	backend.installErrorPresents[identities.USNReader.SAMAccountName] = true

	_, err := reconcileApproval2LocalIdentitiesWithBackend(
		report,
		plan,
		backend,
	)
	if err == nil {
		t.Fatal(
			"ambiguous failed install unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"ownership is ambiguous",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if !backend.present[identities.USNReader.SAMAccountName] {
		t.Fatal(
			"ambiguous installed state was destructively removed",
		)
	}

	for _, event := range backend.events {
		if event ==
			"remove:"+identities.USNReader.SAMAccountName {
			t.Fatal(
				"FI removed local identity whose ownership was ambiguous",
			)
		}
	}
}

func TestApproval2LocalIdentityRejectsUnexpectedMutationTarget(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval2LocalIdentityTestState()
	identities := plan.Identities

	plan.Actions = []PlanAction{
		{
			Action:    planActionReconcile,
			Authority: "LOCAL ID",
			Target:    `ISS\gFI-NOT-OURS$`,
		},
	}

	backend := newFakeApproval2LocalIdentityBackend(
		identities,
	)

	_, err := reconcileApproval2LocalIdentitiesWithBackend(
		report,
		plan,
		backend,
	)
	if err == nil {
		t.Fatal(
			"unexpected LOCAL ID target was accepted",
		)
	}

	if len(backend.events) != 0 {
		t.Fatalf(
			"backend was touched for unexpected target: %v",
			backend.events,
		)
	}
}

func approval2LocalIdentityTestState() (
	Report,
	InstallPlan,
) {
	identities := approval2LocalIdentityTestIdentities()

	const computerSID = "S-1-5-21-2096275705-3984399647-1579629934-1104"

	report := Report{
		AD: ActiveDirectoryState{
			ComputerObjectKnown: true,
			ComputerSID:         computerSID,
			GMSADiscoveryKnown:  true,
		},

		Host: HostState{
			BuildNumber: 14393,
			Computer:    "AdminBox",
			DomainDNS:   "iss.local",
			Elevated:    true,
		},

		Join: DomainJoinState{
			Name:   "ISS",
			Status: "domain",
		},
	}

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		report.AD.GMSAs = append(
			report.AD.GMSAs,
			ActiveDirectoryGMSAState{
				DNSHostName: strings.TrimSuffix(
					identity.SAMAccountName,
					"$",
				) + ".iss.local",

				DistinguishedName: "CN=" +
					strings.TrimSuffix(
						identity.SAMAccountName,
						"$",
					) +
					",CN=Managed Service Accounts,DC=iss,DC=local",

				PasswordRetrievalTrustees: []GMSAMembershipTrustee{
					{
						SID: computerSID,
					},
				},

				Role:           identity.Role,
				SAMAccountName: identity.SAMAccountName,
			},
		)
	}

	report.GMSAs = []GMSAState{
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
	}

	plan := InstallPlan{
		Identities: identities,

		Actions: []PlanAction{
			{
				Action:    planActionNoChange,
				Authority: "LOCAL ID",
				Target:    identities.CollectorSender.Account,
			},
			{
				Action:    planActionReconcile,
				Authority: "LOCAL ID",
				Target:    identities.CRLRefresher.Account,
			},
			{
				Action:    planActionReconcile,
				Authority: "LOCAL ID",
				Target:    identities.USNReader.Account,
			},
			{
				Action:    planActionReconcile,
				Authority: "LOCAL ID",
				Target:    identities.ObjReader.Account,
			},
		},
	}

	return report, plan
}

func approval2LocalIdentityTestIdentities() DesiredFIIdentities {
	return DesiredFIIdentities{
		CRLRefresher: DesiredFIIdentity{
			Account:        `ISS\gFI-CRL-ADMINBOX$`,
			Role:           "FICRLRefresher",
			SAMAccountName: "gFI-CRL-ADMINBOX$",
		},

		CollectorSender: DesiredFIIdentity{
			Account:        `ISS\gFI-ADMINBOX$`,
			Role:           "FICollector/FISender",
			SAMAccountName: "gFI-ADMINBOX$",
		},

		ObjReader: DesiredFIIdentity{
			Account:        `ISS\gFI-OBJ-ADMINBOX$`,
			Role:           "FIObjReader",
			SAMAccountName: "gFI-OBJ-ADMINBOX$",
		},

		USNReader: DesiredFIIdentity{
			Account:        `ISS\gFI-USN-ADMINBOX$`,
			Role:           "FIUSNReader",
			SAMAccountName: "gFI-USN-ADMINBOX$",
		},
	}
}

func newFakeApproval2LocalIdentityBackend(
	identities DesiredFIIdentities,
) *fakeApproval2LocalIdentityBackend {
	return &fakeApproval2LocalIdentityBackend{
		installErr: make(map[string]error),

		installErrorPresents: make(map[string]bool),

		present: map[string]bool{
			identities.CollectorSender.SAMAccountName: true,
			identities.CRLRefresher.SAMAccountName:    false,
			identities.USNReader.SAMAccountName:       false,
			identities.ObjReader.SAMAccountName:       false,
		},

		presentErr: make(map[string]error),

		removeErr: make(map[string]error),
	}
}
