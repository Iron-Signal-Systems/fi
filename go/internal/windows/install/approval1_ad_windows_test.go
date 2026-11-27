// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type fakeApproval1ADBackend struct {
	createErr   map[string]error
	created     map[string]bool
	events      []string
	rollbackErr map[string]error
}

func (backend *fakeApproval1ADBackend) Create(
	report Report,
	identity DesiredFIIdentity,
) (ActiveDirectoryGMSAState, bool, error) {
	backend.events = append(
		backend.events,
		"create:"+identity.SAMAccountName,
	)
	created := backend.created[identity.SAMAccountName]
	return ActiveDirectoryGMSAState{
		DistinguishedName: "CN=" + strings.TrimSuffix(
			identity.SAMAccountName,
			"$",
		) + ",CN=Managed Service Accounts,DC=iss,DC=local",
		Role:           identity.Role,
		SAMAccountName: identity.SAMAccountName,
	}, created, backend.createErr[identity.SAMAccountName]
}

func (backend *fakeApproval1ADBackend) RollbackCreated(
	report Report,
	identity DesiredFIIdentity,
) error {
	backend.events = append(
		backend.events,
		"rollback:"+identity.SAMAccountName,
	)
	return backend.rollbackErr[identity.SAMAccountName]
}

func TestApproval1ADCreateIdentitiesSelectsOnlyPlannedAbsentFIGMSAs(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval1ADTestState(t)
	identities, err := approval1ADCreateIdentities(
		report,
		plan,
	)
	if err != nil {
		t.Fatalf("select identities: %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("identity count=%d, want 2", len(identities))
	}
	if identities[0].SAMAccountName != "gFI-USN-ADMINBOX$" {
		t.Fatalf("first identity=%s", identities[0].SAMAccountName)
	}
	if identities[1].SAMAccountName != "gFI-OBJ-ADMINBOX$" {
		t.Fatalf("second identity=%s", identities[1].SAMAccountName)
	}
}

func TestApproval1ADTransactionCreatesUSNThenObjWithoutTouchingExistingCollector(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval1ADTestState(t)
	identities, err := approval1ADCreateIdentities(report, plan)
	if err != nil {
		t.Fatalf("select identities: %v", err)
	}
	backend := &fakeApproval1ADBackend{
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": true,
		},
	}
	var output bytes.Buffer
	result, err := executeApproval1ADGMSATransactionWithBackend(
		&output,
		report,
		identities,
		backend,
	)
	if err != nil {
		t.Fatalf("execute transaction: %v", err)
	}
	wantEvents := []string{
		"create:gFI-USN-ADMINBOX$",
		"create:gFI-OBJ-ADMINBOX$",
	}
	if strings.Join(backend.events, "|") != strings.Join(wantEvents, "|") {
		t.Fatalf("events=%v want=%v", backend.events, wantEvents)
	}
	if len(result.Created) != 2 {
		t.Fatalf("created count=%d, want 2", len(result.Created))
	}
	if result.RollbackAttempted {
		t.Fatal("rollback attempted on successful transaction")
	}
}

func TestApproval1ADTransactionRollsBackOnlyPreviouslyCreatedObjectOnSecondFailure(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval1ADTestState(t)
	identities, err := approval1ADCreateIdentities(report, plan)
	if err != nil {
		t.Fatalf("select identities: %v", err)
	}
	backend := &fakeApproval1ADBackend{
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": false,
		},
		createErr: map[string]error{
			"gFI-OBJ-ADMINBOX$": errors.New("synthetic create failure"),
		},
	}
	var output bytes.Buffer
	result, err := executeApproval1ADGMSATransactionWithBackend(
		&output,
		report,
		identities,
		backend,
	)
	if err == nil {
		t.Fatal("transaction unexpectedly succeeded")
	}
	wantEvents := []string{
		"create:gFI-USN-ADMINBOX$",
		"create:gFI-OBJ-ADMINBOX$",
		"rollback:gFI-USN-ADMINBOX$",
	}
	if strings.Join(backend.events, "|") != strings.Join(wantEvents, "|") {
		t.Fatalf("events=%v want=%v", backend.events, wantEvents)
	}
	if !result.RollbackAttempted {
		t.Fatal("rollback was not attempted")
	}
}

func TestApproval1ADTransactionRollsBackCurrentAmbiguousCreateBeforeEarlierCreate(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval1ADTestState(t)
	identities, err := approval1ADCreateIdentities(report, plan)
	if err != nil {
		t.Fatalf("select identities: %v", err)
	}
	backend := &fakeApproval1ADBackend{
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": true,
		},
		createErr: map[string]error{
			"gFI-OBJ-ADMINBOX$": errors.New("synthetic post-create verification failure"),
		},
	}
	var output bytes.Buffer
	result, err := executeApproval1ADGMSATransactionWithBackend(
		&output,
		report,
		identities,
		backend,
	)
	if err == nil {
		t.Fatal("transaction unexpectedly succeeded")
	}
	wantEvents := []string{
		"create:gFI-USN-ADMINBOX$",
		"create:gFI-OBJ-ADMINBOX$",
		"rollback:gFI-OBJ-ADMINBOX$",
		"rollback:gFI-USN-ADMINBOX$",
	}
	if strings.Join(backend.events, "|") != strings.Join(wantEvents, "|") {
		t.Fatalf("events=%v want=%v", backend.events, wantEvents)
	}
	if !result.RollbackAttempted {
		t.Fatal("rollback was not attempted")
	}
}

func TestApproval1ADTransactionSurfacesRollbackFailure(t *testing.T) {
	t.Parallel()

	report, plan := approval1ADTestState(t)
	identities, err := approval1ADCreateIdentities(report, plan)
	if err != nil {
		t.Fatalf("select identities: %v", err)
	}
	backend := &fakeApproval1ADBackend{
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": false,
		},
		createErr: map[string]error{
			"gFI-OBJ-ADMINBOX$": errors.New("synthetic create failure"),
		},
		rollbackErr: map[string]error{
			"gFI-USN-ADMINBOX$": errors.New("synthetic rollback failure"),
		},
	}
	var output bytes.Buffer
	result, err := executeApproval1ADGMSATransactionWithBackend(
		&output,
		report,
		identities,
		backend,
	)
	if err == nil {
		t.Fatal("transaction unexpectedly succeeded")
	}
	if len(result.RollbackErrors) != 1 {
		t.Fatalf("rollback error count=%d, want 1", len(result.RollbackErrors))
	}
	if !strings.Contains(err.Error(), "synthetic rollback failure") {
		t.Fatalf("rollback failure not surfaced: %v", err)
	}
}

func TestApproval1ADCreateIdentitiesRejectsKDSCreation(t *testing.T) {
	t.Parallel()

	report, plan := approval1ADTestState(t)
	report.AD.KDSRootKeyCount = 0
	plan.Actions = append(
		plan.Actions,
		PlanAction{
			Action:    planActionCreate,
			Authority: "AD",
			Target:    "KDS root key",
		},
	)
	_, err := approval1ADCreateIdentities(report, plan)
	if err == nil {
		t.Fatal("KDS creation was unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "KDS root-key creation is not enabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApproval1ADCreateIdentitiesRejectsADReconcile(t *testing.T) {
	t.Parallel()

	report, plan := approval1ADTestState(t)
	plan.Actions = append(
		plan.Actions,
		PlanAction{
			Action:    planActionReconcile,
			Authority: "AD",
			Target:    plan.Identities.USNReader.Account,
		},
	)
	_, err := approval1ADCreateIdentities(report, plan)
	if err == nil {
		t.Fatal("AD reconcile was unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "not a characterized gMSA CREATE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func approval1ADTestState(t *testing.T) (Report, InstallPlan) {
	t.Helper()

	identities, err := DeriveDesiredFIIdentities(
		"AdminBox",
		"ISS",
	)
	if err != nil {
		t.Fatalf("derive identities: %v", err)
	}

	report := Report{
		AD: ActiveDirectoryState{
			ComputerDN:           "CN=ADMINBOX,CN=Computers,DC=iss,DC=local",
			ComputerObjectKnown:  true,
			ComputerSID:          "S-1-5-21-2096275705-3984399647-1579629934-1104",
			DefaultNamingContext: "DC=iss,DC=local",
			GMSADiscoveryKnown:   true,
			GMSAs: []ActiveDirectoryGMSAState{
				{
					Role:           "FICollector/FISender",
					SAMAccountName: "gFI-ADMINBOX$",
				},
			},
			KDSRootKeyCount: 1,
			KDSRootKeyKnown: true,
		},
		Host: HostState{
			BuildNumber: 14393,
			Computer:    "AdminBox",
			DomainDNS:   "iss.local",
		},
	}
	plan := InstallPlan{
		Identities: identities,
		Mode:       "UPDATE / RECONCILE",
		Actions: []PlanAction{
			{
				Action:    planActionNoChange,
				Authority: "AD",
				Target:    identities.CollectorSender.Account,
			},
			{
				Action:    planActionCreate,
				Authority: "AD",
				Target:    identities.USNReader.Account,
			},
			{
				Action:    planActionCreate,
				Authority: "AD",
				Target:    identities.ObjReader.Account,
			},
			{
				Action:    planActionReconcile,
				Authority: "PKI",
				Target:    "FI transport PKI",
			},
			{
				Action:    planActionReconcile,
				Authority: "LOCAL ID",
				Target:    identities.USNReader.Account,
			},
		},
	}
	return report, plan
}
