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

type fakeApproval1ControllerBackend struct {
	applyPKIErr     error
	createErr       map[string]error
	created         map[string]bool
	events          []string
	plans           []InstallPlan
	rediscoveries   []Report
	rediscoverIndex int
	rollbackADErr   map[string]error
	rollbackPKIErr  error
}

func (backend *fakeApproval1ControllerBackend) Create(
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

func (backend *fakeApproval1ControllerBackend) RollbackCreated(
	report Report,
	identity DesiredFIIdentity,
) error {
	backend.events = append(
		backend.events,
		"rollback-ad:"+identity.SAMAccountName,
	)
	return backend.rollbackADErr[identity.SAMAccountName]
}

func (backend *fakeApproval1ControllerBackend) ApplyPKI(
	before Report,
	plan InstallPlan,
) (Approval1PKITransactionResult, error) {
	backend.events = append(
		backend.events,
		"apply:pki",
	)
	if backend.applyPKIErr != nil {
		return Approval1PKITransactionResult{}, backend.applyPKIErr
	}
	return Approval1PKITransactionResult{
		Applied: true,
		Detail:  "synthetic PKI transaction",
	}, nil
}

func (backend *fakeApproval1ControllerBackend) RollbackPKI(
	before Report,
	plan InstallPlan,
	result Approval1PKITransactionResult,
) error {
	backend.events = append(
		backend.events,
		"rollback:pki",
	)
	return backend.rollbackPKIErr
}

func (backend *fakeApproval1ControllerBackend) Rediscover() Report {
	backend.events = append(
		backend.events,
		"rediscover",
	)
	if len(backend.rediscoveries) == 0 {
		return Report{}
	}
	index := backend.rediscoverIndex
	if index >= len(backend.rediscoveries) {
		index = len(backend.rediscoveries) - 1
	}
	backend.rediscoverIndex++
	return backend.rediscoveries[index]
}

func (backend *fakeApproval1ControllerBackend) BuildPlan(
	report Report,
	inputs PlanInputs,
) InstallPlan {
	backend.events = append(
		backend.events,
		"build-plan",
	)
	index := backend.rediscoverIndex - 1
	if index < 0 {
		index = 0
	}
	if index >= len(backend.plans) {
		index = len(backend.plans) - 1
	}
	return backend.plans[index]
}

func TestApproval1ControllerInvalidatesOldPlanAndProducesNewApproval2Digest(
	testingT *testing.T,
) {
	testingT.Parallel()

	before, beforePlan := approval1ControllerTestState(testingT)
	post := before
	postPlan := approval1ControllerPostPlan(beforePlan)
	approval := approvalBoundaryTestState(
		testingT,
		before,
		beforePlan,
		approvalBoundaryInfrastructure,
	)
	backend := &fakeApproval1ControllerBackend{
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": true,
		},
		plans: []InstallPlan{
			beforePlan,
			postPlan,
		},
		rediscoveries: []Report{
			before,
			post,
		},
	}

	var output bytes.Buffer
	result, err := executeApproval1ControllerWithBackend(
		&output,
		before,
		beforePlan,
		PlanInputs{},
		approval,
		backend,
	)
	if err != nil {
		testingT.Fatalf("execute controller: %v", err)
	}
	if !result.OldPlanInvalidated {
		testingT.Fatal("pre-Approval-1 plan was not invalidated")
	}
	if !result.Approval2Required {
		testingT.Fatal("Approval 2 was not required")
	}
	if result.Approval2SHA256 == "" {
		testingT.Fatal("new Approval 2 digest is empty")
	}
	if strings.EqualFold(
		result.Approval2SHA256,
		approval.BoundarySHA256,
	) {
		testingT.Fatal("Approval 2 reused the Approval 1 digest")
	}
	wantEvents := []string{
		"rediscover",
		"build-plan",
		"create:gFI-USN-ADMINBOX$",
		"create:gFI-OBJ-ADMINBOX$",
		"apply:pki",
		"rediscover",
		"build-plan",
	}
	if strings.Join(backend.events, "|") != strings.Join(wantEvents, "|") {
		testingT.Fatalf("events=%v want=%v", backend.events, wantEvents)
	}
	if !strings.Contains(
		output.String(),
		"STOP: explicit Approval 2 is required",
	) {
		testingT.Fatalf("missing Approval 2 stop boundary:\n%s", output.String())
	}
}

func TestApproval1ControllerRejectsPreMutationDigestDriftWithoutMutation(
	testingT *testing.T,
) {
	testingT.Parallel()

	before, beforePlan := approval1ControllerTestState(testingT)
	approval := approvalBoundaryTestState(
		testingT,
		before,
		beforePlan,
		approvalBoundaryInfrastructure,
	)
	driftedPlan := beforePlan
	driftedPlan.Actions = append(
		append([]PlanAction(nil), beforePlan.Actions...),
		PlanAction{
			Action:    planActionReconcile,
			Authority: "ACL",
			Target:    `C:\ProgramData\FI\state`,
			Detail:    "synthetic drift",
		},
	)
	backend := &fakeApproval1ControllerBackend{
		plans: []InstallPlan{
			driftedPlan,
		},
		rediscoveries: []Report{
			before,
		},
	}

	var output bytes.Buffer
	_, err := executeApproval1ControllerWithBackend(
		&output,
		before,
		beforePlan,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		testingT.Fatal("digest drift was unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "state changed after Approval 1") {
		testingT.Fatalf("unexpected error: %v", err)
	}
	for _, event := range backend.events {
		if strings.HasPrefix(event, "create:") || event == "apply:pki" {
			testingT.Fatalf("mutation occurred after digest drift: %v", backend.events)
		}
	}
}

func TestApproval1ControllerRollsBackADWhenPKIFails(
	testingT *testing.T,
) {
	testingT.Parallel()

	before, beforePlan := approval1ControllerTestState(testingT)
	approval := approvalBoundaryTestState(
		testingT,
		before,
		beforePlan,
		approvalBoundaryInfrastructure,
	)
	backend := &fakeApproval1ControllerBackend{
		applyPKIErr: errors.New("synthetic PKI failure"),
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": true,
		},
		plans: []InstallPlan{
			beforePlan,
		},
		rediscoveries: []Report{
			before,
		},
	}

	var output bytes.Buffer
	result, err := executeApproval1ControllerWithBackend(
		&output,
		before,
		beforePlan,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		testingT.Fatal("PKI failure unexpectedly succeeded")
	}
	if !result.RollbackAttempted {
		testingT.Fatal("outer rollback was not attempted")
	}
	wantTail := []string{
		"apply:pki",
		"rollback-ad:gFI-OBJ-ADMINBOX$",
		"rollback-ad:gFI-USN-ADMINBOX$",
	}
	joined := strings.Join(backend.events, "|")
	if !strings.Contains(joined, strings.Join(wantTail, "|")) {
		testingT.Fatalf("rollback order incorrect: %v", backend.events)
	}
}

func TestApproval1ControllerRollsBackPKIThenADWhenInfrastructureDoesNotConverge(
	testingT *testing.T,
) {
	testingT.Parallel()

	before, beforePlan := approval1ControllerTestState(testingT)
	approval := approvalBoundaryTestState(
		testingT,
		before,
		beforePlan,
		approvalBoundaryInfrastructure,
	)
	backend := &fakeApproval1ControllerBackend{
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": true,
		},
		plans: []InstallPlan{
			beforePlan,
			beforePlan,
		},
		rediscoveries: []Report{
			before,
			before,
		},
	}

	var output bytes.Buffer
	result, err := executeApproval1ControllerWithBackend(
		&output,
		before,
		beforePlan,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		testingT.Fatal("non-converged infrastructure unexpectedly succeeded")
	}
	if !result.RollbackAttempted {
		testingT.Fatal("outer rollback was not attempted")
	}
	wantTail := []string{
		"rollback:pki",
		"rollback-ad:gFI-OBJ-ADMINBOX$",
		"rollback-ad:gFI-USN-ADMINBOX$",
	}
	joined := strings.Join(backend.events, "|")
	if !strings.Contains(joined, strings.Join(wantTail, "|")) {
		testingT.Fatalf("rollback order incorrect: %v", backend.events)
	}
}

func TestApproval1ControllerSurfacesOuterRollbackErrors(
	testingT *testing.T,
) {
	testingT.Parallel()

	before, beforePlan := approval1ControllerTestState(testingT)
	approval := approvalBoundaryTestState(
		testingT,
		before,
		beforePlan,
		approvalBoundaryInfrastructure,
	)
	backend := &fakeApproval1ControllerBackend{
		applyPKIErr: errors.New("synthetic PKI failure"),
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": true,
		},
		plans: []InstallPlan{
			beforePlan,
		},
		rediscoveries: []Report{
			before,
		},
		rollbackADErr: map[string]error{
			"gFI-USN-ADMINBOX$": errors.New("synthetic AD rollback failure"),
		},
	}

	var output bytes.Buffer
	result, err := executeApproval1ControllerWithBackend(
		&output,
		before,
		beforePlan,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		testingT.Fatal("rollback error was not surfaced")
	}
	if len(result.RollbackErrors) != 1 {
		testingT.Fatalf("rollback errors=%v", result.RollbackErrors)
	}
	if !strings.Contains(err.Error(), "synthetic AD rollback failure") {
		testingT.Fatalf("unexpected error: %v", err)
	}
}

func approval1ControllerTestState(
	testingT *testing.T,
) (Report, InstallPlan) {
	testingT.Helper()

	report, plan := approval1ADTestState(testingT)
	report.Host.Elevated = true
	report.Join = DomainJoinState{
		Name:   "ISS",
		Status: "domain",
	}
	report.Package = PackageState{
		AuthenticodeFilesTrusted:             true,
		AuthenticodeSignerIdentitiesComplete: true,
		AuthenticodeSignersAuthorized:        true,
		ManifestSignature: ManifestSignatureState{
			SignatureValid:     true,
			SignerChainTrusted: true,
			SignerCertSHA256: strings.Repeat(
				"A",
				64,
			),
			SignerSPKISHA256: strings.Repeat(
				"B",
				64,
			),
		},
		ManifestValid:      true,
		PayloadHashesMatch: true,
		ReleaseID:          "test-release",
	}
	report.ReleaseTrust = ReleaseTrustState{
		BootstrapAuthoritySPKISHA256: strings.Repeat(
			"C",
			64,
		),
		ManifestSignerAuthorized: true,
		Package: ReleaseTrustDocumentState{
			PolicySHA256: strings.Repeat(
				"D",
				64,
			),
		},
		TransitionAllowed: true,
	}
	return report, plan
}

func approval1ControllerPostPlan(
	before InstallPlan,
) InstallPlan {
	post := before
	post.Actions = make(
		[]PlanAction,
		0,
		len(before.Actions),
	)
	for _, action := range before.Actions {
		if planActionMutates(action.Action) &&
			(action.Authority == "AD" || action.Authority == "PKI") {
			continue
		}
		post.Actions = append(
			post.Actions,
			action,
		)
	}
	return post
}

func approvalBoundaryTestState(
	testingT *testing.T,
	report Report,
	plan InstallPlan,
	boundary int,
) ApprovalBoundaryState {
	testingT.Helper()

	reviewed, err := PlanDigest(
		report,
		plan,
	)
	if err != nil {
		testingT.Fatalf("plan digest: %v", err)
	}
	boundaryDigest, err := ApprovalBoundaryDigest(
		report,
		plan,
		boundary,
	)
	if err != nil {
		testingT.Fatalf("boundary digest: %v", err)
	}
	return ApprovalBoundaryState{
		Boundary:           boundary,
		BoundarySHA256:     boundaryDigest,
		Given:              true,
		Required:           true,
		ReviewedPlanSHA256: reviewed,
	}
}
