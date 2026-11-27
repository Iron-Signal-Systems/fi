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

type fakeApproval2ControllerBackend struct {
	configErr       error
	configRollback  error
	events          []string
	localErr        error
	localRollback   error
	plans           []InstallPlan
	rediscoveries   []Report
	rediscoverIndex int
}

func (backend *fakeApproval2ControllerBackend) ApplyLocalIdentities(
	report Report,
	plan InstallPlan,
) (func() error, error) {
	backend.events = append(
		backend.events,
		"apply:local-id",
	)

	if backend.localErr != nil {
		return nil, backend.localErr
	}

	return func() error {
		backend.events = append(
			backend.events,
			"rollback:local-id",
		)
		return backend.localRollback
	}, nil
}

func (backend *fakeApproval2ControllerBackend) ApplyTransportTrust(
	report Report,
	plan InstallPlan,
	handoff approval1PKIHandoff,
	transactionID string,
) (func() error, error) {
	backend.events = append(
		backend.events,
		"apply:config",
	)

	if strings.TrimSpace(
		transactionID,
	) == "" {
		return nil, errors.New(
			"synthetic backend received empty transaction ID",
		)
	}

	if err := handoff.validate(); err != nil {
		return nil, err
	}

	if backend.configErr != nil {
		return nil, backend.configErr
	}

	return func() error {
		backend.events = append(
			backend.events,
			"rollback:config",
		)
		return backend.configRollback
	}, nil
}

func (backend *fakeApproval2ControllerBackend) BuildPlan(
	report Report,
	inputs PlanInputs,
	handoff approval1PKIHandoff,
) InstallPlan {
	backend.events = append(
		backend.events,
		"build-plan",
	)

	index := backend.rediscoverIndex - 1

	if index < 0 {
		index = 0
	}

	if index >= len(
		backend.plans,
	) {
		index = len(backend.plans) - 1
	}

	return backend.plans[index]
}

func (backend *fakeApproval2ControllerBackend) Rediscover() Report {
	backend.events = append(
		backend.events,
		"rediscover",
	)

	if len(
		backend.rediscoveries,
	) == 0 {
		return Report{}
	}

	index := backend.rediscoverIndex

	if index >= len(
		backend.rediscoveries,
	) {
		index = len(backend.rediscoveries) - 1
	}

	backend.rediscoverIndex++

	return backend.rediscoveries[index]
}

func TestApproval2ControllerExecutesSupportedTransactionAndConverges(
	t *testing.T,
) {
	t.Parallel()

	approval1, approval :=
		approval2ControllerTestState(
			t,
		)

	post := approval1.Rediscovered
	postPlan := approval2ControllerConvergedPlan(
		approval1.Approval2Plan,
	)

	backend := &fakeApproval2ControllerBackend{
		plans: []InstallPlan{
			approval1.Approval2Plan,
			postPlan,
		},

		rediscoveries: []Report{
			approval1.Rediscovered,
			post,
		},
	}

	var output bytes.Buffer

	result, err := executeApproval2ControllerWithBackend(
		&output,
		approval1,
		PlanInputs{},
		approval,
		backend,
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.RollbackAttempted {
		t.Fatal(
			"successful Approval 2 transaction unexpectedly rolled back",
		)
	}

	if strings.TrimSpace(
		result.TransactionID,
	) == "" {
		t.Fatal(
			"Approval 2 transaction ID is empty",
		)
	}

	if len(
		result.Applied,
	) != 2 {
		t.Fatalf(
			"applied mutations=%v want=2",
			result.Applied,
		)
	}

	wantEvents := []string{
		"rediscover",
		"build-plan",
		"apply:local-id",
		"apply:config",
		"rediscover",
		"build-plan",
	}

	if strings.Join(
		backend.events,
		"|",
	) != strings.Join(
		wantEvents,
		"|",
	) {
		t.Fatalf(
			"events=%v want=%v",
			backend.events,
			wantEvents,
		)
	}

	if !strings.Contains(
		output.String(),
		"APPROVAL 2 RESULT: PASS",
	) {
		t.Fatalf(
			"missing Approval 2 PASS output:\n%s",
			output.String(),
		)
	}
}

func TestApproval2ControllerRejectsDigestDriftBeforeMutation(
	t *testing.T,
) {
	t.Parallel()

	approval1, approval :=
		approval2ControllerTestState(
			t,
		)

	drifted := approval1.Approval2Plan

	drifted.Actions = append(
		[]PlanAction(nil),
		drifted.Actions...,
	)

	drifted.Actions[0].Detail +=
		" synthetic-drift"

	backend := &fakeApproval2ControllerBackend{
		plans: []InstallPlan{
			drifted,
		},

		rediscoveries: []Report{
			approval1.Rediscovered,
		},
	}

	var output bytes.Buffer

	_, err := executeApproval2ControllerWithBackend(
		&output,
		approval1,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		t.Fatal(
			"Approval 2 digest drift unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"state changed after Approval 2",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	for _, event := range backend.events {
		if strings.HasPrefix(
			event,
			"apply:",
		) {
			t.Fatalf(
				"mutation occurred after Approval 2 digest drift: %v",
				backend.events,
			)
		}
	}
}

func TestApproval2ControllerRejectsUnsupportedAuthorityBeforeRediscovery(
	t *testing.T,
) {
	t.Parallel()

	approval1, _ :=
		approval2ControllerTestState(
			t,
		)

	approval1.Approval2Plan.Actions = append(
		approval1.Approval2Plan.Actions,
		PlanAction{
			Action:    planActionReconcile,
			Authority: "RIGHTS",
			Detail:    "synthetic unsupported authority",
			Target:    `ISS\gFI-USN-ADMINBOX$`,
		},
	)

	digest, err := ApprovalBoundaryDigest(
		approval1.Rediscovered,
		approval1.Approval2Plan,
		approvalBoundaryLocal,
	)
	if err != nil {
		t.Fatal(err)
	}

	approval1.Approval2SHA256 = digest

	approval := approvalBoundaryTestState(
		t,
		approval1.Rediscovered,
		approval1.Approval2Plan,
		approvalBoundaryLocal,
	)

	backend := &fakeApproval2ControllerBackend{}

	var output bytes.Buffer

	_, err = executeApproval2ControllerWithBackend(
		&output,
		approval1,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		t.Fatal(
			"unsupported Approval 2 authority unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		`mutating authority "RIGHTS" is not implemented`,
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if len(
		backend.events,
	) != 0 {
		t.Fatalf(
			"backend was touched before unsupported authority rejection: %v",
			backend.events,
		)
	}
}

func TestApproval2ControllerConfigFailureRollsBackLocalIdentity(
	t *testing.T,
) {
	t.Parallel()

	approval1, approval :=
		approval2ControllerTestState(
			t,
		)

	backend := &fakeApproval2ControllerBackend{
		configErr: errors.New(
			"synthetic CONFIG failure",
		),

		plans: []InstallPlan{
			approval1.Approval2Plan,
		},

		rediscoveries: []Report{
			approval1.Rediscovered,
		},
	}

	var output bytes.Buffer

	result, err := executeApproval2ControllerWithBackend(
		&output,
		approval1,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		t.Fatal(
			"synthetic CONFIG failure unexpectedly succeeded",
		)
	}

	if !result.RollbackAttempted {
		t.Fatal(
			"Approval 2 did not roll back the earlier LOCAL ID transaction",
		)
	}

	wantTail :=
		"apply:local-id" +
			"|apply:config" +
			"|rollback:local-id"

	if !strings.Contains(
		strings.Join(
			backend.events,
			"|",
		),
		wantTail,
	) {
		t.Fatalf(
			"unexpected rollback order: %v",
			backend.events,
		)
	}
}

func TestApproval2ControllerPostMutationFailureRollsBackInReverseOrder(
	t *testing.T,
) {
	t.Parallel()

	approval1, approval :=
		approval2ControllerTestState(
			t,
		)

	failedPost := approval1.Rediscovered

	failedPost.Checks = append(
		failedPost.Checks,
		Check{
			Detail: "synthetic post-mutation failure",
			Name:   "synthetic Approval 2 convergence",
			Status: checkFail,
		},
	)

	backend := &fakeApproval2ControllerBackend{
		plans: []InstallPlan{
			approval1.Approval2Plan,
			approval2ControllerConvergedPlan(
				approval1.Approval2Plan,
			),
		},

		rediscoveries: []Report{
			approval1.Rediscovered,
			failedPost,
		},
	}

	var output bytes.Buffer

	result, err := executeApproval2ControllerWithBackend(
		&output,
		approval1,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		t.Fatal(
			"post-mutation discovery failure unexpectedly succeeded",
		)
	}

	if !result.RollbackAttempted {
		t.Fatal(
			"post-mutation failure did not trigger rollback",
		)
	}

	wantTail :=
		"apply:config" +
			"|rediscover" +
			"|build-plan" +
			"|rollback:config" +
			"|rollback:local-id"

	if !strings.Contains(
		strings.Join(
			backend.events,
			"|",
		),
		wantTail,
	) {
		t.Fatalf(
			"Approval 2 rollback was not reverse transaction order: %v",
			backend.events,
		)
	}
}

func TestApproval2ControllerTransportConfigRequiresTypedHandoff(
	t *testing.T,
) {
	t.Parallel()

	approval1, approval :=
		approval2ControllerTestState(
			t,
		)

	approval1.PKI.Handoff =
		approval1PKIHandoff{}

	backend := &fakeApproval2ControllerBackend{}

	var output bytes.Buffer

	_, err := executeApproval2ControllerWithBackend(
		&output,
		approval1,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		t.Fatal(
			"transport CONFIG without typed PKI handoff unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"complete typed Approval 1 PKI handoff",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if len(
		backend.events,
	) != 0 {
		t.Fatalf(
			"backend was touched without a typed handoff: %v",
			backend.events,
		)
	}
}

func approval2ControllerTestState(
	t *testing.T,
) (
	Approval1ControllerResult,
	ApprovalBoundaryState,
) {
	t.Helper()

	handoff := approval1CompleteTestHandoff()

	report := Report{
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

		Package: PackageState{
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
		},

		ReleaseTrust: ReleaseTrustState{
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
		},

		Trust: TransportTrustState{
			Path: `C:\ProgramData\FI\config\fi-transport-trust.conf`,

			Presence: presenceAbsent,
		},
	}

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "LOCAL ID",
				Detail:    "install approved local gMSA",
				Target:    `ISS\gFI-USN-ADMINBOX$`,
			},
			{
				Action:    planActionCreate,
				Authority: "CONFIG",
				Detail:    "persist approved transport CRL",
				Target:    handoff.CRLDestinationPath,
			},
			{
				Action:    planActionCreate,
				Authority: "CONFIG",
				Detail:    "persist approved FI transport-trust configuration",
				Target:    report.Trust.Path,
			},
		},
	}

	digest, err := ApprovalBoundaryDigest(
		report,
		plan,
		approvalBoundaryLocal,
	)
	if err != nil {
		t.Fatal(err)
	}

	approval1 := Approval1ControllerResult{
		Approval2Plan:      plan,
		Approval2Required:  true,
		Approval2SHA256:    digest,
		OldPlanInvalidated: true,

		PKI: Approval1PKITransactionResult{
			Applied: true,
			Durable: true,
			Handoff: handoff,
		},

		Rediscovered: report,
	}

	approval := approvalBoundaryTestState(
		t,
		report,
		plan,
		approvalBoundaryLocal,
	)

	return approval1, approval
}

func approval2ControllerConvergedPlan(
	before InstallPlan,
) InstallPlan {
	post := before

	post.Actions = make(
		[]PlanAction,
		0,
		len(
			before.Actions,
		),
	)

	for _, action := range before.Actions {
		if planActionMutates(
			action.Action,
		) {
			continue
		}

		post.Actions = append(
			post.Actions,
			action,
		)
	}

	return post
}
