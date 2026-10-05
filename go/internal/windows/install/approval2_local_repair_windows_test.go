// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"strings"
	"testing"
)

func TestRequiresServer2016Approval2Controller(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		name      string
		authority string
		action    string
		want      bool
	}{
		{
			name:      "SCM create",
			authority: "SCM",
			action:    planActionCreate,
			want:      true,
		},
		{
			name:      "SCM reconcile",
			authority: "SCM",
			action:    planActionReconcile,
			want:      true,
		},
		{
			name:      "LOCAL ID reconcile",
			authority: "LOCAL ID",
			action:    planActionReconcile,
			want:      true,
		},
		{
			name:      "CONFIG create",
			authority: "CONFIG",
			action:    planActionCreate,
			want:      true,
		},
		{
			name:      "PACKAGE reconcile stays legacy",
			authority: "PACKAGE",
			action:    planActionReconcile,
			want:      false,
		},
		{
			name:      "RIGHTS reconcile stays legacy",
			authority: "RIGHTS",
			action:    planActionReconcile,
			want:      false,
		},
		{
			name:      "GROUPS reconcile stays legacy",
			authority: "GROUPS",
			action:    planActionReconcile,
			want:      false,
		},
		{
			name:      "ACL reconcile stays legacy",
			authority: "ACL",
			action:    planActionReconcile,
			want:      false,
		},
		{
			name:      "RUNTIME reconcile stays legacy",
			authority: "RUNTIME",
			action:    planActionReconcile,
			want:      false,
		},
		{
			name:      "RELEASE TRUST reconcile stays legacy",
			authority: "RELEASE TRUST",
			action:    planActionReconcile,
			want:      false,
		},
		{
			name:      "NO CHANGE SCM does not route",
			authority: "SCM",
			action:    planActionNoChange,
			want:      false,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(
			test.name,
			func(t *testing.T) {
				t.Parallel()

				plan := InstallPlan{
					Actions: []PlanAction{
						{
							Action:    test.action,
							Authority: test.authority,
							Target:    "synthetic target",
						},
					},
				}

				got :=
					RequiresServer2016Approval2Controller(
						plan,
					)

				if got != test.want {
					t.Fatalf(
						"RequiresServer2016Approval2Controller()=%t want=%t plan=%+v",
						got,
						test.want,
						plan,
					)
				}
			},
		)
	}
}

func TestLocalApproval2ControllerExecutesWithoutApproval1Mutation(
	t *testing.T,
) {
	t.Parallel()

	approval1, _ :=
		approval2ControllerTestState(
			t,
		)

	report := approval1.Rediscovered

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "LOCAL ID",
				Detail:    "synthetic local-only repair",
				Target:    `ISS\gFI-USN-ADMINBOX$`,
			},
		},
	}

	approval := approvalBoundaryTestState(
		t,
		report,
		plan,
		approvalBoundaryLocal,
	)

	postPlan :=
		approval2ControllerConvergedPlan(
			plan,
		)

	backend := &fakeApproval2ControllerBackend{
		plans: []InstallPlan{
			plan,
			postPlan,
		},

		rediscoveries: []Report{
			report,
			report,
		},
	}

	var output bytes.Buffer

	result, err :=
		executeLocalApproval2ControllerWithBackend(
			&output,
			report,
			plan,
			PlanInputs{},
			approval,
			backend,
		)
	if err != nil {
		t.Fatal(err)
	}

	if result.RollbackAttempted {
		t.Fatal(
			"successful local Approval 2 repair unexpectedly rolled back",
		)
	}

	if len(
		result.Applied,
	) != 1 {
		t.Fatalf(
			"applied mutations=%v want=1",
			result.Applied,
		)
	}

	wantEvents := []string{
		"rediscover",
		"build-plan",
		"apply:local-id",
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
			"missing local Approval 2 PASS output:\n%s",
			output.String(),
		)
	}
}

func TestLocalApproval2ControllerRejectsInfrastructureMutation(
	t *testing.T,
) {
	t.Parallel()

	approval1, _ :=
		approval2ControllerTestState(
			t,
		)

	report := approval1.Rediscovered

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "AD",
				Detail:    "synthetic infrastructure mutation",
				Target:    `ISS\gFI-USN-ADMINBOX$`,
			},
			{
				Action:    planActionCreate,
				Authority: "SCM",
				Detail:    "synthetic local mutation",
				Target:    "FISender",
			},
		},
	}

	approval := approvalBoundaryTestState(
		t,
		report,
		plan,
		approvalBoundaryLocal,
	)

	backend := &fakeApproval2ControllerBackend{}

	var output bytes.Buffer

	_, err :=
		executeLocalApproval2ControllerWithBackend(
			&output,
			report,
			plan,
			PlanInputs{},
			approval,
			backend,
		)

	if err == nil {
		t.Fatal(
			"local Approval 2 controller accepted an Approval 1 mutation",
		)
	}

	if !strings.Contains(
		err.Error(),
		"refuses a plan containing Approval 1 AD/PKI mutations",
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
			"backend was touched before infrastructure rejection: %v",
			backend.events,
		)
	}
}

func TestLocalApproval2ControllerRejectsLegacyOnlyPlan(
	t *testing.T,
) {
	t.Parallel()

	approval1, _ :=
		approval2ControllerTestState(
			t,
		)

	report := approval1.Rediscovered

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "PACKAGE",
				Detail:    "synthetic package-only update",
				Target:    `C:\Program Files\FI`,
			},
		},
	}

	approval := approvalBoundaryTestState(
		t,
		report,
		plan,
		approvalBoundaryLocal,
	)

	backend := &fakeApproval2ControllerBackend{}

	var output bytes.Buffer

	_, err :=
		executeLocalApproval2ControllerWithBackend(
			&output,
			report,
			plan,
			PlanInputs{},
			approval,
			backend,
		)

	if err == nil {
		t.Fatal(
			"local Approval 2 controller accepted a legacy-only package plan",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not require the Server 2016 local Approval 2 repair controller",
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
			"backend was touched for a legacy-only plan: %v",
			backend.events,
		)
	}
}
