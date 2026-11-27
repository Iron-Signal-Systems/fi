// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestApproval2InstallRecordApprovalState(
	t *testing.T,
) {
	t.Parallel()

	approval1, approval :=
		approval2ControllerTestState(
			t,
		)

	approval1.Approval1 = ApprovalBoundaryState{
		Boundary: approvalBoundaryInfrastructure,
		Given:    true,
		Required: true,
	}

	state, err :=
		approval2InstallRecordApprovalState(
			approval1,
			approval,
		)
	if err != nil {
		t.Fatal(err)
	}

	wantPlanSHA256, err := PlanDigest(
		approval1.Rediscovered,
		approval1.Approval2Plan,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.EqualFold(
		state.PlanSHA256,
		wantPlanSHA256,
	) {
		t.Fatalf(
			"record plan SHA256=%s want=%s",
			state.PlanSHA256,
			wantPlanSHA256,
		)
	}

	if !state.Approval1Required ||
		!state.Approval1Given {
		t.Fatalf(
			"Approval 1 record state=%+v",
			state,
		)
	}

	if !state.Approval2Required ||
		!state.Approval2Given {
		t.Fatalf(
			"Approval 2 record state=%+v",
			state,
		)
	}
}

func TestApproval2InstallRecordRejectsReviewedPlanDigestDrift(
	t *testing.T,
) {
	t.Parallel()

	approval1, approval :=
		approval2ControllerTestState(
			t,
		)

	approval.ReviewedPlanSHA256 =
		strings.Repeat(
			"0",
			64,
		)

	_, err :=
		approval2InstallRecordApprovalState(
			approval1,
			approval,
		)

	if err == nil {
		t.Fatal(
			"install-record mapping accepted reviewed-plan digest drift",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not match calculated plan SHA256",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestLocalApproval2SealedStateHasNoInfrastructureApproval(
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
				Action:    planActionCreate,
				Authority: "SCM",
				Detail:    "synthetic missing service repair",
				Target:    "FISender",
			},
		},
	}

	sealed, err := localApproval2SealedState(
		report,
		plan,
	)
	if err != nil {
		t.Fatal(err)
	}

	if sealed.Approval1.Required ||
		sealed.Approval1.Given {
		t.Fatalf(
			"local repair unexpectedly carries Approval 1 authority: %+v",
			sealed.Approval1,
		)
	}

	if !sealed.Approval2Required {
		t.Fatal(
			"local repair did not require Approval 2",
		)
	}

	if strings.TrimSpace(
		sealed.Approval2SHA256,
	) == "" {
		t.Fatal(
			"local repair did not seal Approval 2 digest",
		)
	}
}
