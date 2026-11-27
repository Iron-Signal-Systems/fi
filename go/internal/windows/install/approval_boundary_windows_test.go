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

func TestApprovalBoundaryDigestSeparatesApproval1AndApproval2(
	testingT *testing.T,
) {
	testingT.Parallel()

	report, plan := approval1ControllerTestState(testingT)
	approval1, err := ApprovalBoundaryDigest(
		report,
		plan,
		approvalBoundaryInfrastructure,
	)
	if err != nil {
		testingT.Fatalf("Approval 1 digest: %v", err)
	}
	approval2, err := ApprovalBoundaryDigest(
		report,
		plan,
		approvalBoundaryLocal,
	)
	if err != nil {
		testingT.Fatalf("Approval 2 digest: %v", err)
	}
	if strings.EqualFold(approval1, approval2) {
		testingT.Fatal("Approval 1 and Approval 2 digests are identical")
	}
}

func TestApproval1BoundaryDigestCommitsToReviewedFullPlan(
	testingT *testing.T,
) {
	testingT.Parallel()

	report, plan := approval1ControllerTestState(testingT)
	before, err := ApprovalBoundaryDigest(
		report,
		plan,
		approvalBoundaryInfrastructure,
	)
	if err != nil {
		testingT.Fatalf("before digest: %v", err)
	}

	changed := plan
	changed.Actions = append(
		append([]PlanAction(nil), plan.Actions...),
		PlanAction{
			Action:    planActionReconcile,
			Authority: "ACL",
			Target:    `C:\ProgramData\FI\state`,
			Detail:    "local-plan change that Approval 1 does not authorize",
		},
	)
	after, err := ApprovalBoundaryDigest(
		report,
		changed,
		approvalBoundaryInfrastructure,
	)
	if err != nil {
		testingT.Fatalf("after digest: %v", err)
	}
	if strings.EqualFold(before, after) {
		testingT.Fatal("Approval 1 digest did not commit to the reviewed full plan")
	}
}

func TestPromptApprovalBoundaryOneDoesNotGrantApprovalTwo(
	testingT *testing.T,
) {
	testingT.Parallel()

	report, plan := approval1ControllerTestState(testingT)
	digest, err := ApprovalBoundaryDigest(
		report,
		plan,
		approvalBoundaryInfrastructure,
	)
	if err != nil {
		testingT.Fatalf("Approval 1 digest: %v", err)
	}
	input := strings.NewReader(
		approvalToken(
			approvalBoundaryInfrastructure,
			digest,
		) + "\n",
	)
	var output bytes.Buffer
	state, err := PromptApprovalBoundary(
		input,
		&output,
		report,
		plan,
		approvalBoundaryInfrastructure,
	)
	if err != nil {
		testingT.Fatalf("prompt Approval 1: %v", err)
	}
	if !state.Given || !state.Required {
		testingT.Fatalf("unexpected state: %+v", state)
	}
	if !strings.Contains(
		output.String(),
		"Approval 1 grants no Approval 2 authority",
	) {
		testingT.Fatalf("missing boundary warning:\n%s", output.String())
	}
}

func TestValidateApprovalBoundaryStateRejectsWrongBoundaryDigest(
	testingT *testing.T,
) {
	testingT.Parallel()

	report, plan := approval1ControllerTestState(testingT)
	state := approvalBoundaryTestState(
		testingT,
		report,
		plan,
		approvalBoundaryInfrastructure,
	)
	state.BoundarySHA256 = strings.Repeat("0", 64)
	if err := validateApprovalBoundaryState(
		report,
		plan,
		state,
		approvalBoundaryInfrastructure,
	); err == nil {
		testingT.Fatal("wrong Approval 1 digest was unexpectedly accepted")
	}
}
