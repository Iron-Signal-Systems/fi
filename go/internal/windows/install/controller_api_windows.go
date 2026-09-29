// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "io"

func PromptApproval1Boundary(
	reader io.Reader,
	writer io.Writer,
	report Report,
	plan InstallPlan,
) (ApprovalBoundaryState, error) {
	return PromptApprovalBoundary(
		reader,
		writer,
		report,
		plan,
		approvalBoundaryInfrastructure,
	)
}

func PromptApproval2Boundary(
	reader io.Reader,
	writer io.Writer,
	report Report,
	plan InstallPlan,
) (ApprovalBoundaryState, error) {
	return PromptApprovalBoundary(
		reader,
		writer,
		report,
		plan,
		approvalBoundaryLocal,
	)
}

func ExecuteServer2016Approval1Controller(
	writer io.Writer,
	before Report,
	plan InstallPlan,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
) (Approval1ControllerResult, error) {
	return executeServer2016Approval1Controller(
		writer,
		before,
		plan,
		inputs,
		approval,
	)
}

func ExecuteServer2016Approval2Controller(
	writer io.Writer,
	approval1 Approval1ControllerResult,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
) (Approval2ControllerResult, error) {
	return executeServer2016Approval2Controller(
		writer,
		approval1,
		inputs,
		approval,
	)
}
