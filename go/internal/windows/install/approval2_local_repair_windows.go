// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"io"
)

// RequiresServer2016Approval2Controller reports whether the current plan
// contains a characterized local mutation that the legacy one-plan Server 2016
// apply path intentionally does not own.
//
// PACKAGE, RIGHTS, GROUPS, ACL, RELEASE TRUST, and ordinary RUNTIME
// reconciliation remain on the already-characterized legacy update path when
// they are the only local mutations.
//
// CONFIG, LOCAL ID, and SCM require the newer Approval-2 transaction
// controller because that controller owns:
//   - local gMSA installation,
//   - operational configuration creation,
//   - service creation/reconciliation,
//   - ordered activation,
//   - broker readiness,
//   - rollback ownership,
//   - authoritative post-mutation convergence.
func RequiresServer2016Approval2Controller(
	plan InstallPlan,
) bool {
	for _, action := range plan.Actions {
		if !planActionMutates(
			action.Action,
		) {
			continue
		}

		switch action.Authority {
		case "CONFIG", "LOCAL ID", "SCM":
			return true
		}
	}

	return false
}

// ExecuteServer2016LocalApproval2Controller executes an Approval-2-only local
// repair/reinstall transaction.
//
// This path is valid only when authoritative discovery proves that no Approval
// 1 AD/PKI mutation is required. The operator still approves the exact local
// boundary digest, the controller rediscoveries immediately before mutation,
// and the production wrapper writes the same durable install record used by
// other FI installer mutation paths.
func ExecuteServer2016LocalApproval2Controller(
	writer io.Writer,
	before Report,
	plan InstallPlan,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
) (Approval2ControllerResult, error) {
	if writer == nil {
		return Approval2ControllerResult{}, fmt.Errorf(
			"local Approval 2 controller output writer is required",
		)
	}

	sealed, err := localApproval2SealedState(
		before,
		plan,
	)
	if err != nil {
		return Approval2ControllerResult{}, err
	}

	backend := &server2016Approval2Backend{}

	return executeRecordedApproval2Controller(
		writer,
		sealed,
		inputs,
		approval,
		backend,
	)
}

func executeLocalApproval2ControllerWithBackend(
	writer io.Writer,
	before Report,
	plan InstallPlan,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
	backend approval2ControllerBackend,
) (Approval2ControllerResult, error) {
	if writer == nil {
		return Approval2ControllerResult{}, fmt.Errorf(
			"local Approval 2 controller output writer is required",
		)
	}

	if backend == nil {
		return Approval2ControllerResult{}, fmt.Errorf(
			"local Approval 2 controller backend is required",
		)
	}

	sealed, err := localApproval2SealedState(
		before,
		plan,
	)
	if err != nil {
		return Approval2ControllerResult{}, err
	}

	// Keep the testable controller path free of durable host writes.
	return executeApproval2ControllerWithBackend(
		writer,
		sealed,
		inputs,
		approval,
		backend,
	)
}

func localApproval2SealedState(
	before Report,
	plan InstallPlan,
) (Approval1ControllerResult, error) {
	approval1Required, approval2Required :=
		ApprovalRequirements(
			plan,
		)

	if approval1Required {
		return Approval1ControllerResult{}, fmt.Errorf(
			"local Approval 2 controller refuses a plan containing Approval 1 AD/PKI mutations",
		)
	}

	if !approval2Required {
		return Approval1ControllerResult{}, fmt.Errorf(
			"local Approval 2 controller requires at least one local mutation",
		)
	}

	if !RequiresApproval2Controller(
		plan,
	) {
		return Approval1ControllerResult{}, fmt.Errorf(
			"plan does not require the local Approval 2 controller",
		)
	}

	digest, err := ApprovalBoundaryDigest(
		before,
		plan,
		approvalBoundaryLocal,
	)
	if err != nil {
		return Approval1ControllerResult{}, fmt.Errorf(
			"seal local Approval 2 repair boundary: %w",
			err,
		)
	}

	// The core Approval-2 transaction engine consumes the same sealed
	// post-Approval-1 shape used by first installation. A local-only repair has
	// no Approval-1 mutation and therefore no PKI handoff. Construct the
	// equivalent sealed local authority directly from authoritative current
	// state. This grants no AD/PKI authority.
	return Approval1ControllerResult{
		Approval1: ApprovalBoundaryState{
			Boundary: approvalBoundaryInfrastructure,
			Given:    false,
			Required: false,
		},

		Approval2Plan:      plan,
		Approval2Required:  true,
		Approval2SHA256:    digest,
		OldPlanInvalidated: true,
		Rediscovered:       before,
	}, nil
}
