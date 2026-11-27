// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

// RequiresApproval2Controller answers only the routing question:
//
// Does this plan require Approval 2 without also requiring Approval 1?
//
// It deliberately does not duplicate Approval-2 controller capability or
// mutation-authority validation. The Approval-2 controller owns those checks
// and must fail closed if a routed plan contains an unsupported mutation.
//
// This keeps routing correct when a plan is rebuilt after receiver activation
// selection. In particular, a Receiver-Pending plan can legitimately contain
// PACKAGE and RUNTIME reconciliation while SCM and FISender runtime state are
// already converged.
func RequiresApproval2Controller(
	plan InstallPlan,
) bool {
	approval1Required, approval2Required :=
		ApprovalRequirements(
			plan,
		)

	return !approval1Required &&
		approval2Required
}
