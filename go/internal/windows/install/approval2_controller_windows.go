// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type Approval2ControllerResult struct {
	Applied           []AppliedMutation
	Approval          ApprovalBoundaryState
	PostPlan          InstallPlan
	Rediscovered      Report
	RollbackAttempted bool
	RollbackErrors    []string
	TransactionID     string
}

type approval2ControllerBackend interface {
	ApplyLocalIdentities(
		report Report,
		plan InstallPlan,
	) (func() error, error)

	ApplyTransportTrust(
		report Report,
		plan InstallPlan,
		handoff approval1PKIHandoff,
		transactionID string,
	) (func() error, error)

	BuildPlan(
		report Report,
		inputs PlanInputs,
		handoff approval1PKIHandoff,
	) InstallPlan

	Rediscover() Report
}

type approval2ControllerStep struct {
	name     string
	rollback func() error
}

// executeApproval2ControllerWithBackend is deliberately not wired to
// fi-install -apply yet.
//
// It establishes the second approval boundary and transaction semantics before
// local new-install mutation authority is exposed. The controller accepts only
// the exact post-Approval-1 report, plan, typed PKI handoff, and Approval-2
// digest produced by the first controller.
//
// Before the first mutation it performs another authoritative rediscovery,
// rebuilds the Approval-2 plan, and requires the local-boundary digest to remain
// byte-for-byte equivalent to the approved digest.
//
// This initial controller slice owns only:
//
//   - LOCAL ID gMSA installation
//   - the exact two-file transport-trust CONFIG transaction
//
// Any other mutating Approval-2 authority blocks the controller before the
// first mutation. Additional local authorities are added only when their
// transaction and rollback contracts are ready.
func executeApproval2ControllerWithBackend(
	writer io.Writer,
	approval1 Approval1ControllerResult,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
	backend approval2ControllerBackend,
) (Approval2ControllerResult, error) {
	if writer == nil {
		return Approval2ControllerResult{}, errors.New(
			"Approval 2 controller output writer is required",
		)
	}

	if backend == nil {
		return Approval2ControllerResult{}, errors.New(
			"Approval 2 controller backend is required",
		)
	}

	if !approval1.OldPlanInvalidated {
		return Approval2ControllerResult{}, errors.New(
			"Approval 2 requires a completed Approval 1 result that invalidated the pre-Approval-1 plan",
		)
	}

	if !approval1.Approval2Required {
		return Approval2ControllerResult{}, errors.New(
			"Approval 1 result does not require Approval 2",
		)
	}

	if strings.TrimSpace(
		approval1.Approval2SHA256,
	) == "" {
		return Approval2ControllerResult{}, errors.New(
			"Approval 1 result does not contain the sealed Approval 2 digest",
		)
	}

	if err := validateApproval2ControllerPlan(
		approval1.Rediscovered,
		approval1.Approval2Plan,
		approval1.PKI.Handoff,
	); err != nil {
		return Approval2ControllerResult{}, fmt.Errorf(
			"sealed post-Approval-1 plan is not eligible for Approval 2: %w",
			err,
		)
	}

	if err := validateApprovalBoundaryState(
		approval1.Rediscovered,
		approval1.Approval2Plan,
		approval,
		approvalBoundaryLocal,
	); err != nil {
		return Approval2ControllerResult{}, err
	}

	if !strings.EqualFold(
		approval.BoundarySHA256,
		approval1.Approval2SHA256,
	) {
		return Approval2ControllerResult{}, fmt.Errorf(
			"Approval 2 digest does not match the digest sealed by Approval 1: approval1=%s approval2=%s",
			approval1.Approval2SHA256,
			approval.BoundarySHA256,
		)
	}

	result := Approval2ControllerResult{
		Approval:       approval,
		Applied:        make([]AppliedMutation, 0),
		RollbackErrors: make([]string, 0),
	}

	fmt.Fprintln(
		writer,
		"",
	)
	fmt.Fprintln(
		writer,
		"============================================================",
	)
	fmt.Fprintln(
		writer,
		"FI WINDOWS INSTALLER - APPROVAL 2 CONTROLLER",
	)
	fmt.Fprintln(
		writer,
		"============================================================",
	)
	fmt.Fprintf(
		writer,
		"Approved Approval 2 SHA256: %s\n",
		approval.BoundarySHA256,
	)
	fmt.Fprintln(
		writer,
		"PRE-MUTATION REDISCOVERY: authoritative local state must still match the sealed Approval 2 digest",
	)

	current := backend.Rediscover()

	currentPlan := backend.BuildPlan(
		current,
		inputs,
		approval1.PKI.Handoff,
	)

	if err := validateApproval2ControllerPlan(
		current,
		currentPlan,
		approval1.PKI.Handoff,
	); err != nil {
		return result, fmt.Errorf(
			"Approval 2 pre-mutation rediscovery failed validation: %w",
			err,
		)
	}

	currentDigest, err := ApprovalBoundaryDigest(
		current,
		currentPlan,
		approvalBoundaryLocal,
	)
	if err != nil {
		return result, err
	}

	if !strings.EqualFold(
		currentDigest,
		approval.BoundarySHA256,
	) ||
		!strings.EqualFold(
			currentDigest,
			approval1.Approval2SHA256,
		) {
		return result, fmt.Errorf(
			"state changed after Approval 2; sealed SHA256=%s approved SHA256=%s revalidated SHA256=%s; no mutation was performed",
			approval1.Approval2SHA256,
			approval.BoundarySHA256,
			currentDigest,
		)
	}

	startedAt := time.Now().UTC()

	result.TransactionID = startedAt.Format(
		"20060102T150405.000000000Z",
	)

	steps := make(
		[]approval2ControllerStep,
		0,
		2,
	)

	rollbackAll := func(
		cause error,
	) (
		Approval2ControllerResult,
		error,
	) {
		result.RollbackAttempted =
			len(steps) != 0

		result.RollbackErrors =
			result.RollbackErrors[:0]

		for index := len(steps) - 1; index >= 0; index-- {
			step := steps[index]

			if step.rollback == nil {
				continue
			}

			if rollbackErr := step.rollback(); rollbackErr != nil {
				result.RollbackErrors = append(
					result.RollbackErrors,
					step.name+
						": "+
						rollbackErr.Error(),
				)
			}
		}

		if len(result.RollbackErrors) == 0 {
			return result, cause
		}

		return result, fmt.Errorf(
			"%w; Approval 2 rollback errors: %s",
			cause,
			strings.Join(
				result.RollbackErrors,
				"; ",
			),
		)
	}

	if planHasMutationAuthority(
		currentPlan,
		"LOCAL ID",
	) {
		fmt.Fprintln(
			writer,
			"APPLY LOCAL ID: install exact approved FI gMSAs into the native local Netlogon store",
		)

		rollback, err := backend.ApplyLocalIdentities(
			current,
			currentPlan,
		)
		if err != nil {
			return rollbackAll(
				fmt.Errorf(
					"Approval 2 LOCAL ID transaction failed: %w",
					err,
				),
			)
		}

		steps = append(
			steps,
			approval2ControllerStep{
				name:     "LOCAL ID",
				rollback: rollback,
			},
		)

		result.Applied = append(
			result.Applied,
			AppliedMutation{
				Authority: "LOCAL ID",
				Target:    "FI managed service accounts",
			},
		)
	}

	if planHasMutationAuthority(
		currentPlan,
		"CONFIG",
	) {
		fmt.Fprintln(
			writer,
			"APPLY CONFIG: bind the exact Approval 1 transport PKI handoff to local FI trust",
		)

		rollback, err := backend.ApplyTransportTrust(
			current,
			currentPlan,
			approval1.PKI.Handoff,
			result.TransactionID,
		)
		if err != nil {
			return rollbackAll(
				fmt.Errorf(
					"Approval 2 transport-trust CONFIG transaction failed: %w",
					err,
				),
			)
		}

		steps = append(
			steps,
			approval2ControllerStep{
				name:     "CONFIG",
				rollback: rollback,
			},
		)

		result.Applied = append(
			result.Applied,
			AppliedMutation{
				Authority: "CONFIG",
				Target:    "FI transport trust",
			},
		)
	}

	fmt.Fprintln(
		writer,
		"POST-APPROVAL-2 REDISCOVERY: prove all implemented local mutations converged",
	)

	post := backend.Rediscover()

	postPlan := backend.BuildPlan(
		post,
		inputs,
		approval1.PKI.Handoff,
	)

	result.Rediscovered = post
	result.PostPlan = postPlan

	if post.HasFailures() {
		return rollbackAll(
			errors.New(
				"post-Approval-2 discovery contains failures",
			),
		)
	}

	if postPlan.HasBlockers() {
		return rollbackAll(
			errors.New(
				"post-Approval-2 plan contains blockers",
			),
		)
	}

	if postPlan.HasQuestions() {
		return rollbackAll(
			errors.New(
				"post-Approval-2 plan contains unanswered questions",
			),
		)
	}

	if hasApprovalBoundaryMutation(
		postPlan,
		approvalBoundaryLocal,
	) {
		return rollbackAll(
			errors.New(
				"post-Approval-2 rediscovery still contains local mutations; implemented Approval 2 transaction did not converge",
			),
		)
	}

	if hasApprovalBoundaryMutation(
		postPlan,
		approvalBoundaryInfrastructure,
	) {
		return rollbackAll(
			errors.New(
				"post-Approval-2 rediscovery unexpectedly contains Approval 1 mutations",
			),
		)
	}

	fmt.Fprintln(
		writer,
		"APPROVAL 2 RESULT: PASS",
	)
	fmt.Fprintln(
		writer,
		"Authoritative post-mutation discovery converged with no remaining mutations.",
	)

	return result, nil
}

func validateApproval2ControllerPlan(
	report Report,
	plan InstallPlan,
	handoff approval1PKIHandoff,
) error {
	if report.Host.BuildNumber != 14393 {
		return fmt.Errorf(
			"Approval 2 controller is characterized only for Windows Server 2016 build 14393; observed build=%d",
			report.Host.BuildNumber,
		)
	}

	if !report.Host.Elevated {
		return errors.New(
			"Approval 2 controller requires an elevated administrator session",
		)
	}

	if report.Join.Status != "domain" {
		return fmt.Errorf(
			"Approval 2 controller requires a domain-joined source; observed status=%s",
			valueOrNotKnown(
				report.Join.Status,
			),
		)
	}

	if plan.HasBlockers() {
		return errors.New(
			"plan contains blockers",
		)
	}

	if plan.HasQuestions() {
		return errors.New(
			"plan still contains unanswered questions",
		)
	}

	if err := validateAuthenticatedRelease(
		report,
	); err != nil {
		return err
	}

	if hasApprovalBoundaryMutation(
		plan,
		approvalBoundaryInfrastructure,
	) {
		return errors.New(
			"Approval 2 plan still contains Approval 1 infrastructure mutations",
		)
	}

	_, approval2Required := ApprovalRequirements(
		plan,
	)
	if !approval2Required {
		return errors.New(
			"Approval 2 is not required by the current plan",
		)
	}

	return validateApproval2ControllerMutationScope(
		report,
		plan,
		handoff,
	)
}

func validateApproval2ControllerMutationScope(
	report Report,
	plan InstallPlan,
	handoff approval1PKIHandoff,
) error {
	configMutationCount := 0
	crlMutationCount := 0
	trustMutationCount := 0

	for _, action := range plan.Actions {
		if !planActionMutates(
			action.Action,
		) {
			continue
		}

		switch action.Authority {
		case "LOCAL ID":
			if action.Action != planActionReconcile {
				return fmt.Errorf(
					"Approval 2 controller supports LOCAL ID only as RECONCILE; action=%s target=%s",
					action.Action,
					action.Target,
				)
			}

		case "CONFIG":
			configMutationCount++

			if err := handoff.validate(); err != nil {
				return fmt.Errorf(
					"Approval 2 CONFIG mutation requires a complete typed Approval 1 PKI handoff: %w",
					err,
				)
			}

			if action.Action != planActionCreate {
				return fmt.Errorf(
					"Approval 2 transport CONFIG supports CREATE only; action=%s target=%s",
					action.Action,
					action.Target,
				)
			}

			target := strings.TrimSpace(
				action.Target,
			)

			switch {
			case strings.EqualFold(
				target,
				strings.TrimSpace(
					handoff.CRLDestinationPath,
				),
			):
				crlMutationCount++

			case strings.EqualFold(
				target,
				strings.TrimSpace(
					report.Trust.Path,
				),
			):
				trustMutationCount++

			default:
				return fmt.Errorf(
					"Approval 2 CONFIG target %q is not implemented by the current controller",
					action.Target,
				)
			}

		default:
			return fmt.Errorf(
				"Approval 2 mutating authority %q is not implemented by the current controller; target=%s",
				action.Authority,
				action.Target,
			)
		}
	}

	if configMutationCount != 0 {
		if configMutationCount != 2 ||
			crlMutationCount != 1 ||
			trustMutationCount != 1 {
			return fmt.Errorf(
				"Approval 2 transport CONFIG requires exactly one approved CRL CREATE and one approved trust-config CREATE; config=%d crl=%d trust=%d",
				configMutationCount,
				crlMutationCount,
				trustMutationCount,
			)
		}
	}

	return nil
}
