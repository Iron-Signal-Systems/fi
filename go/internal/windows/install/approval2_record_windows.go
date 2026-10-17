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

const approval2TransactionTimeLayout = "20060102T150405.000000000Z"

// executeRecordedApproval2Controller is the production wrapper around the pure
// Approval-2 transaction controller.
//
// The underlying controller owns mutation, rollback, and convergence.
// This wrapper owns the durable transaction record. Unit tests may continue to
// exercise executeApproval2ControllerWithBackend without writing host state.
func executeRecordedApproval2Controller(
	writer io.Writer,
	approval1 Approval1ControllerResult,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
	backend approval2ControllerBackend,
) (Approval2ControllerResult, error) {
	result, controllerErr :=
		executeApproval2ControllerWithBackend(
			writer,
			approval1,
			inputs,
			approval,
			backend,
		)

	// No transaction ID means mutation never crossed the pre-mutation
	// revalidation boundary. There is no transaction to record.
	if strings.TrimSpace(
		result.TransactionID,
	) == "" {
		return result, controllerErr
	}

	recordErr := persistApproval2ControllerInstallRecord(
		writer,
		approval1,
		inputs,
		approval,
		backend,
		&result,
		controllerErr,
	)

	if recordErr != nil {
		recordFailure := fmt.Errorf(
			"write durable FI Approval 2 install record: %w",
			recordErr,
		)

		if controllerErr != nil {
			return result, errors.Join(
				controllerErr,
				recordFailure,
			)
		}

		return result, fmt.Errorf(
			"Approval 2 converged, but durable FI install record failed: %w",
			recordErr,
		)
	}

	return result, controllerErr
}

func persistApproval2ControllerInstallRecord(
	writer io.Writer,
	approval1 Approval1ControllerResult,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
	backend approval2ControllerBackend,
	result *Approval2ControllerResult,
	controllerErr error,
) error {
	if writer == nil {
		return errors.New(
			"Approval 2 install-record output writer is required",
		)
	}

	if backend == nil {
		return errors.New(
			"Approval 2 install-record backend is required",
		)
	}

	if result == nil {
		return errors.New(
			"Approval 2 install-record result is required",
		)
	}

	startedAt, err := time.Parse(
		approval2TransactionTimeLayout,
		result.TransactionID,
	)
	if err != nil {
		return fmt.Errorf(
			"parse Approval 2 transaction ID %q: %w",
			result.TransactionID,
			err,
		)
	}

	approvalState, err :=
		approval2InstallRecordApprovalState(
			approval1,
			approval,
		)
	if err != nil {
		return err
	}

	context := newInstallRecordContext(
		approval1.Rediscovered,
		approval1.Approval2Plan,
		approvalState,
		result.TransactionID,
		startedAt,
	)

	var postMutation *Report
	var postMutationPlan *InstallPlan

	if result.Rediscovered.Host.BuildNumber != 0 {
		post := result.Rediscovered
		postPlan := result.PostPlan

		postMutation = &post
		postMutationPlan = &postPlan
	}

	var final Report
	var finalPlan InstallPlan

	if controllerErr == nil &&
		result.Rediscovered.Host.BuildNumber != 0 {
		final = result.Rediscovered
		finalPlan = result.PostPlan
	} else {
		final = backend.Rediscover()
		finalPlan = backend.BuildPlan(
			final,
			inputs,
			approval1.PKI.Handoff,
		)
	}

	recordResult := "PASS"
	if controllerErr != nil {
		recordResult = "FAIL"
	}

	record := buildInstallRecord(
		context,
		result.Applied,
		recordResult,
		controllerErr,
		result.RollbackAttempted,
		result.RollbackErrors,
		postMutation,
		postMutationPlan,
		final,
		finalPlan,
	)

	path, hash, err := writeInstallRecord(
		record,
	)
	if err != nil {
		return err
	}

	result.RecordPath = path
	result.RecordSHA256 = hash

	fmt.Fprintf(
		writer,
		"Install record: %s\n",
		path,
	)
	fmt.Fprintf(
		writer,
		"Install record SHA256: %s\n",
		hash,
	)

	return nil
}

func approval2InstallRecordApprovalState(
	approval1 Approval1ControllerResult,
	approval ApprovalBoundaryState,
) (ApprovalState, error) {
	planSHA256, err := PlanDigest(
		approval1.Rediscovered,
		approval1.Approval2Plan,
	)
	if err != nil {
		return ApprovalState{}, fmt.Errorf(
			"calculate Approval 2 reviewed-plan digest for install record: %w",
			err,
		)
	}

	reviewed := strings.TrimSpace(
		approval.ReviewedPlanSHA256,
	)

	if reviewed == "" {
		return ApprovalState{}, errors.New(
			"Approval 2 install record requires the reviewed plan SHA256",
		)
	}

	if !strings.EqualFold(
		reviewed,
		planSHA256,
	) {
		return ApprovalState{}, fmt.Errorf(
			"Approval 2 reviewed plan SHA256=%s does not match calculated plan SHA256=%s",
			reviewed,
			planSHA256,
		)
	}

	return ApprovalState{
		Approval1Required: approval1.Approval1.Required,
		Approval1Given:    approval1.Approval1.Given,
		Approval2Required: approval.Required,
		Approval2Given:    approval.Given,
		PlanSHA256:        planSHA256,
	}, nil
}
