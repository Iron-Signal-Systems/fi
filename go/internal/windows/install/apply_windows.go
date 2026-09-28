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

type AppliedMutation struct {
	Authority string
	Target    string
}

type ApplyResult struct {
	Applied       []AppliedMutation
	PlanSHA256    string
	RecordPath    string
	RecordSHA256  string
	TransactionID string
}

type transactionStep struct {
	commit   func() error
	name     string
	rollback func() error
}

func ValidateServer2016Apply(report Report, plan InstallPlan) error {
	if report.Host.BuildNumber != 14393 {
		return fmt.Errorf("mutation is characterized only for Windows Server 2016 build 14393; observed build=%d", report.Host.BuildNumber)
	}
	if plan.HasBlockers() {
		return fmt.Errorf("plan contains blockers")
	}
	if len(plan.Questions) != 0 {
		return fmt.Errorf("plan still contains unanswered questions")
	}

	for _, action := range plan.Actions {
		if !planActionMutates(action.Action) {
			continue
		}
		switch action.Authority {
		case "RIGHTS", "GROUPS", "ACL", "RELEASE TRUST", "PACKAGE", "RUNTIME":
			// Characterized local mutation authorities.
		case "AD", "PKI":
			return fmt.Errorf("Approval 1 mutation authority %s is not enabled in this milestone; target=%s", action.Authority, action.Target)
		case "CONFIG", "LOCAL ID", "SCM":
			return fmt.Errorf("local mutation authority %s is not enabled in this milestone; target=%s", action.Authority, action.Target)
		default:
			return fmt.Errorf("unrecognized mutating authority %s target=%s", action.Authority, action.Target)
		}
	}

	if !report.Package.ManifestValid ||
		!report.Package.PayloadHashesMatch ||
		!report.Package.AuthenticodeFilesTrusted ||
		!report.Package.AuthenticodeSignerIdentitiesComplete ||
		!report.Package.AuthenticodeSignersAuthorized ||
		!report.Package.ManifestSignature.SignatureValid ||
		!report.Package.ManifestSignature.SignerChainTrusted ||
		!report.ReleaseTrust.ManifestSignerAuthorized {
		return fmt.Errorf("release package is not fully authenticated and FI-authorized")
	}
	return nil
}

func ApplyServer2016ApprovedPlan(writer io.Writer, before Report, plan InstallPlan, approvals ApprovalState) (ApplyResult, error) {
	if writer == nil {
		return ApplyResult{}, fmt.Errorf("apply output writer is required")
	}
	if err := ValidateServer2016Apply(before, plan); err != nil {
		return ApplyResult{}, err
	}

	digest, err := PlanDigest(before, plan)
	if err != nil {
		return ApplyResult{}, err
	}
	if !strings.EqualFold(digest, approvals.PlanSHA256) {
		return ApplyResult{}, fmt.Errorf("approval plan digest mismatch: approved=%s current=%s", approvals.PlanSHA256, digest)
	}
	required1, required2 := ApprovalRequirements(plan)
	if required1 && !approvals.Approval1Given {
		return ApplyResult{}, fmt.Errorf("Approval 1 is required but was not granted")
	}
	if required2 && !approvals.Approval2Given {
		return ApplyResult{}, fmt.Errorf("Approval 2 is required but was not granted")
	}

	// Re-discover after approval. Any drift invalidates the approval token.
	current := Discover()
	currentPlan := BuildPlan(current)
	if err := ValidateServer2016Apply(current, currentPlan); err != nil {
		return ApplyResult{}, fmt.Errorf("post-approval revalidation failed: %w", err)
	}
	currentDigest, err := PlanDigest(current, currentPlan)
	if err != nil {
		return ApplyResult{}, err
	}
	if !strings.EqualFold(currentDigest, approvals.PlanSHA256) {
		return ApplyResult{}, fmt.Errorf("state changed after approval; approved plan SHA256=%s revalidated SHA256=%s; rerun fi-install and approve the new plan", approvals.PlanSHA256, currentDigest)
	}

	startedAt := time.Now().UTC()
	transactionID := startedAt.Format("20060102T150405.000000000Z")
	result := ApplyResult{
		PlanSHA256:    approvals.PlanSHA256,
		TransactionID: transactionID,
	}
	steps := make([]transactionStep, 0, 6)
	recordContext := newInstallRecordContext(
		current,
		currentPlan,
		approvals,
		transactionID,
		startedAt,
	)

	rollbackAttempted := false
	rollbackErrors := make([]string, 0)

	rollbackAll := func(cause error) error {
		rollbackAttempted = len(steps) != 0
		rollbackErrors = rollbackErrors[:0]
		for index := len(steps) - 1; index >= 0; index-- {
			if steps[index].rollback == nil {
				continue
			}
			if err := steps[index].rollback(); err != nil {
				rollbackErrors = append(
					rollbackErrors,
					steps[index].name+": "+err.Error(),
				)
			}
		}
		if len(rollbackErrors) == 0 {
			return cause
		}
		return fmt.Errorf(
			"%w; rollback errors: %s",
			cause,
			strings.Join(
				rollbackErrors,
				"; ",
			),
		)
	}

	writeFailureRecord := func(
		cause error,
		postMutation *Report,
		postMutationPlan *InstallPlan,
	) (ApplyResult, error) {
		failure := rollbackAll(
			cause,
		)
		final := Discover()
		finalPlan := BuildPlan(
			final,
		)
		record := buildInstallRecord(
			recordContext,
			result.Applied,
			"FAIL",
			failure,
			rollbackAttempted,
			rollbackErrors,
			postMutation,
			postMutationPlan,
			final,
			finalPlan,
		)
		path, hash, recordErr := writeInstallRecord(
			record,
		)
		if recordErr != nil {
			return result, errors.Join(
				failure,
				fmt.Errorf(
					"write durable FI install record: %w",
					recordErr,
				),
			)
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
		return result, failure
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI WINDOWS INSTALLER - APPLY")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(writer, "Transaction: %s\n", transactionID)
	fmt.Fprintf(writer, "Approved plan SHA256: %s\n", approvals.PlanSHA256)
	if !planHasAnyMutation(
		currentPlan,
	) {
		fmt.Fprintln(
			writer,
			"APPLY NO-OP: desired state already converged; create a verified install transaction record only",
		)
	}

	if planHasMutationAuthority(currentPlan, "RIGHTS") {
		fmt.Fprintln(writer, "APPLY RIGHTS: exact Server 2016 direct-right contracts")
		rollback, err := reconcileServer2016Rights(currentPlan.Identities)
		if err != nil {
			return writeFailureRecord(
				err,
				nil,
				nil,
			)
		}
		steps = append(steps, transactionStep{name: "RIGHTS", rollback: rollback})
		result.Applied = append(result.Applied, AppliedMutation{Authority: "RIGHTS", Target: "FI service identities"})
	}

	if planHasMutationAuthority(currentPlan, "GROUPS") {
		fmt.Fprintln(writer, "APPLY GROUPS: direct local-group boundary")
		rollback, err := reconcileServer2016Groups(currentPlan.Identities)
		if err != nil {
			return writeFailureRecord(
				err,
				nil,
				nil,
			)
		}
		steps = append(steps, transactionStep{name: "GROUPS", rollback: rollback})
		result.Applied = append(result.Applied, AppliedMutation{Authority: "GROUPS", Target: "FI service identities"})
	}

	if planHasMutationAuthority(currentPlan, "ACL") {
		fmt.Fprintln(writer, "APPLY ACL: protected FI-owned roots")
		rollback, err := reconcileServer2016ACLs(current, currentPlan.Identities, currentPlan)
		if err != nil {
			return writeFailureRecord(
				err,
				nil,
				nil,
			)
		}
		steps = append(steps, transactionStep{name: "ACL", rollback: rollback})
		result.Applied = append(result.Applied, AppliedMutation{Authority: "ACL", Target: "FI-owned roots"})
	}

	if planHasMutationAuthority(currentPlan, "RELEASE TRUST") {
		fmt.Fprintln(writer, "APPLY RELEASE TRUST: install authorized policy")
		rollback, commit, err := installReleaseTrust(current, transactionID)
		if err != nil {
			return writeFailureRecord(
				err,
				nil,
				nil,
			)
		}
		steps = append(steps, transactionStep{name: "RELEASE TRUST", rollback: rollback, commit: commit})
		result.Applied = append(result.Applied, AppliedMutation{Authority: "RELEASE TRUST", Target: installedReleaseTrustRoot})
	}

	if planHasMutationAuthority(currentPlan, "PACKAGE") {
		fmt.Fprintln(writer, "APPLY PACKAGE: stop FI services, replace authenticated mismatched binaries, restart")
		rollback, commit, err := replaceRuntimeBinaries(current, transactionID)
		if err != nil {
			return writeFailureRecord(
				err,
				nil,
				nil,
			)
		}
		steps = append(steps, transactionStep{name: "PACKAGE", rollback: rollback, commit: commit})
		result.Applied = append(result.Applied, AppliedMutation{Authority: "PACKAGE", Target: `C:\Program Files\FI`})
	}

	if planHasMutationAuthority(currentPlan, "RUNTIME") {
		fmt.Fprintln(writer, "APPLY RUNTIME: start FI services whose configuration is already correct")
		rollback, err := reconcileFIRuntimeServices(
			currentPlan,
		)
		if err != nil {
			return writeFailureRecord(
				err,
				nil,
				nil,
			)
		}
		steps = append(
			steps,
			transactionStep{
				name:     "RUNTIME",
				rollback: rollback,
			},
		)
		result.Applied = append(
			result.Applied,
			AppliedMutation{
				Authority: "RUNTIME",
				Target:    "FI services",
			},
		)
	}

	// Do not destroy rollback material until authoritative post-install discovery
	// proves that every characterized mutation converged to NO CHANGE.
	after := Discover()
	afterPlan := BuildPlan(after)
	if after.HasFailures() || afterPlan.HasBlockers() || planHasAnyMutation(afterPlan) {
		writePostInstallConvergenceFailure(
			writer,
			after,
			afterPlan,
		)
		return writeFailureRecord(
			fmt.Errorf(
				"post-install verification did not converge to NO CHANGE; rollback required",
			),
			&after,
			&afterPlan,
		)
	}

	for _, step := range steps {
		if step.commit == nil {
			continue
		}
		if err := step.commit(); err != nil {
			cleanupErr := fmt.Errorf(
				"installation verified, but transaction cleanup failed at %s: %w",
				step.name,
				err,
			)
			record := buildInstallRecord(
				recordContext,
				result.Applied,
				"FAIL",
				cleanupErr,
				false,
				make([]string, 0),
				&after,
				&afterPlan,
				after,
				afterPlan,
			)
			path, hash, recordErr := writeInstallRecord(
				record,
			)
			if recordErr != nil {
				return result, errors.Join(
					cleanupErr,
					fmt.Errorf(
						"write durable FI install record: %w",
						recordErr,
					),
				)
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
			return result, cleanupErr
		}
	}

	record := buildInstallRecord(
		recordContext,
		result.Applied,
		"PASS",
		nil,
		false,
		make([]string, 0),
		&after,
		&afterPlan,
		after,
		afterPlan,
	)
	path, hash, err := writeInstallRecord(
		record,
	)
	if err != nil {
		return result, fmt.Errorf(
			"installation converged to NO CHANGE but durable FI install record failed: %w",
			err,
		)
	}
	result.RecordPath = path
	result.RecordSHA256 = hash

	fmt.Fprintln(writer, "FI APPLY RESULT: PASS")
	fmt.Fprintln(writer, "Post-install discovery and desired-state plan converged to NO CHANGE.")
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
	return result, nil
}

func planHasMutationAuthority(plan InstallPlan, authority string) bool {
	for _, action := range plan.Actions {
		if action.Authority == authority && planActionMutates(action.Action) {
			return true
		}
	}
	return false
}

func planHasAnyMutation(plan InstallPlan) bool {
	for _, action := range plan.Actions {
		if planActionMutates(action.Action) {
			return true
		}
	}
	return false
}

func writePostInstallConvergenceFailure(
	writer io.Writer,
	report Report,
	plan InstallPlan,
) {
	fmt.Fprintln(
		writer,
		"",
	)
	fmt.Fprintln(
		writer,
		"===== POST-INSTALL CONVERGENCE FAILURE =====",
	)

	failureCount := 0
	for _, check := range report.Checks {
		if check.Status != checkFail {
			continue
		}
		failureCount++
		fmt.Fprintf(
			writer,
			"[FAIL] %-42s %s\n",
			check.Name,
			check.Detail,
		)
	}
	if failureCount == 0 {
		fmt.Fprintln(
			writer,
			"[FAIL] no discovery check was FAIL; convergence was rejected by the desired-state plan",
		)
	}

	actionCount := 0
	for _, action := range plan.Actions {
		if action.Action != planActionBlocked &&
			!planActionMutates(
				action.Action,
			) {
			continue
		}
		actionCount++
		fmt.Fprintf(
			writer,
			"%-10s %-12s %-40s %s\n",
			action.Action,
			action.Authority,
			action.Target,
			action.Detail,
		)
	}
	if actionCount == 0 {
		fmt.Fprintln(
			writer,
			"NO remaining BLOCKED/CREATE/RECONCILE plan actions were present.",
		)
	}

	fmt.Fprintln(
		writer,
		"Rollback begins after the diagnostics above.",
	)
}
