// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"io"
	"strings"
)

type Approval1PKITransactionResult struct {
	Applied bool
	Detail  string
}

type Approval1ControllerResult struct {
	AD                 Approval1ADTransactionResult
	Approval1          ApprovalBoundaryState
	Approval2Plan      InstallPlan
	Approval2Required  bool
	Approval2SHA256    string
	OldPlanInvalidated bool
	PKI                Approval1PKITransactionResult
	Rediscovered       Report
	RollbackAttempted  bool
	RollbackErrors     []string
}

type approval1ControllerBackend interface {
	approval1ADGMSABackend
	ApplyPKI(
		before Report,
		plan InstallPlan,
	) (Approval1PKITransactionResult, error)
	RollbackPKI(
		before Report,
		plan InstallPlan,
		result Approval1PKITransactionResult,
	) error
	Rediscover() Report
	BuildPlan(
		report Report,
		inputs PlanInputs,
	) InstallPlan
}

// executeApproval1ControllerWithBackend is deliberately not wired to
// fi-install -apply in this milestone. It establishes the two-boundary
// controller semantics before any new-install mutation authority is exposed.
//
// Approval 1 is valid only for the exact pre-mutation boundary digest. The
// controller rediscoveries immediately before mutation and immediately after
// the infrastructure transaction are mandatory. The pre-Approval-1 plan is
// never reused as Approval 2 authority.
func executeApproval1ControllerWithBackend(
	writer io.Writer,
	before Report,
	plan InstallPlan,
	inputs PlanInputs,
	approval ApprovalBoundaryState,
	backend approval1ControllerBackend,
) (Approval1ControllerResult, error) {
	if writer == nil {
		return Approval1ControllerResult{}, fmt.Errorf(
			"Approval 1 controller output writer is required",
		)
	}
	if backend == nil {
		return Approval1ControllerResult{}, fmt.Errorf(
			"Approval 1 controller backend is required",
		)
	}
	if err := validateApproval1ControllerPlan(
		before,
		plan,
	); err != nil {
		return Approval1ControllerResult{}, err
	}
	if err := validateApprovalBoundaryState(
		before,
		plan,
		approval,
		approvalBoundaryInfrastructure,
	); err != nil {
		return Approval1ControllerResult{}, err
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI WINDOWS INSTALLER - APPROVAL 1 CONTROLLER")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(
		writer,
		"Approved Approval 1 SHA256: %s\n",
		approval.BoundarySHA256,
	)
	fmt.Fprintln(
		writer,
		"PRE-MUTATION REDISCOVERY: authoritative state must still match the approved Approval 1 digest",
	)

	current := backend.Rediscover()
	currentPlan := backend.BuildPlan(
		current,
		inputs,
	)
	if err := validateApproval1ControllerPlan(
		current,
		currentPlan,
	); err != nil {
		return Approval1ControllerResult{}, fmt.Errorf(
			"Approval 1 pre-mutation rediscovery failed validation: %w",
			err,
		)
	}
	currentDigest, err := ApprovalBoundaryDigest(
		current,
		currentPlan,
		approvalBoundaryInfrastructure,
	)
	if err != nil {
		return Approval1ControllerResult{}, err
	}
	if !strings.EqualFold(
		currentDigest,
		approval.BoundarySHA256,
	) {
		return Approval1ControllerResult{}, fmt.Errorf(
			"state changed after Approval 1; approved Approval 1 SHA256=%s revalidated SHA256=%s; no mutation was performed",
			approval.BoundarySHA256,
			currentDigest,
		)
	}

	identities, err := approval1ADCreateIdentities(
		current,
		currentPlan,
	)
	if err != nil {
		return Approval1ControllerResult{}, fmt.Errorf(
			"prepare Approval 1 AD transaction: %w",
			err,
		)
	}

	result := Approval1ControllerResult{
		Approval1:      approval,
		RollbackErrors: make([]string, 0),
	}
	adResult, err := executeApproval1ADGMSATransactionWithBackend(
		writer,
		current,
		identities,
		backend,
	)
	result.AD = adResult
	if err != nil {
		return result, err
	}

	rollbackOuter := func(cause error) (Approval1ControllerResult, error) {
		result.RollbackAttempted = result.PKI.Applied ||
			len(result.AD.Created) != 0

		if result.PKI.Applied {
			fmt.Fprintln(
				writer,
				"ROLLBACK PKI: reverse Approval 1 transport-PKI mutation",
			)
			if rollbackErr := backend.RollbackPKI(
				current,
				currentPlan,
				result.PKI,
			); rollbackErr != nil {
				result.RollbackErrors = append(
					result.RollbackErrors,
					"PKI: "+rollbackErr.Error(),
				)
			}
		}

		adRollbackErrors := rollbackApproval1ADCreatedWithBackend(
			writer,
			current,
			currentPlan,
			result.AD,
			backend,
		)
		result.RollbackErrors = append(
			result.RollbackErrors,
			adRollbackErrors...,
		)
		result.AD.RollbackAttempted = len(result.AD.Created) != 0
		result.AD.RollbackErrors = append(
			result.AD.RollbackErrors[:0],
			adRollbackErrors...,
		)

		if len(result.RollbackErrors) == 0 {
			return result, cause
		}
		return result, fmt.Errorf(
			"%w; Approval 1 outer rollback errors: %s",
			cause,
			strings.Join(
				result.RollbackErrors,
				"; ",
			),
		)
	}

	if planHasMutationAuthority(
		currentPlan,
		"PKI",
	) {
		fmt.Fprintln(
			writer,
			"APPLY PKI: execute the exact Approval 1 transport-PKI transaction",
		)
		result.PKI, err = backend.ApplyPKI(
			current,
			currentPlan,
		)
		if err != nil {
			return rollbackOuter(
				fmt.Errorf(
					"Approval 1 PKI transaction failed: %w",
					err,
				),
			)
		}
		if !result.PKI.Applied {
			return rollbackOuter(
				fmt.Errorf(
					"Approval 1 PKI transaction returned success without transaction ownership",
				),
			)
		}
	} else {
		fmt.Fprintln(
			writer,
			"APPROVAL 1 PKI: NO-OP - no transport-PKI mutation is planned",
		)
	}

	fmt.Fprintln(
		writer,
		"POST-APPROVAL-1 REDISCOVERY: discard the approved pre-mutation plan and rebuild from authoritative state",
	)
	post := backend.Rediscover()
	postPlan := backend.BuildPlan(
		post,
		inputs,
	)
	result.Rediscovered = post
	result.Approval2Plan = postPlan
	result.OldPlanInvalidated = true

	if postPlan.HasBlockers() {
		return rollbackOuter(
			fmt.Errorf(
				"post-Approval-1 plan contains blockers",
			),
		)
	}
	if postPlan.HasQuestions() {
		return rollbackOuter(
			fmt.Errorf(
				"post-Approval-1 plan contains unanswered questions",
			),
		)
	}
	if hasApprovalBoundaryMutation(
		postPlan,
		approvalBoundaryInfrastructure,
	) {
		return rollbackOuter(
			fmt.Errorf(
				"post-Approval-1 rediscovery still contains Approval 1 mutations; infrastructure did not converge",
			),
		)
	}
	if err := validateAuthenticatedRelease(
		post,
	); err != nil {
		return rollbackOuter(
			fmt.Errorf(
				"post-Approval-1 release authentication failed: %w",
				err,
			),
		)
	}

	_, result.Approval2Required = ApprovalRequirements(
		postPlan,
	)
	if result.Approval2Required {
		result.Approval2SHA256, err = ApprovalBoundaryDigest(
			post,
			postPlan,
			approvalBoundaryLocal,
		)
		if err != nil {
			return rollbackOuter(err)
		}
	}

	fmt.Fprintln(writer, "APPROVAL 1 RESULT: PASS")
	fmt.Fprintln(
		writer,
		"The pre-Approval-1 plan is invalidated and cannot authorize local mutation.",
	)
	if result.Approval2Required {
		fmt.Fprintf(
			writer,
			"New Approval 2 SHA256: %s\n",
			result.Approval2SHA256,
		)
		fmt.Fprintln(
			writer,
			"STOP: explicit Approval 2 is required before any local FI mutation.",
		)
	} else {
		fmt.Fprintln(
			writer,
			"Approval 2: NOT REQUIRED - no local FI mutation remains after rediscovery.",
		)
	}
	return result, nil
}

func rollbackApproval1ADCreatedWithBackend(
	writer io.Writer,
	before Report,
	plan InstallPlan,
	result Approval1ADTransactionResult,
	backend approval1ADGMSABackend,
) []string {
	if len(result.Created) == 0 {
		return nil
	}

	identityBySAM := make(map[string]DesiredFIIdentity)
	for _, identity := range desiredFIIdentityList(
		plan.Identities,
	) {
		identityBySAM[strings.ToLower(
			strings.TrimSpace(identity.SAMAccountName),
		)] = identity
	}

	errorsFound := make([]string, 0)
	for index := len(result.Created) - 1; index >= 0; index-- {
		created := result.Created[index]
		identity, found := identityBySAM[strings.ToLower(
			strings.TrimSpace(created.SAMAccountName),
		)]
		if !found {
			errorsFound = append(
				errorsFound,
				created.SAMAccountName+": cannot map transaction-owned gMSA to approved FI identity",
			)
			continue
		}
		fmt.Fprintf(
			writer,
			"ROLLBACK AD: delete transaction-created %s (%s)\n",
			identity.SAMAccountName,
			identity.Role,
		)
		if err := backend.RollbackCreated(
			before,
			identity,
		); err != nil {
			errorsFound = append(
				errorsFound,
				identity.SAMAccountName+": "+err.Error(),
			)
		}
	}
	return errorsFound
}

func validateApproval1ControllerPlan(
	report Report,
	plan InstallPlan,
) error {
	if report.Host.BuildNumber != 14393 {
		return fmt.Errorf(
			"Approval 1 controller is characterized only for Windows Server 2016 build 14393; observed build=%d",
			report.Host.BuildNumber,
		)
	}
	if !report.Host.Elevated {
		return fmt.Errorf(
			"Approval 1 controller requires an elevated administrator session",
		)
	}
	if report.Join.Status != "domain" {
		return fmt.Errorf(
			"Approval 1 controller requires a domain-joined source; observed status=%s",
			valueOrNotKnown(report.Join.Status),
		)
	}
	if plan.HasBlockers() {
		return fmt.Errorf("plan contains blockers")
	}
	if plan.HasQuestions() {
		return fmt.Errorf("plan still contains unanswered questions")
	}
	if err := validateAuthenticatedRelease(
		report,
	); err != nil {
		return err
	}
	approval1Required, _ := ApprovalRequirements(plan)
	if !approval1Required {
		return fmt.Errorf(
			"Approval 1 is not required by the current plan",
		)
	}
	return nil
}

func validateAuthenticatedRelease(report Report) error {
	if !report.Package.ManifestValid ||
		!report.Package.PayloadHashesMatch ||
		!report.Package.AuthenticodeFilesTrusted ||
		!report.Package.AuthenticodeSignerIdentitiesComplete ||
		!report.Package.AuthenticodeSignersAuthorized ||
		!report.Package.ManifestSignature.SignatureValid ||
		!report.Package.ManifestSignature.SignerChainTrusted ||
		!report.ReleaseTrust.ManifestSignerAuthorized ||
		!report.ReleaseTrust.TransitionAllowed {
		return fmt.Errorf(
			"release package is not fully authenticated, transition-valid, and FI-authorized",
		)
	}
	return nil
}

func validateApprovalBoundaryState(
	report Report,
	plan InstallPlan,
	approval ApprovalBoundaryState,
	boundary int,
) error {
	if approval.Boundary != boundary {
		return fmt.Errorf(
			"approval boundary mismatch: approved=%d required=%d",
			approval.Boundary,
			boundary,
		)
	}
	if !approval.Required {
		return fmt.Errorf(
			"Approval %d state does not mark the boundary as required",
			boundary,
		)
	}
	if !approval.Given {
		return fmt.Errorf(
			"Approval %d is required but was not granted",
			boundary,
		)
	}

	reviewedPlanSHA256, err := PlanDigest(
		report,
		plan,
	)
	if err != nil {
		return err
	}
	if !strings.EqualFold(
		reviewedPlanSHA256,
		approval.ReviewedPlanSHA256,
	) {
		return fmt.Errorf(
			"Approval %d reviewed-plan digest mismatch: approved=%s current=%s",
			boundary,
			approval.ReviewedPlanSHA256,
			reviewedPlanSHA256,
		)
	}

	boundarySHA256, err := ApprovalBoundaryDigest(
		report,
		plan,
		boundary,
	)
	if err != nil {
		return err
	}
	if !strings.EqualFold(
		boundarySHA256,
		approval.BoundarySHA256,
	) {
		return fmt.Errorf(
			"Approval %d boundary digest mismatch: approved=%s current=%s",
			boundary,
			approval.BoundarySHA256,
			boundarySHA256,
		)
	}
	return nil
}

func hasApprovalBoundaryMutation(
	plan InstallPlan,
	boundary int,
) bool {
	for _, action := range plan.Actions {
		if !planActionMutates(action.Action) {
			continue
		}
		infrastructure := action.Authority == "AD" ||
			action.Authority == "PKI"
		if boundary == approvalBoundaryInfrastructure && infrastructure {
			return true
		}
		if boundary == approvalBoundaryLocal && !infrastructure {
			return true
		}
	}
	return false
}
