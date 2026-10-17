// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	approvalBoundaryInfrastructure = 1
	approvalBoundaryLocal          = 2
)

type ApprovalState struct {
	Approval1Given    bool
	Approval1Required bool
	Approval2Given    bool
	Approval2Required bool
	PlanSHA256        string
}

type digestFile struct {
	ExpectedSHA256 string `json:"expected_sha256"`
	Name           string `json:"name"`
	Role           string `json:"role"`
	SignerCert     string `json:"signer_cert_sha256"`
	SignerSPKI     string `json:"signer_spki_sha256"`
}

type planDigestInput struct {
	Actions                    []PlanAction `json:"actions"`
	BuildNumber                uint32       `json:"build_number"`
	Computer                   string       `json:"computer"`
	InstalledPolicySHA256      string       `json:"installed_policy_sha256"`
	ManifestSignerCertSHA256   string       `json:"manifest_signer_cert_sha256"`
	ManifestSignerSPKISHA256   string       `json:"manifest_signer_spki_sha256"`
	PackagePolicySHA256        string       `json:"package_policy_sha256"`
	Payloads                   []digestFile `json:"payloads"`
	ReleaseID                  string       `json:"release_id"`
	ReleasePolicyAuthoritySPKI string       `json:"release_policy_authority_spki_sha256"`
}

func ApprovalRequirements(plan InstallPlan) (approval1 bool, approval2 bool) {
	for _, action := range plan.Actions {
		if !planActionMutates(action.Action) {
			continue
		}

		switch action.Authority {
		case "AD", "PKI":
			approval1 = true
		default:
			approval2 = true
		}
	}
	return approval1, approval2
}

func PlanDigest(report Report, plan InstallPlan) (string, error) {
	input := planDigestInput{
		BuildNumber:                report.Host.BuildNumber,
		Computer:                   report.Host.Computer,
		InstalledPolicySHA256:      report.ReleaseTrust.Installed.PolicySHA256,
		ManifestSignerCertSHA256:   report.Package.ManifestSignature.SignerCertSHA256,
		ManifestSignerSPKISHA256:   report.Package.ManifestSignature.SignerSPKISHA256,
		PackagePolicySHA256:        report.ReleaseTrust.Package.PolicySHA256,
		ReleaseID:                  report.Package.ReleaseID,
		ReleasePolicyAuthoritySPKI: report.ReleaseTrust.BootstrapAuthoritySPKISHA256,
	}

	for _, action := range plan.Actions {
		if planActionMutates(action.Action) {
			input.Actions = append(input.Actions, action)
		}
	}
	for _, file := range report.Package.Files {
		input.Payloads = append(input.Payloads, digestFile{
			ExpectedSHA256: file.ExpectedSHA256,
			Name:           file.Name,
			Role:           file.Role,
			SignerCert:     file.PayloadAuthenticodeSignerCertSHA256,
			SignerSPKI:     file.PayloadAuthenticodeSignerSPKISHA256,
		})
	}

	encoded, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("encode FI approval plan digest: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

func writeFailClosedApprovalPrompt(
	writer io.Writer,
	token string,
	approval string,
) {
	fmt.Fprintf(
		writer,
		"\nType exactly: %s\n",
		token,
	)
	fmt.Fprintln(
		writer,
		"Any other input is treated as rejection.",
	)
	fmt.Fprintf(
		writer,
		"The installer will exit with a non-zero status and %s will not be applied.\n",
		approval,
	)
	fmt.Fprint(
		writer,
		"> ",
	)
}
func PromptApprovals(reader io.Reader, writer io.Writer, report Report, plan InstallPlan) (ApprovalState, error) {
	if reader == nil {
		return ApprovalState{}, fmt.Errorf("approval input reader is required")
	}
	if writer == nil {
		return ApprovalState{}, fmt.Errorf("approval output writer is required")
	}

	digest, err := PlanDigest(report, plan)
	if err != nil {
		return ApprovalState{}, err
	}
	approval1, approval2 := ApprovalRequirements(plan)
	state := ApprovalState{
		Approval1Required: approval1,
		Approval2Required: approval2,
		PlanSHA256:        digest,
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI WINDOWS INSTALLER - APPROVAL")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(writer, "Plan SHA256: %s\n", digest)

	scanner := bufio.NewScanner(reader)
	if approval1 {
		writeApprovalActions(writer, plan, approvalBoundaryInfrastructure)
		token := approvalToken(approvalBoundaryInfrastructure, digest)
		writeFailClosedApprovalPrompt(writer, token, "Approval 1")
		if !scanner.Scan() {
			if scanner.Err() != nil {
				return state, fmt.Errorf("read Approval 1: %w", scanner.Err())
			}
			return state, fmt.Errorf("Approval 1 was not provided")
		}
		if strings.TrimSpace(scanner.Text()) != token {
			return state, fmt.Errorf("Approval 1 token did not match the exact approved plan")
		}
		state.Approval1Given = true
	} else {
		fmt.Fprintln(writer, "Approval 1: NOT REQUIRED - no AD/KDS/gMSA/PKI mutations are planned.")
	}

	if approval2 {
		writeApprovalActions(writer, plan, approvalBoundaryLocal)
		token := approvalToken(approvalBoundaryLocal, digest)
		writeFailClosedApprovalPrompt(writer, token, "Approval 2")
		if !scanner.Scan() {
			if scanner.Err() != nil {
				return state, fmt.Errorf("read Approval 2: %w", scanner.Err())
			}
			return state, fmt.Errorf("Approval 2 was not provided")
		}
		if strings.TrimSpace(scanner.Text()) != token {
			return state, fmt.Errorf("Approval 2 token did not match the exact approved plan")
		}
		state.Approval2Given = true
	} else {
		fmt.Fprintln(writer, "Approval 2: NOT REQUIRED - no local FI mutations are planned.")
	}

	return state, nil
}

func approvalToken(boundary int, digest string) string {
	short := digest
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("APPROVE-%d %s", boundary, short)
}

func writeApprovalActions(writer io.Writer, plan InstallPlan, boundary int) {
	fmt.Fprintln(writer, "")
	fmt.Fprintf(writer, "===== APPROVAL %d ACTIONS =====\n", boundary)
	for _, action := range plan.Actions {
		if !planActionMutates(action.Action) {
			continue
		}
		boundary1 := action.Authority == "AD" || action.Authority == "PKI"
		if boundary == approvalBoundaryInfrastructure && !boundary1 {
			continue
		}
		if boundary == approvalBoundaryLocal && boundary1 {
			continue
		}
		fmt.Fprintf(writer, "%-10s %-12s %-40s %s\n", action.Action, action.Authority, action.Target, action.Detail)
	}
}

func planActionMutates(action string) bool {
	return action == planActionCreate || action == planActionReconcile
}

type ApprovalBoundaryState struct {
	Boundary           int
	BoundarySHA256     string
	Given              bool
	Required           bool
	ReviewedPlanSHA256 string
}

type approvalBoundaryDigestInput struct {
	Actions            []PlanAction `json:"actions"`
	Boundary           int          `json:"boundary"`
	ReviewedPlanSHA256 string       `json:"reviewed_plan_sha256"`
	Version            string       `json:"version"`
}

func ApprovalBoundaryDigest(
	report Report,
	plan InstallPlan,
	boundary int,
) (string, error) {
	if boundary != approvalBoundaryInfrastructure &&
		boundary != approvalBoundaryLocal {
		return "", fmt.Errorf(
			"unsupported approval boundary %d",
			boundary,
		)
	}

	reviewedPlanSHA256, err := PlanDigest(
		report,
		plan,
	)
	if err != nil {
		return "", err
	}

	input := approvalBoundaryDigestInput{
		Boundary:           boundary,
		ReviewedPlanSHA256: reviewedPlanSHA256,
		Version:            "fi-approval-boundary/1.0",
	}
	for _, action := range plan.Actions {
		if !planActionMutates(action.Action) {
			continue
		}
		infrastructure := action.Authority == "AD" ||
			action.Authority == "PKI"
		if boundary == approvalBoundaryInfrastructure &&
			!infrastructure {
			continue
		}
		if boundary == approvalBoundaryLocal && infrastructure {
			continue
		}
		input.Actions = append(
			input.Actions,
			action,
		)
	}

	encoded, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf(
			"encode FI approval boundary digest: %w",
			err,
		)
	}
	sum := sha256.Sum256(encoded)
	return strings.ToUpper(
		hex.EncodeToString(sum[:]),
	), nil
}

func PromptApprovalBoundary(
	reader io.Reader,
	writer io.Writer,
	report Report,
	plan InstallPlan,
	boundary int,
) (ApprovalBoundaryState, error) {
	if reader == nil {
		return ApprovalBoundaryState{}, fmt.Errorf(
			"approval input reader is required",
		)
	}
	if writer == nil {
		return ApprovalBoundaryState{}, fmt.Errorf(
			"approval output writer is required",
		)
	}
	if boundary != approvalBoundaryInfrastructure &&
		boundary != approvalBoundaryLocal {
		return ApprovalBoundaryState{}, fmt.Errorf(
			"unsupported approval boundary %d",
			boundary,
		)
	}

	reviewedPlanSHA256, err := PlanDigest(
		report,
		plan,
	)
	if err != nil {
		return ApprovalBoundaryState{}, err
	}
	boundarySHA256, err := ApprovalBoundaryDigest(
		report,
		plan,
		boundary,
	)
	if err != nil {
		return ApprovalBoundaryState{}, err
	}

	required1, required2 := ApprovalRequirements(plan)
	required := required2
	if boundary == approvalBoundaryInfrastructure {
		required = required1
	}
	state := ApprovalBoundaryState{
		Boundary:           boundary,
		BoundarySHA256:     boundarySHA256,
		Required:           required,
		ReviewedPlanSHA256: reviewedPlanSHA256,
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(writer, "FI WINDOWS INSTALLER - APPROVAL %d\n", boundary)
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(writer, "Reviewed plan SHA256: %s\n", reviewedPlanSHA256)
	fmt.Fprintf(writer, "Approval %d SHA256:   %s\n", boundary, boundarySHA256)

	if !required {
		fmt.Fprintf(
			writer,
			"Approval %d: NOT REQUIRED - no mutations are planned for this boundary.\n",
			boundary,
		)
		return state, nil
	}

	writeApprovalActions(
		writer,
		plan,
		boundary,
	)
	token := approvalToken(
		boundary,
		boundarySHA256,
	)
	writeFailClosedApprovalPrompt(
		writer,
		token,
		fmt.Sprintf(
			"Approval %d",
			boundary,
		),
	)

	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		if scanner.Err() != nil {
			return state, fmt.Errorf(
				"read Approval %d: %w",
				boundary,
				scanner.Err(),
			)
		}
		return state, fmt.Errorf(
			"Approval %d was not provided",
			boundary,
		)
	}
	if strings.TrimSpace(scanner.Text()) != token {
		return state, fmt.Errorf(
			"Approval %d token did not match the exact approved boundary digest",
			boundary,
		)
	}
	state.Given = true

	if boundary == approvalBoundaryInfrastructure {
		fmt.Fprintln(
			writer,
			"Approval 1 grants no Approval 2 authority; local mutation requires a new post-rediscovery digest and explicit Approval 2.",
		)
	}
	return state, nil
}
