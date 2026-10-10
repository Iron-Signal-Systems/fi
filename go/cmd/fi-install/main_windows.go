// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/install"
)

type repeatedStringFlag []string

func (value *repeatedStringFlag) Set(input string) error {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*value = append(
		*value,
		trimmed,
	)
	return nil
}

func (value *repeatedStringFlag) String() string {
	if value == nil {
		return ""
	}
	return strings.Join(
		[]string(*value),
		",",
	)
}

func main() {
	apply := flag.Bool(
		"apply",
		true,
		"apply the exact validated Windows Server desired-state plan after explicit approval boundaries; enabled by default",
	)
	planOnly := flag.Bool(
		"plan-only",
		false,
		"perform discovery and planning only; do not mutate FI, Active Directory, PKI, or local system state",
	)

	receiverAddress := flag.String(
		"receiver-address",
		"",
		"new-install deployment input: FI receiver address",
	)
	receiverName := flag.String(
		"receiver-name",
		"",
		"new-install deployment input: FI receiver DNS/name",
	)
	spoolDir := flag.String(
		"spool-dir",
		"",
		"new-install deployment input: FI spool directory",
	)
	stageDir := flag.String(
		"stage-dir",
		"",
		"new-install deployment input: FI stage directory; defaults to C:\\ProgramData\\FI\\transport-v2-drain\\stage",
	)
	stateDir := flag.String(
		"state-dir",
		"",
		"new-install deployment input: FI state directory; defaults to C:\\ProgramData\\FI\\state",
	)
	configPath := flag.String(
		"config",
		"",
		"new-install deployment configuration file; when omitted, missing configuration values are collected interactively",
	)
	pkiChoice := flag.String(
		"pki-choice",
		"",
		"new-install deployment input: reuse, enroll, or create",
	)

	var governedRoots repeatedStringFlag
	flag.Var(
		&governedRoots,
		"governed-root",
		"new-install deployment input: governed root; repeat for multiple roots",
	)

	flag.Parse()

	doApply :=
		*apply &&
			!*planOnly

	inputs := install.PlanInputs{
		GovernedRoots:   append([]string(nil), governedRoots...),
		PKIChoice:       strings.TrimSpace(*pkiChoice),
		ReceiverAddress: strings.TrimSpace(*receiverAddress),
		ReceiverName:    strings.TrimSpace(*receiverName),
		SpoolDir:        strings.TrimSpace(*spoolDir),
		StageDir:        strings.TrimSpace(*stageDir),
		StateDir:        strings.TrimSpace(*stateDir),
	}

	if doApply {
		if err := validateApplyPKIChoice(
			inputs.PKIChoice,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI INSTALLER INPUT BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}
	}

	report := install.Discover()

	environmentPrerequisites :=
		install.EvaluateEnvironmentPrerequisites(
			report,
		)

	if err := report.WriteText(
		os.Stdout,
	); err != nil {
		os.Exit(2)
	}
	if err := environmentPrerequisites.WriteText(
		os.Stdout,
	); err != nil {
		os.Exit(2)
	}

	if doApply &&
		environmentPrerequisites.HasFailures() {
		os.Exit(1)
	}

	if doApply &&
		environmentPrerequisites.HasApprovals() {
		publicationPlan, required, err :=
			install.BuildCATemplatePublicationPlan(
				report,
			)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI CA TEMPLATE PUBLICATION PLANNING FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}
		if !required {
			fmt.Fprintln(
				os.Stderr,
				"\nFI CA TEMPLATE PUBLICATION BLOCKED: prerequisite report requested approval but rediscovery found no publication mutation",
			)
			os.Exit(1)
		}

		publicationApproval, err :=
			install.PromptCATemplatePublicationApproval(
				os.Stdin,
				os.Stdout,
				publicationPlan,
			)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI CA TEMPLATE PUBLICATION APPROVAL FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}

		if err := install.ApplyCATemplatePublication(
			os.Stdout,
			report,
			publicationPlan,
			publicationApproval,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI CA TEMPLATE PUBLICATION FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stdout,
			"\nPOST-CA-TEMPLATE-PUBLICATION REDISCOVERY",
		)
		report = install.Discover()
		environmentPrerequisites =
			install.EvaluateEnvironmentPrerequisites(
				report,
			)
		if err := environmentPrerequisites.WriteText(
			os.Stdout,
		); err != nil {
			os.Exit(2)
		}
		if environmentPrerequisites.HasFailures() ||
			environmentPrerequisites.HasApprovals() {
			os.Exit(1)
		}
	}

	var deploymentConfigProposal *install.DeploymentConfigProposal
	if strings.TrimSpace(*configPath) != "" {
		if !inputs.ConfigEmpty() {
			fmt.Fprintln(
				os.Stderr,
				"\nFI INSTALLER CONFIG BLOCKED: -config cannot be combined with -receiver-address, -receiver-name, -spool-dir, -stage-dir, -state-dir, or -governed-root",
			)
			os.Exit(1)
		}

		proposal, err := install.LoadDeploymentConfigProposal(
			report,
			*configPath,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI INSTALLER CONFIG FILE BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		pkiChoiceValue := inputs.PKIChoice
		inputs = proposal.Inputs
		inputs.PKIChoice = pkiChoiceValue
		deploymentConfigProposal = &proposal
	}
	plan := install.BuildPlanWithInputs(
		report,
		inputs,
	)

	if doApply &&
		plan.HasQuestions() {
		var err error

		inputs, err =
			promptMissingInstallInputs(
				os.Stdin,
				os.Stdout,
				plan,
				inputs,
			)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI INSTALLER INPUT FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}

		plan = install.BuildPlanWithInputs(
			report,
			inputs,
		)
	}

	if doApply &&
		deploymentConfigProposal == nil &&
		!inputs.ConfigEmpty() {
		proposal, err := install.BuildManualDeploymentConfigProposal(
			report,
			inputs,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI INSTALLER MANUAL CONFIG BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}
		deploymentConfigProposal = &proposal
	}

	if deploymentConfigProposal != nil {
		if doApply {
			if _, err := install.PromptDeploymentConfigApproval(
				os.Stdin,
				os.Stdout,
				*deploymentConfigProposal,
			); err != nil {
				fmt.Fprintf(
					os.Stderr,
					"\nFI INSTALLER CONFIG APPROVAL FAILED: %v\n",
					err,
				)
				os.Exit(1)
			}
		} else {
			if err := install.WriteDeploymentConfigProposal(
				os.Stdout,
				*deploymentConfigProposal,
			); err != nil {
				fmt.Fprintf(
					os.Stderr,
					"\nFI INSTALLER CONFIG DISPLAY FAILED: %v\n",
					err,
				)
				os.Exit(1)
			}
		}
	}
	if doApply {
		if err := install.ValidateGovernedRootsForInstall(
			inputs.GovernedRoots,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI INSTALLER INPUT BLOCKED: %v\n",
				err,
			)
			os.Exit(1)
		}

		inputPrerequisites :=
			install.EvaluateInputPrerequisites(
				report,
				inputs,
			)

		if err := inputPrerequisites.WriteText(
			os.Stdout,
		); err != nil {
			os.Exit(2)
		}

		if inputPrerequisites.HasFailures() {
			os.Exit(1)
		}
	}
	if err := plan.WriteText(os.Stdout); err != nil {
		os.Exit(2)
	}
	if plan.HasBlockers() {
		os.Exit(1)
	}

	if !doApply {
		if report.HasFailures() {
			os.Exit(1)
		}
		return
	}

	approval1Required, _ :=
		install.ApprovalRequirements(
			plan,
		)

	if approval1Required {
		receiverPending, err := executeNewInstall(
			report,
			plan,
			inputs,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI APPROVAL-1/2 INSTALL FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}

		writeFinalState(receiverPending)
		return
	}

	if install.RequiresApproval2Controller(
		plan,
	) {
		receiverPending, err := executeLocalApproval2(
			report,
			plan,
			inputs,
		)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI LOCAL REPAIR FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}

		writeFinalState(receiverPending)
		return
	}

	if err := install.ValidateServer2016Apply(report, plan); err != nil {
		fmt.Fprintf(os.Stderr, "\nFI APPLY BLOCKED: %v\n", err)
		os.Exit(1)
	}
	approvals, err := install.PromptApprovals(os.Stdin, os.Stdout, report, plan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFI APPROVAL FAILED: %v\n", err)
		os.Exit(1)
	}
	if _, err := install.ApplyServer2016ApprovedPlan(os.Stdout, report, plan, approvals); err != nil {
		fmt.Fprintf(os.Stderr, "\nFI APPLY FAILED: %v\n", err)
		os.Exit(1)
	}

	writeFinalState(false)
}

func validateApplyPKIChoice(
	choice string,
) error {
	choice =
		strings.ToLower(
			strings.TrimSpace(
				choice,
			),
		)

	switch choice {
	case "", "enroll":
		return nil

	case "reuse", "create":
		return fmt.Errorf(
			"apply mode currently supports only -pki-choice enroll; %q remains a planning contract but has no native mutation backend yet",
			choice,
		)

	default:
		return fmt.Errorf(
			"unsupported -pki-choice %q; expected enroll for apply mode",
			choice,
		)
	}
}
func planAsks(
	plan install.InstallPlan,
	text string,
) bool {
	for _, question := range plan.Questions {
		if strings.Contains(
			question,
			text,
		) {
			return true
		}
	}

	return false
}

func promptInstallValue(
	scanner *bufio.Scanner,
	writer io.Writer,
	label string,
) (string, error) {
	if scanner == nil {
		return "", fmt.Errorf(
			"installer input scanner is unavailable",
		)
	}
	if writer == nil {
		return "", fmt.Errorf(
			"installer output writer is unavailable",
		)
	}

	fmt.Fprint(
		writer,
		label,
	)

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}

		return "", fmt.Errorf(
			"interactive installer input ended while reading %s",
			strings.TrimSpace(
				label,
			),
		)
	}

	return strings.TrimSpace(
		scanner.Text(),
	), nil
}

func promptRequiredInstallValue(
	scanner *bufio.Scanner,
	writer io.Writer,
	label string,
) (string, error) {
	for {
		value, err :=
			promptInstallValue(
				scanner,
				writer,
				label,
			)
		if err != nil {
			return "", err
		}

		if value != "" {
			return value, nil
		}

		fmt.Fprintln(
			writer,
			"Value is required.",
		)
	}
}

func promptPKIChoice(
	scanner *bufio.Scanner,
	writer io.Writer,
) (string, error) {
	for {
		value, err :=
			promptInstallValue(
				scanner,
				writer,
				"PKI path [enroll]: ",
			)
		if err != nil {
			return "", err
		}

		if value == "" {
			return "enroll", nil
		}

		if strings.EqualFold(
			value,
			"enroll",
		) {
			return "enroll", nil
		}

		fmt.Fprintln(
			writer,
			"Current native FI installer supports only enroll.",
		)
	}
}
func promptMissingInstallInputs(
	reader io.Reader,
	writer io.Writer,
	plan install.InstallPlan,
	inputs install.PlanInputs,
) (install.PlanInputs, error) {
	if reader == nil {
		return inputs, fmt.Errorf(
			"installer input is unavailable",
		)
	}
	if writer == nil {
		return inputs, fmt.Errorf(
			"installer output is unavailable",
		)
	}

	scanner :=
		bufio.NewScanner(
			reader,
		)

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
		"FI WINDOWS INSTALLER - REQUIRED DEPLOYMENT INPUT",
	)
	fmt.Fprintln(
		writer,
		"============================================================",
	)

	var err error

	if planAsks(
		plan,
		"receiver address",
	) && strings.TrimSpace(
		inputs.ReceiverAddress,
	) == "" {
		inputs.ReceiverAddress, err =
			promptRequiredInstallValue(
				scanner,
				writer,
				"FI receiver address: ",
			)
		if err != nil {
			return inputs, err
		}
	}

	if planAsks(
		plan,
		"receiver DNS/name",
	) && strings.TrimSpace(
		inputs.ReceiverName,
	) == "" {
		inputs.ReceiverName, err =
			promptRequiredInstallValue(
				scanner,
				writer,
				"FI receiver DNS/name: ",
			)
		if err != nil {
			return inputs, err
		}
	}

	if planAsks(
		plan,
		"spool location",
	) && strings.TrimSpace(
		inputs.SpoolDir,
	) == "" {
		inputs.SpoolDir, err =
			promptRequiredInstallValue(
				scanner,
				writer,
				"FI spool directory: ",
			)
		if err != nil {
			return inputs, err
		}
	}

	if planAsks(
		plan,
		"governed root",
	) && len(
		inputs.GovernedRoots,
	) == 0 {
		first, promptErr :=
			promptRequiredInstallValue(
				scanner,
				writer,
				"Governed root: ",
			)
		if promptErr != nil {
			return inputs, promptErr
		}

		inputs.GovernedRoots =
			append(
				inputs.GovernedRoots,
				first,
			)

		for {
			additional, promptErr :=
				promptInstallValue(
					scanner,
					writer,
					"Additional governed root [blank to finish]: ",
				)
			if promptErr != nil {
				return inputs, promptErr
			}

			if additional == "" {
				break
			}

			inputs.GovernedRoots =
				append(
					inputs.GovernedRoots,
					additional,
				)
		}
	}

	if planAsks(
		plan,
		"PKI path",
	) && strings.TrimSpace(
		inputs.PKIChoice,
	) == "" {
		inputs.PKIChoice, err =
			promptPKIChoice(
				scanner,
				writer,
			)
		if err != nil {
			return inputs, err
		}
	}

	return inputs, nil
}
func executeNewInstall(
	report install.Report,
	plan install.InstallPlan,
	inputs install.PlanInputs,
) (bool, error) {
	approval1Required, _ := install.ApprovalRequirements(
		plan,
	)
	if !approval1Required {
		return false, fmt.Errorf(
			"install plan does not contain an Approval 1 AD/PKI boundary",
		)
	}

	approval1, err := install.PromptApproval1Boundary(
		os.Stdin,
		os.Stdout,
		report,
		plan,
	)
	if err != nil {
		return false, fmt.Errorf(
			"Approval 1 failed: %w",
			err,
		)
	}

	approval1Result, err := install.ExecuteServer2016Approval1Controller(
		os.Stdout,
		report,
		plan,
		inputs,
		approval1,
	)
	if err != nil {
		return false, err
	}

	approval1Result, inputs, receiverPending, err :=
		resolveApproval1ReceiverActivation(
			approval1Result,
			inputs,
		)
	if err != nil {
		return false, err
	}

	fmt.Fprintln(
		os.Stdout,
		"",
	)
	if err := approval1Result.Rediscovered.WriteText(
		os.Stdout,
	); err != nil {
		return false, err
	}
	if err := approval1Result.Approval2Plan.WriteText(
		os.Stdout,
	); err != nil {
		return false, err
	}

	if !approval1Result.Approval2Required {
		return receiverPending, nil
	}

	approval2, err := install.PromptApproval2Boundary(
		os.Stdin,
		os.Stdout,
		approval1Result.Rediscovered,
		approval1Result.Approval2Plan,
	)
	if err != nil {
		return false, fmt.Errorf(
			"Approval 2 failed: %w",
			err,
		)
	}

	if !strings.EqualFold(
		approval2.BoundarySHA256,
		approval1Result.Approval2SHA256,
	) {
		return false, fmt.Errorf(
			"Approval 2 digest=%s does not match Approval 1 sealed digest=%s",
			approval2.BoundarySHA256,
			approval1Result.Approval2SHA256,
		)
	}

	_, err = install.ExecuteServer2016Approval2Controller(
		os.Stdout,
		approval1Result,
		inputs,
		approval2,
	)
	return receiverPending, err
}

func executeLocalApproval2(
	report install.Report,
	plan install.InstallPlan,
	inputs install.PlanInputs,
) (bool, error) {
	approval1Required, approval2Required :=
		install.ApprovalRequirements(
			plan,
		)

	if approval1Required {
		return false, fmt.Errorf(
			"local repair path refuses a plan containing Approval 1 AD/PKI mutations",
		)
	}

	if !approval2Required {
		return false, fmt.Errorf(
			"local repair path requires at least one Approval 2 mutation",
		)
	}

	if !install.RequiresApproval2Controller(
		plan,
	) {
		return false, fmt.Errorf(
			"plan does not require the local Approval 2 repair controller",
		)
	}

	fmt.Fprintln(
		os.Stdout,
		"",
	)
	fmt.Fprintln(
		os.Stdout,
		"Approval 1: NOT REQUIRED - authoritative discovery contains no AD/PKI mutations.",
	)

	receiverPending := false
	if install.RequiresReceiverActivation(plan) {
		selectedPending, err := resolveInstalledReceiverActivation(
			report,
		)
		if err != nil {
			return false, err
		}
		if selectedPending {
			plan, inputs, err =
				install.RebuildInstalledApproval2ForReceiverPending(
					report,
					inputs,
				)
			if err != nil {
				return false, err
			}
			receiverPending = true

			fmt.Fprintln(os.Stdout, "RECEIVER ACTIVATION RESULT: PENDING")
			fmt.Fprintln(os.Stdout, "Approval 2 has been rebuilt so the installed FISender will converge to Manual/Stopped; all other approved FI local state may converge normally.")
			if err := plan.WriteText(os.Stdout); err != nil {
				return false, err
			}
			if plan.HasBlockers() {
				return false, fmt.Errorf(
					"receiver-pending local repair plan contains blockers",
				)
			}
			if plan.HasQuestions() {
				return false, fmt.Errorf(
					"receiver-pending local repair plan contains unanswered questions",
				)
			}

			approval1Pending, approval2Pending :=
				install.ApprovalRequirements(
					plan,
				)
			if approval1Pending {
				return false, fmt.Errorf(
					"receiver-pending local repair unexpectedly requires Approval 1",
				)
			}
			if !approval2Pending {
				return true, nil
			}
			if !install.RequiresApproval2Controller(
				plan,
			) {
				return false, fmt.Errorf(
					"receiver-pending plan does not require the local Approval 2 repair controller",
				)
			}
		}
	}

	approval2, err := install.PromptApproval2Boundary(
		os.Stdin,
		os.Stdout,
		report,
		plan,
	)
	if err != nil {
		return false, fmt.Errorf(
			"Approval 2 failed: %w",
			err,
		)
	}

	_, err =
		install.ExecuteServer2016LocalApproval2Controller(
			os.Stdout,
			report,
			plan,
			inputs,
			approval2,
		)

	return receiverPending, err
}

func resolveApproval1ReceiverActivation(
	result install.Approval1ControllerResult,
	inputs install.PlanInputs,
) (install.Approval1ControllerResult, install.PlanInputs, bool, error) {
	for {
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintln(os.Stdout, "============================================================")
		fmt.Fprintln(os.Stdout, "FI WINDOWS INSTALLER - RECEIVER mTLS ACTIVATION CHECK")
		fmt.Fprintln(os.Stdout, "============================================================")
		fmt.Fprintf(os.Stdout, "Receiver: %s (%s)\n", inputs.ReceiverName, inputs.ReceiverAddress)
		fmt.Fprintln(os.Stdout, "Probe behavior: authenticated TLS handshake only; no FI payload is transmitted.")

		probe, err := install.ProbeApproval1ReceiverActivation(result, inputs)
		if err == nil {
			writeReceiverActivationPass(probe)
			return result, inputs, false, nil
		}

		fmt.Fprintf(os.Stdout, "RESULT: FAIL\nReason: %v\n", err)
		choice, choiceErr := promptReceiverActivationFailure(
			os.Stdin,
			os.Stdout,
			"Install with Receiver Pending",
		)
		if choiceErr != nil {
			return result, inputs, false, choiceErr
		}
		switch choice {
		case "abort":
			return result, inputs, false, fmt.Errorf(
				"receiver mTLS activation failed; operator selected Abort: %w",
				err,
			)
		case "retry":
			continue
		case "pending":
			pendingResult, pendingInputs, rebuildErr :=
				install.RebuildApproval2ForReceiverPending(result, inputs)
			if rebuildErr != nil {
				return result, inputs, false, rebuildErr
			}
			fmt.Fprintln(os.Stdout, "RECEIVER ACTIVATION RESULT: PENDING")
			fmt.Fprintln(os.Stdout, "Approval 2 has been re-sealed so FISender will be installed Manual/Stopped; all other approved FI local state may converge normally.")
			return pendingResult, pendingInputs, true, nil
		}
	}
}

func resolveInstalledReceiverActivation(
	report install.Report,
) (bool, error) {
	for {
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintln(os.Stdout, "============================================================")
		fmt.Fprintln(os.Stdout, "FI WINDOWS INSTALLER - RECEIVER mTLS ACTIVATION CHECK")
		fmt.Fprintln(os.Stdout, "============================================================")
		fmt.Fprintf(os.Stdout, "Receiver: %s (%s)\n", report.Config.ReceiverName, report.Config.ReceiverAddress)
		fmt.Fprintln(os.Stdout, "Probe behavior: authenticated TLS handshake only; no FI payload is transmitted.")

		probe, err := install.ProbeInstalledReceiverActivation(report)
		if err == nil {
			writeReceiverActivationPass(probe)
			return false, nil
		}

		fmt.Fprintf(os.Stdout, "RESULT: FAIL\nReason: %v\n", err)
		choice, choiceErr := promptReceiverActivationFailure(
			os.Stdin,
			os.Stdout,
			"Install/keep Receiver Pending (FISender Manual/Stopped)",
		)
		if choiceErr != nil {
			return false, choiceErr
		}
		switch choice {
		case "abort":
			return false, fmt.Errorf(
				"receiver mTLS activation failed; operator selected Abort: %w",
				err,
			)
		case "retry":
			continue
		case "pending":
			return true, nil
		}
	}
}

func promptReceiverActivationFailure(
	reader io.Reader,
	writer io.Writer,
	pendingLabel string,
) (string, error) {
	if reader == nil || writer == nil {
		return "", fmt.Errorf("receiver activation choice requires input and output")
	}
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "Receiver activation did not succeed.")
	fmt.Fprintln(writer, "[A] Abort")
	fmt.Fprintln(writer, "[R] Retry")
	fmt.Fprintf(writer, "[P] %s\n> ", pendingLabel)

	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		if scanner.Err() != nil {
			return "", fmt.Errorf("read receiver activation choice: %w", scanner.Err())
		}
		return "", fmt.Errorf("receiver activation choice was not provided")
	}
	switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
	case "a", "abort":
		return "abort", nil
	case "r", "retry":
		return "retry", nil
	case "p", "pending":
		return "pending", nil
	default:
		return "", fmt.Errorf("receiver activation choice must be A, R, or P")
	}
}

func writeReceiverActivationPass(result install.ReceiverActivationResult) {
	fmt.Fprintln(os.Stdout, "RESULT: PASS")
	fmt.Fprintf(os.Stdout, "TLS: %s / %s\n", result.TLSVersion, result.CipherSuite)
	fmt.Fprintf(os.Stdout, "Receiver certificate SHA256: %s\n", result.PeerCertificateSHA256)
	fmt.Fprintln(os.Stdout, "No FI payload was transmitted by the activation probe.")
}

func writeFinalState(receiverPending bool) {
	post := install.Discover()
	postPlan := install.BuildPlan(post)
	if receiverPending {
		var err error
		post, err = install.NormalizeReceiverPendingReport(post)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI RECEIVER-PENDING FINAL STATE INVALID: %v\n",
				err,
			)
			os.Exit(1)
		}
		postPlan, err = install.BuildReceiverPendingPlan(post)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI RECEIVER-PENDING FINAL PLAN INVALID: %v\n",
				err,
			)
			os.Exit(1)
		}
	}

	fmt.Fprintln(os.Stdout, "")
	if err := post.WriteText(os.Stdout); err != nil {
		os.Exit(2)
	}
	if err := postPlan.WriteText(os.Stdout); err != nil {
		os.Exit(2)
	}
	if post.HasFailures() ||
		postPlan.HasBlockers() ||
		postPlan.HasQuestions() ||
		planHasMutation(postPlan) {
		os.Exit(1)
	}

	if receiverPending {
		fmt.Fprintln(
			os.Stdout,
			"FI INSTALLER RESULT: PASS_WITH_RECEIVER_PENDING",
		)
		fmt.Fprintln(
			os.Stdout,
			"FISender is installed but intentionally Manual/Stopped. Correct the receiver, rerun fi-install, and the receiver activation probe must pass before FISender is enabled.",
		)
		return
	}
	fmt.Fprintln(os.Stdout, "FI INSTALLER RESULT: PASS")
}

func planHasMutation(
	plan install.InstallPlan,
) bool {
	for _, action := range plan.Actions {
		if action.Action == "CREATE" ||
			action.Action == "RECONCILE" {
			return true
		}
	}
	return false
}
