// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"flag"
	"fmt"
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
		false,
		"apply the exact validated Server 2016 desired-state plan after explicit approval boundaries",
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

	inputs := install.PlanInputs{
		GovernedRoots:   append([]string(nil), governedRoots...),
		PKIChoice:       strings.TrimSpace(*pkiChoice),
		ReceiverAddress: strings.TrimSpace(*receiverAddress),
		ReceiverName:    strings.TrimSpace(*receiverName),
		SpoolDir:        strings.TrimSpace(*spoolDir),
		StageDir:        strings.TrimSpace(*stageDir),
		StateDir:        strings.TrimSpace(*stateDir),
	}

	if err := install.ValidateGovernedRootsForInstall(
		inputs.GovernedRoots,
	); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"`nFI INSTALLER INPUT BLOCKED: %v`n",
			err,
		)
		os.Exit(1)
	}

	report := install.Discover()
	plan := install.BuildPlanWithInputs(
		report,
		inputs,
	)

	if err := report.WriteText(os.Stdout); err != nil {
		os.Exit(2)
	}
	if err := plan.WriteText(os.Stdout); err != nil {
		os.Exit(2)
	}
	if plan.HasBlockers() {
		os.Exit(1)
	}

	if !*apply {
		if report.HasFailures() {
			os.Exit(1)
		}
		return
	}

	if plan.Mode == "NEW INSTALL" ||
		!inputs.Empty() {
		if err := executeNewInstall(
			report,
			plan,
			inputs,
		); err != nil {
			fmt.Fprintf(
				os.Stderr,
				"\nFI NEW INSTALL FAILED: %v\n",
				err,
			)
			os.Exit(1)
		}
		writeFinalState()
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

	writeFinalState()
}

func executeNewInstall(
	report install.Report,
	plan install.InstallPlan,
	inputs install.PlanInputs,
) error {
	approval1Required, _ := install.ApprovalRequirements(
		plan,
	)
	if !approval1Required {
		return fmt.Errorf(
			"new-install plan does not contain an Approval 1 AD/PKI boundary",
		)
	}

	approval1, err := install.PromptApproval1Boundary(
		os.Stdin,
		os.Stdout,
		report,
		plan,
	)
	if err != nil {
		return fmt.Errorf(
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
		return err
	}

	fmt.Fprintln(
		os.Stdout,
		"",
	)
	if err := approval1Result.Rediscovered.WriteText(
		os.Stdout,
	); err != nil {
		return err
	}
	if err := approval1Result.Approval2Plan.WriteText(
		os.Stdout,
	); err != nil {
		return err
	}

	if !approval1Result.Approval2Required {
		return nil
	}

	approval2, err := install.PromptApproval2Boundary(
		os.Stdin,
		os.Stdout,
		approval1Result.Rediscovered,
		approval1Result.Approval2Plan,
	)
	if err != nil {
		return fmt.Errorf(
			"Approval 2 failed: %w",
			err,
		)
	}

	if !strings.EqualFold(
		approval2.BoundarySHA256,
		approval1Result.Approval2SHA256,
	) {
		return fmt.Errorf(
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
	return err
}

func writeFinalState() {
	post := install.Discover()
	postPlan := install.BuildPlan(post)
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
