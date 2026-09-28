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
		"apply the exact validated Server 2016 desired-state plan after explicit approval",
	)

	receiverAddress := flag.String(
		"receiver-address",
		"",
		"read-only new-install planning input: FI receiver address",
	)
	receiverName := flag.String(
		"receiver-name",
		"",
		"read-only new-install planning input: FI receiver DNS/name",
	)
	spoolDir := flag.String(
		"spool-dir",
		"",
		"read-only new-install planning input: FI spool directory",
	)
	stageDir := flag.String(
		"stage-dir",
		"",
		"read-only new-install planning input: FI stage directory; defaults to C:\\ProgramData\\FI\\transport-v2-drain\\stage",
	)
	stateDir := flag.String(
		"state-dir",
		"",
		"read-only new-install planning input: FI state directory; defaults to C:\\ProgramData\\FI\\state",
	)
	pkiChoice := flag.String(
		"pki-choice",
		"",
		"read-only new-install planning input: reuse, enroll, or create",
	)

	var governedRoots repeatedStringFlag
	flag.Var(
		&governedRoots,
		"governed-root",
		"read-only new-install planning input: governed root; repeat for multiple roots",
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
		fmt.Fprintln(
			os.Stderr,
			"\nFI APPLY BLOCKED: M19 new-install deployment inputs are planning-only; AD/PKI/config/SCM first-install mutation authority is not enabled",
		)
		os.Exit(1)
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

	post := install.Discover()
	postPlan := install.BuildPlan(post)
	fmt.Fprintln(os.Stdout, "")
	if err := post.WriteText(os.Stdout); err != nil {
		os.Exit(2)
	}
	if err := postPlan.WriteText(os.Stdout); err != nil {
		os.Exit(2)
	}
	if post.HasFailures() || postPlan.HasBlockers() {
		os.Exit(1)
	}
}
