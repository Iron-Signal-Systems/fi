// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	prerequisiteApproval = "APPROVAL"
	prerequisiteFail     = "FAIL"
	prerequisitePass     = "PASS"
)

type PrerequisiteCheck struct {
	Detail string
	Name   string
	Status string
}

type PrerequisiteReport struct {
	Checks []PrerequisiteCheck
}

func (report *PrerequisiteReport) add(
	status string,
	name string,
	detail string,
) {
	report.Checks = append(
		report.Checks,
		PrerequisiteCheck{
			Detail: detail,
			Name:   name,
			Status: status,
		},
	)
}

func (report PrerequisiteReport) HasFailures() bool {
	for _, check := range report.Checks {
		if check.Status == prerequisiteFail {
			return true
		}
	}
	return false
}

func (report PrerequisiteReport) HasApprovals() bool {
	for _, check := range report.Checks {
		if check.Status == prerequisiteApproval {
			return true
		}
	}
	return false
}

func (report PrerequisiteReport) WriteText(
	writer io.Writer,
) error {
	if writer == nil {
		return fmt.Errorf(
			"prerequisite output writer is required",
		)
	}

	if _, err := fmt.Fprintln(
		writer,
		"",
		"============================================================",
		"FI WINDOWS INSTALLER - PREREQUISITE CHECK",
		"============================================================",
	); err != nil {
		return err
	}

	for _, check := range report.Checks {
		if _, err := fmt.Fprintf(
			writer,
			"%-5s %-34s %s\n",
			check.Status,
			check.Name,
			check.Detail,
		); err != nil {
			return err
		}
	}

	result := "PASS"
	if report.HasFailures() {
		result = "BLOCKED"
	} else if report.HasApprovals() {
		result = "APPROVAL REQUIRED"
	}

	_, err := fmt.Fprintf(
		writer,
		"\nFI INSTALLER PREREQUISITE RESULT: %s\n",
		result,
	)
	if err != nil {
		return err
	}

	if report.HasFailures() {
		_, err = fmt.Fprintln(
			writer,
			"No FI host, AD, PKI, service, ACL, configuration, or package mutation was performed.",
		)
		return err
	}

	if report.HasApprovals() {
		_, err = fmt.Fprintln(
			writer,
			"A shared-infrastructure change requires a separate explicit approval before FI asks for deployment input.",
		)
		return err
	}

	_, err = fmt.Fprintln(
		writer,
		"Prerequisites are satisfied for the currently enabled installer mutation profile.",
	)
	return err
}

func EvaluateEnvironmentPrerequisites(
	report Report,
) PrerequisiteReport {
	var result PrerequisiteReport

	prerequisiteFromDiscoveryCheck(
		&result,
		report,
		"administrator session",
		"Administrator session",
	)
	prerequisiteFromDiscoveryCheck(
		&result,
		report,
		"Windows profile",
		"Windows release profile",
	)
	prerequisiteFromDiscoveryCheck(
		&result,
		report,
		"Windows domain join",
		"Domain membership",
	)
	prerequisiteFromDiscoveryCheck(
		&result,
		report,
		"Active Directory LDAP bind",
		"Active Directory LDAP",
	)
	prerequisiteFromDiscoveryCheck(
		&result,
		report,
		"Active Directory computer object",
		"AD computer object",
	)

	prerequisiteMutationProfile(
		&result,
		report,
	)
	prerequisiteKDS(
		&result,
		report,
	)
	prerequisiteReleaseTrust(
		&result,
		report,
	)
	prerequisitePKIEnvironment(
		&result,
		report,
	)

	return result
}

func EvaluateInputPrerequisites(
	report Report,
	inputs PlanInputs,
) PrerequisiteReport {
	var result PrerequisiteReport

	prerequisitePaths(
		&result,
		report,
		inputs,
	)
	prerequisitePKIInput(
		&result,
		report,
		inputs,
	)

	return result
}

func EvaluatePrerequisites(
	report Report,
	inputs PlanInputs,
) PrerequisiteReport {
	result := EvaluateEnvironmentPrerequisites(
		report,
	)
	inputResult := EvaluateInputPrerequisites(
		report,
		inputs,
	)
	result.Checks = append(
		result.Checks,
		inputResult.Checks...,
	)
	return result
}

func prerequisiteFromDiscoveryCheck(
	result *PrerequisiteReport,
	report Report,
	checkName string,
	outputName string,
) {
	check, found := findCheck(
		report,
		checkName,
	)
	if !found {
		result.add(
			prerequisiteFail,
			outputName,
			"authoritative discovery check is unavailable",
		)
		return
	}

	if check.Status != checkPass {
		result.add(
			prerequisiteFail,
			outputName,
			check.Detail,
		)
		return
	}

	result.add(
		prerequisitePass,
		outputName,
		check.Detail,
	)
}

func prerequisiteMutationProfile(
	result *PrerequisiteReport,
	report Report,
) {
	if !installerMutationSupportedBuild(
		report.Host.BuildNumber,
	) {
		result.add(
			prerequisiteFail,
			"Installer mutation profile",
			fmt.Sprintf(
				"Windows build %d is not enabled for FI installer mutation",
				report.Host.BuildNumber,
			),
		)
		return
	}

	if !objReaderRightsMutationEnabledBuild(
		report.Host.BuildNumber,
	) {
		result.add(
			prerequisiteFail,
			"FIObjReader release acceptance",
			fmt.Sprintf(
				"%s build %d has not completed FIObjReader mutation acceptance; no Approval 1 mutation is allowed",
				report.Host.Profile.Name,
				report.Host.BuildNumber,
			),
		)
		return
	}

	result.add(
		prerequisitePass,
		"Installer mutation profile",
		fmt.Sprintf(
			"%s exact build %d is enabled for the current FI installer mutation contract",
			report.Host.Profile.Name,
			report.Host.BuildNumber,
		),
	)
}

func prerequisiteKDS(
	result *PrerequisiteReport,
	report Report,
) {
	if !report.AD.KDSRootKeyKnown {
		result.add(
			prerequisiteFail,
			"KDS root key",
			"KDS root-key state is not authoritative",
		)
		return
	}

	if report.AD.KDSRootKeyCount == 0 {
		result.add(
			prerequisiteFail,
			"KDS root key",
			"no KDS root key is available; the current native installer does not create a production KDS root key automatically",
		)
		return
	}

	result.add(
		prerequisitePass,
		"KDS root key",
		fmt.Sprintf(
			"root_key_objects=%d",
			report.AD.KDSRootKeyCount,
		),
	)
}

func prerequisiteReleaseTrust(
	result *PrerequisiteReport,
	report Report,
) {
	names := []struct {
		discovery string
		output    string
	}{
		{
			discovery: "ISS release-policy authority pin",
			output:    "ISS release-policy authority",
		},
		{
			discovery: "package FI release-trust policy",
			output:    "FI release-trust policy",
		},
		{
			discovery: "FI installer Authenticode signer authorization",
			output:    "Installer signer authorization",
		},
		{
			discovery: "FI release manifest signer authorization",
			output:    "Manifest signer authorization",
		},
	}

	for _, name := range names {
		prerequisiteFromDiscoveryCheck(
			result,
			report,
			name.discovery,
			name.output,
		)
	}
}

func prerequisitePaths(
	result *PrerequisiteReport,
	report Report,
	inputs PlanInputs,
) {
	governedRoots := append(
		[]string(nil),
		inputs.GovernedRoots...,
	)
	if len(governedRoots) == 0 &&
		report.Config.Presence == presencePresent {
		governedRoots = append(
			[]string(nil),
			report.Config.GovernedRoots...,
		)
	}

	if err := ValidateGovernedRootsForInstall(
		governedRoots,
	); err != nil {
		result.add(
			prerequisiteFail,
			"Governed roots",
			err.Error(),
		)
	} else {
		result.add(
			prerequisitePass,
			"Governed roots",
			fmt.Sprintf(
				"%d operator-owned governed root(s) exist",
				len(governedRoots),
			),
		)
	}

	spool := strings.TrimSpace(
		inputs.SpoolDir,
	)
	if spool == "" &&
		report.Config.Presence == presencePresent {
		spool = strings.TrimSpace(
			report.Config.SpoolDir,
		)
	}
	if spool == "" {
		result.add(
			prerequisiteFail,
			"FI spool directory",
			"spool directory is required for a new installation",
		)
		return
	}

	if !filepath.IsAbs(spool) {
		result.add(
			prerequisiteFail,
			"FI spool directory",
			fmt.Sprintf(
				"spool directory must be an absolute Windows path: %q",
				spool,
			),
		)
		return
	}

	systemDrive := strings.TrimSpace(
		os.Getenv(
			"SystemDrive",
		),
	)
	if systemDrive != "" &&
		strings.EqualFold(
			filepath.Clean(spool),
			filepath.Clean(systemDrive+`\`),
		) {
		result.add(
			prerequisiteFail,
			"FI spool directory",
			fmt.Sprintf(
				"FI spool directory must not be the Windows system-volume root %q",
				spool,
			),
		)
		return
	}

	result.add(
		prerequisitePass,
		"FI spool directory",
		spool,
	)
}
