// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentConfigFileProposalNormalizesExactInstallerContract(t *testing.T) {
	report := deploymentConfigTestReport()
	inputs := deploymentConfigTestInputs()

	manual, err := BuildManualDeploymentConfigProposal(report, inputs)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "fi.conf")
	if err := os.WriteFile(path, manual.Normalized, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadDeploymentConfigProposal(report, path)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.SourceMode != deploymentConfigSourceFile {
		t.Fatalf("source mode=%q", loaded.SourceMode)
	}
	if !strings.EqualFold(loaded.NormalizedSHA256, manual.NormalizedSHA256) {
		t.Fatalf("normalized hash=%s want=%s", loaded.NormalizedSHA256, manual.NormalizedSHA256)
	}
	if string(loaded.Normalized) != string(manual.Normalized) {
		t.Fatalf("normalized config differs:\n%s\nwant:\n%s", loaded.Normalized, manual.Normalized)
	}
	if loaded.Inputs.ReceiverAddress != inputs.ReceiverAddress ||
		loaded.Inputs.ReceiverName != inputs.ReceiverName ||
		loaded.Inputs.SpoolDir != inputs.SpoolDir ||
		loaded.Inputs.StageDir != inputs.StageDir ||
		loaded.Inputs.StateDir != inputs.StateDir {
		t.Fatalf("loaded inputs=%+v want=%+v", loaded.Inputs, inputs)
	}
}

func TestDeploymentConfigFileRejectsUnsupportedFixedValue(t *testing.T) {
	report := deploymentConfigTestReport()
	inputs := deploymentConfigTestInputs()

	manual, err := BuildManualDeploymentConfigProposal(report, inputs)
	if err != nil {
		t.Fatal(err)
	}

	mutated := strings.Replace(
		string(manual.Normalized),
		"sender.poll_interval = 5s",
		"sender.poll_interval = 6s",
		1,
	)
	path := filepath.Join(t.TempDir(), "fi.conf")
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadDeploymentConfigProposal(report, path)
	if err == nil {
		t.Fatal("unsupported fixed config unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "exact supported FI 1.1 operational contract") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeploymentConfigFileRejectsWrongSourceIdentity(t *testing.T) {
	report := deploymentConfigTestReport()
	inputs := deploymentConfigTestInputs()

	manual, err := BuildManualDeploymentConfigProposal(report, inputs)
	if err != nil {
		t.Fatal(err)
	}

	mutated := strings.Replace(
		string(manual.Normalized),
		"source.id = iss-fs-19.iss.local",
		"source.id = wrong-host.iss.local",
		1,
	)
	path := filepath.Join(t.TempDir(), "fi.conf")
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = LoadDeploymentConfigProposal(report, path)
	if err == nil {
		t.Fatal("wrong source identity unexpectedly accepted")
	}
}

func TestDeploymentConfigApprovalRequiresExactDigestToken(t *testing.T) {
	proposal, err := BuildManualDeploymentConfigProposal(
		deploymentConfigTestReport(),
		deploymentConfigTestInputs(),
	)
	if err != nil {
		t.Fatal(err)
	}

	token := "APPROVE-CONFIG " + strings.ToUpper(proposal.DigestSHA256[:16]) + "\n"
	var output strings.Builder
	approval, err := PromptDeploymentConfigApproval(
		strings.NewReader(token),
		&output,
		proposal,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !approval.Given || !strings.EqualFold(approval.DigestSHA256, proposal.DigestSHA256) {
		t.Fatalf("approval=%+v proposal=%+v", approval, proposal)
	}
	if !strings.Contains(output.String(), "BEGIN EXACT NORMALIZED FI CONFIGURATION TO INSTALL") {
		t.Fatalf("approval output missing exact config:\n%s", output.String())
	}
}

func TestDeploymentConfigApprovalRejectsWrongToken(t *testing.T) {
	proposal, err := BuildManualDeploymentConfigProposal(
		deploymentConfigTestReport(),
		deploymentConfigTestInputs(),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = PromptDeploymentConfigApproval(
		strings.NewReader("APPROVE-CONFIG WRONG\n"),
		&strings.Builder{},
		proposal,
	)
	if err == nil {
		t.Fatal("wrong approval token unexpectedly accepted")
	}
}

func deploymentConfigTestInputs() PlanInputs {
	return PlanInputs{
		GovernedRoots:   []string{`C:\FI-Governed-Test`},
		ReceiverAddress: "192.168.1.219:8443",
		ReceiverName:    "fi-receiver-b.iss.local",
		SpoolDir:        `C:\ProgramData\FI\spool`,
		StageDir:        `C:\ProgramData\FI\transport-v2-drain\stage`,
		StateDir:        `C:\ProgramData\FI\state`,
	}
}

func deploymentConfigTestReport() Report {
	return Report{
		Config: ConfigState{
			Path:     `C:\ProgramData\FI\config\fi.conf`,
			Presence: presenceAbsent,
		},
		Host: HostState{
			Computer:  "ISS-FS-19",
			DomainDNS: "iss.local",
		},
	}
}
