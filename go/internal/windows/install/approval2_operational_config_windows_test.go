// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

func TestApproval2OperationalConfigProposalUsesTypedInputsNotActionDetail(
	t *testing.T,
) {
	report, plan, inputs, want := approval2OperationalConfigContractState(t)

	for index := range plan.Actions {
		if plan.Actions[index].Authority == "CONFIG" {
			plan.Actions[index].Detail = "opaque digest-bound human-readable detail"
		}
	}

	got, err := approval2OperationalConfigProposal(report, plan, inputs)
	if err != nil {
		t.Fatal(err)
	}

	if got.SourceID != want.SourceID ||
		got.ReceiverAddress != want.ReceiverAddress ||
		got.ReceiverName != want.ReceiverName ||
		got.SpoolDir != want.SpoolDir ||
		got.StageDir != want.StageDir ||
		got.StateDir != want.StateDir {
		t.Fatalf("typed proposal=%+v want=%+v", got, want)
	}

	if len(got.GovernedRoots) != len(want.GovernedRoots) {
		t.Fatalf("governed roots=%v want=%v", got.GovernedRoots, want.GovernedRoots)
	}
	for index := range got.GovernedRoots {
		if got.GovernedRoots[index] != want.GovernedRoots[index] {
			t.Fatalf("governed roots=%v want=%v", got.GovernedRoots, want.GovernedRoots)
		}
	}
}

func TestApproval2OperationalConfigRenderRoundTripsExactVersion11Contract(
	t *testing.T,
) {
	_, _, _, proposal := approval2OperationalConfigContractState(t)

	value, err := approval2OperationalConfigValue(proposal)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := renderApproval2OperationalConfig(value)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := config.Parse(strings.NewReader(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if !sameApproval2OperationalConfig(parsed, value) {
		t.Fatalf("rendered config=%+v want=%+v", parsed, value)
	}

	for _, expected := range []string{
		"version_id: 1.1",
		"collector.collection_every = 1m0s",
		"spool.target_batch_bytes = 33554432",
		"sender.generation_max_encoded_bytes = 68719476736",
		"sender.recovery_threshold_bytes = 0",
		"receiver.timeout = 30s",
		"troubleshoot.enabled = false",
	} {
		if !strings.Contains(string(encoded), expected) {
			t.Fatalf("generated config does not contain %q:\n%s", expected, string(encoded))
		}
	}
}

func TestApproval2OperationalConfigRequiresExactPlanActions(
	t *testing.T,
) {
	report, plan, inputs, _ := approval2OperationalConfigContractState(t)

	filtered := make([]PlanAction, 0, len(plan.Actions))
	for _, action := range plan.Actions {
		if action.Authority == "CONFIG" &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(action.Target)), "source.id=") {
			continue
		}
		filtered = append(filtered, action)
	}
	plan.Actions = filtered

	_, err := approval2OperationalConfigProposal(report, plan, inputs)
	if err == nil {
		t.Fatal("operational config without source.id plan action unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "exactly one config CREATE and one source.id CREATE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApproval2OperationalConfigRejectsLineBreakInjection(
	t *testing.T,
) {
	_, _, _, proposal := approval2OperationalConfigContractState(t)
	proposal.ReceiverName = "receiver.iss.local\nsource.id = attacker"

	_, err := approval2OperationalConfigValue(proposal)
	if err == nil {
		t.Fatal("line-break injection unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "contains a line break") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func approval2OperationalConfigContractState(
	t *testing.T,
) (Report, InstallPlan, PlanInputs, ConfigState) {
	t.Helper()

	report := Report{
		Config: ConfigState{
			Path:     `C:\ProgramData\FI\config\fi.conf`,
			Presence: presenceAbsent,
		},
		Host: HostState{
			Computer:  "AdminBox",
			DomainDNS: "iss.local",
		},
	}

	inputs := PlanInputs{
		GovernedRoots: []string{
			`C:\Data\DepartmentA`,
			`D:\SharedData`,
		},
		ReceiverAddress: "192.168.1.119:8443",
		ReceiverName:    "fi-receiver-a.iss.local",
		SpoolDir:        `D:\FI\spool`,
		StageDir:        filepath.Clean(`C:\ProgramData\FI\transport-v2-drain\stage`),
		StateDir:        filepath.Clean(`C:\ProgramData\FI\state`),
	}

	working := report
	var plan InstallPlan
	planConfiguration(&plan, &working, inputs)
	if plan.HasBlockers() || plan.HasQuestions() {
		t.Fatalf("test plan not ready: actions=%+v questions=%v", plan.Actions, plan.Questions)
	}

	return report, plan, inputs, working.Config
}
