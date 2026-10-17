// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/install"
)

func TestValidateApplyPKIChoice(
	t *testing.T,
) {
	tests := []struct {
		choice  string
		wantErr bool
	}{
		{
			choice: "",
		},
		{
			choice: "enroll",
		},
		{
			choice: "ENROLL",
		},
		{
			choice:  "reuse",
			wantErr: true,
		},
		{
			choice:  "create",
			wantErr: true,
		},
		{
			choice:  "bogus",
			wantErr: true,
		},
	}

	for _, test := range tests {
		err :=
			validateApplyPKIChoice(
				test.choice,
			)

		if test.wantErr &&
			err == nil {
			t.Fatalf(
				"choice=%q unexpectedly accepted",
				test.choice,
			)
		}

		if !test.wantErr &&
			err != nil {
			t.Fatalf(
				"choice=%q unexpectedly rejected: %v",
				test.choice,
				err,
			)
		}
	}
}

func TestPlanOnlyDiscoveryFailuresCovered(t *testing.T) {
	identities, err := install.DeriveDesiredFIIdentities(
		"iss-fs-2022",
		"ISS",
	)
	if err != nil {
		t.Fatal(err)
	}

	report := install.Report{
		Checks: []install.Check{
			{
				Name:   "FICollector/FISender direct Event Log Readers membership",
				Status: "FAIL",
				Detail: "direct_member=false expected=true",
			},
			{
				Name:   "FIUSNReader direct local Administrator membership",
				Status: "FAIL",
				Detail: "direct_member=false expected=true",
			},
			{
				Name:   "FICollector/FISender service-logon right",
				Status: "FAIL",
				Detail: "SeServiceLogonRight is missing",
			},
			{
				Name:   "FIUSNReader service-logon right",
				Status: "FAIL",
				Detail: "SeServiceLogonRight is missing",
			},
			{
				Name:   "FIObjReader release-specific rights contract",
				Status: "FAIL",
				Detail: "missing SeBackupPrivilege; missing SeSecurityPrivilege; missing SeServiceLogonRight",
			},
		},
	}

	plan := install.InstallPlan{
		Identities: identities,
		Actions: []install.PlanAction{
			{
				Action:    "RECONCILE",
				Authority: "GROUPS",
				Target:    identities.CollectorSender.Account + " -> Event Log Readers",
			},
			{
				Action:    "RECONCILE",
				Authority: "GROUPS",
				Target:    identities.USNReader.Account + " -> Administrators",
			},
			{
				Action:    "RECONCILE",
				Authority: "RIGHTS",
				Target:    identities.CollectorSender.Account,
			},
			{
				Action:    "RECONCILE",
				Authority: "RIGHTS",
				Target:    identities.USNReader.Account,
			},
			{
				Action:    "RECONCILE",
				Authority: "RIGHTS",
				Target:    identities.ObjReader.Account,
			},
		},
	}

	if !planOnlyDiscoveryFailuresCovered(report, plan) {
		t.Fatal("planned new-install security reconciliation was rejected")
	}

	unexpected := report
	unexpected.Checks = append(
		append([]install.Check(nil), report.Checks...),
		install.Check{
			Name:   "FI installer Authenticode trust",
			Status: "FAIL",
			Detail: "invalid signature",
		},
	)
	if planOnlyDiscoveryFailuresCovered(unexpected, plan) {
		t.Fatal("unexpected discovery failure was accepted")
	}

	missingAction := plan
	missingAction.Actions = append(
		[]install.PlanAction(nil),
		plan.Actions[:len(plan.Actions)-1]...,
	)
	if planOnlyDiscoveryFailuresCovered(report, missingAction) {
		t.Fatal("unplanned security discrepancy was accepted")
	}

	unknown := report
	unknown.Checks = append([]install.Check(nil), report.Checks...)
	unknown.Checks[0].Detail = "discovery unavailable"

	if planOnlyDiscoveryFailuresCovered(unknown, plan) {
		t.Fatal("unknown membership state was accepted")
	}

	incomplete := plan
	incomplete.Questions = []string{"missing required input"}

	if planOnlyDiscoveryFailuresCovered(report, incomplete) {
		t.Fatal("incomplete plan was accepted")
	}
}
