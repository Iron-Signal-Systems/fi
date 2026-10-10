// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestServer2016Approval2BackendPreservesReceiverPendingAcrossInstalledRediscovery(
	t *testing.T,
) {
	t.Parallel()

	identities, err := DeriveDesiredFIIdentities(
		"ISS-FS-19",
		"ISS",
	)
	if err != nil {
		t.Fatal(err)
	}

	report := Report{
		Config: ConfigState{
			Presence: presencePresent,
		},
		Host: HostState{
			Computer: "ISS-FS-19",
		},
		Join: DomainJoinState{
			Name:   "ISS",
			Status: "domain",
		},
		Services: []ServiceState{
			{
				Account:        identities.CollectorSender.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-collector.exe" -service`,
				ManagedAccount: "true",
				Name:           "FICollector",
				Presence:       presencePresent,
				SIDType:        "UNRESTRICTED",
				StartType:      "Automatic",
				State:          "Running",
			},
			{
				Account:        identities.USNReader.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-usn-reader.exe"`,
				ManagedAccount: "true",
				Name:           "FIUSNReader",
				Presence:       presencePresent,
				SIDType:        "UNRESTRICTED",
				StartType:      "Automatic",
				State:          "Running",
			},
			{
				Account:        identities.ObjReader.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-obj-reader.exe"`,
				ManagedAccount: "true",
				Name:           "FIObjReader",
				Presence:       presencePresent,
				SIDType:        "UNRESTRICTED",
				StartType:      "Automatic",
				State:          "Running",
			},
			{
				Account:        identities.CRLRefresher.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-crl-refresher.exe"`,
				ManagedAccount: "true",
				Name:           "FICRLRefresher",
				Presence:       presencePresent,
				SIDType:        "NONE",
				StartType:      "Automatic",
				State:          "Running",
			},
			{
				Account:        identities.CollectorSender.Account,
				BinaryPath:     `"C:\Program Files\FI\fi-sender.exe"`,
				ManagedAccount: "true",
				Name:           "FISender",
				Presence:       presencePresent,
				SIDType:        "NONE",
				StartType:      "Automatic",
				State:          "Stopped",
			},
		},
	}

	backend := &server2016Approval2Backend{}
	plan := backend.BuildPlan(
		report,
		PlanInputs{
			GovernedRoots:   []string{`C:\must-not-survive-installed-rediscovery`},
			PKIChoice:       "must-not-survive",
			ReceiverAddress: "203.0.113.9:65535",
			ReceiverName:    "must-not-survive.example.invalid",
			ReceiverPending: true,
			SpoolDir:        `Z:\must-not-survive`,
			StageDir:        `C:\must-not-survive-stage`,
			StateDir:        `C:\must-not-survive-state`,
		},
		approval1PKIHandoff{},
	)

	var senderSCM *PlanAction
	var senderRuntime *PlanAction
	for index := range plan.Actions {
		action := &plan.Actions[index]
		if action.Target != "FISender" {
			continue
		}
		switch action.Authority {
		case "SCM":
			senderSCM = action
		case "RUNTIME":
			senderRuntime = action
		}
	}

	if senderSCM == nil ||
		senderSCM.Action != planActionReconcile ||
		!strings.Contains(senderSCM.Detail, "start=Manual") ||
		!strings.Contains(senderSCM.Detail, receiverPendingPlanMarker) {
		t.Fatalf(
			"installed Approval 2 rediscovery lost ReceiverPending SCM state: %+v",
			senderSCM,
		)
	}

	if senderRuntime == nil ||
		senderRuntime.Action != planActionNoChange ||
		!strings.Contains(senderRuntime.Detail, receiverPendingPlanMarker) {
		t.Fatalf(
			"installed Approval 2 rediscovery lost ReceiverPending runtime state: %+v",
			senderRuntime,
		)
	}

	observed := strings.Join(plan.Questions, "|")
	for _, action := range plan.Actions {
		observed += "|" + action.Target + "|" + action.Detail
	}
	if strings.Contains(
		strings.ToLower(observed),
		"must-not-survive",
	) {
		t.Fatalf(
			"installed Approval 2 rediscovery retained deployment input: %s",
			observed,
		)
	}
}
