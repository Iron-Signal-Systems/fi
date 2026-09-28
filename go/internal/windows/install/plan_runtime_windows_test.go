// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestPlanServicesSeparatesConfigurationFromStoppedRuntime(
	t *testing.T,
) {
	t.Parallel()

	identities := DesiredFIIdentities{
		CollectorSender: DesiredFIIdentity{
			Account: `ISS\gFI-FS01$`,
		},
		USNReader: DesiredFIIdentity{
			Account: `ISS\gFI-USN-FS01$`,
		},
		ObjReader: DesiredFIIdentity{
			Account: `ISS\gFI-OBJ-FS01$`,
		},
	}
	report := Report{
		Services: []ServiceState{
			{
				Account:        `ISS\gFI-FS01$`,
				BinaryPath:     `"C:\Program Files\FI\fi.exe" -service`,
				ManagedAccount: "true",
				Name:           "FICollector",
				SIDType:        "UNRESTRICTED",
				StartType:      "Automatic",
				State:          "Stopped",
			},
		},
	}
	plan := InstallPlan{}

	planServices(
		&plan,
		report,
		identities,
		nil,
	)

	var collectorSCM string
	var collectorRuntime string
	for _, action := range plan.Actions {
		if action.Target != "FICollector" {
			continue
		}
		switch action.Authority {
		case "SCM":
			collectorSCM = action.Action
		case "RUNTIME":
			collectorRuntime = action.Action
		}
	}

	if collectorSCM != planActionNoChange {
		t.Fatalf(
			"FICollector SCM action=%q want=%q",
			collectorSCM,
			planActionNoChange,
		)
	}
	if collectorRuntime != planActionReconcile {
		t.Fatalf(
			"FICollector runtime action=%q want=%q",
			collectorRuntime,
			planActionReconcile,
		)
	}
}
