// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"reflect"
	"testing"
)

func TestPlanServicesReconcilesRunningLegacyProcessImage(
	t *testing.T,
) {
	t.Parallel()

	identities :=
		DesiredFIIdentities{
			CollectorSender: DesiredFIIdentity{
				Account: `ISS\gFI-FS19$`,
			},
			USNReader: DesiredFIIdentity{
				Account: `ISS\gFI-USN-FS19$`,
			},
			ObjReader: DesiredFIIdentity{
				Account: `ISS\gFI-OBJ-FS19$`,
			},
			CRLRefresher: DesiredFIIdentity{
				Account: `ISS\gFI-CRL-FS19$`,
			},
		}

	report :=
		Report{
			Services: []ServiceState{
				{
					Account:        identities.CollectorSender.Account,
					BinaryPath:     `"C:\Program Files\FI\fi-collector.exe" -service`,
					ManagedAccount: "true",
					Name:           "FICollector",
					Presence:       presencePresent,
					ProcessID:      3328,
					ProcessPath:    `C:\Program Files\FI\fi.exe`,
					SIDType:        "UNRESTRICTED",
					StartType:      "Automatic",
					State:          "Running",
				},
			},
		}

	var plan InstallPlan

	planServices(
		&plan,
		report,
		identities,
		nil,
		true,
	)

	for _, action := range plan.Actions {

		if action.Authority != "RUNTIME" ||
			action.Target != "FICollector" {
			continue
		}

		if action.Action !=
			planActionReconcile {

			t.Fatalf(
				"FICollector runtime action=%q want=%q detail=%q",
				action.Action,
				planActionReconcile,
				action.Detail,
			)
		}

		return
	}

	t.Fatal(
		"FICollector RUNTIME action is absent",
	)
}

func TestApproval2LegacyRuntimePathsAcceptInterruptedMigration(
	t *testing.T,
) {
	t.Parallel()

	report :=
		Report{
			Services: []ServiceState{
				{
					BinaryPath:  `"C:\Program Files\FI\fi-collector.exe" -service`,
					Name:        "FICollector",
					Presence:    presencePresent,
					ProcessID:   3328,
					ProcessPath: `C:\Program Files\FI\fi.exe`,
					State:       "Running",
				},
			},
		}

	got :=
		approval2LegacyRuntimePaths(
			report,
		)

	want :=
		[]string{
			`C:\Program Files\FI\fi.exe`,
		}

	if !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf(
			"legacy runtime paths=%v want=%v",
			got,
			want,
		)
	}
}

func TestApproval2LegacyRuntimePathsRejectConvergedNewImage(
	t *testing.T,
) {
	t.Parallel()

	report :=
		Report{
			Services: []ServiceState{
				{
					BinaryPath:  `"C:\Program Files\FI\fi-collector.exe" -service`,
					Name:        "FICollector",
					Presence:    presencePresent,
					ProcessID:   4321,
					ProcessPath: `C:\Program Files\FI\fi-collector.exe`,
					State:       "Running",
				},
			},
		}

	got :=
		approval2LegacyRuntimePaths(
			report,
		)

	if len(got) != 0 {
		t.Fatalf(
			"converged process unexpectedly authorizes legacy runtime paths=%v",
			got,
		)
	}
}

func TestSameWindowsExecutablePathIsCaseInsensitive(
	t *testing.T,
) {
	t.Parallel()

	if !sameWindowsExecutablePath(
		`C:\Program Files\FI\fi-collector.exe`,
		`c:\PROGRAM FILES\FI\FI-COLLECTOR.EXE`,
	) {
		t.Fatal(
			"Windows executable path comparison must be case-insensitive",
		)
	}
}
