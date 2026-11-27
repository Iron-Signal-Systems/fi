// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestValidateProposedConfigPathsRejectsSystemVolumeRootSpool(
	t *testing.T,
) {
	t.Setenv(
		"SystemDrive",
		"C:",
	)

	err := validateProposedConfigPaths(
		ConfigState{
			GovernedRoots: []string{
				`C:\FI-Governed-Test`,
			},
			Path:     `C:\ProgramData\FI\config\fi.conf`,
			SpoolDir: `C:\`,
			StageDir: `C:\ProgramData\FI\transport-v2-drain\stage`,
			StateDir: `C:\ProgramData\FI\state`,
		},
	)

	if err == nil {
		t.Fatal(
			"system-volume root spool unexpectedly accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"must not be the Windows system-volume root",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestValidateProposedConfigPathsAllowsDedicatedSystemVolumeSpool(
	t *testing.T,
) {
	t.Setenv(
		"SystemDrive",
		"C:",
	)

	err := validateProposedConfigPaths(
		ConfigState{
			GovernedRoots: []string{
				`C:\FI-Governed-Test`,
			},
			Path:     `C:\ProgramData\FI\config\fi.conf`,
			SpoolDir: `C:\ProgramData\FI\spool`,
			StageDir: `C:\ProgramData\FI\transport-v2-drain\stage`,
			StateDir: `C:\ProgramData\FI\state`,
		},
	)

	if err != nil {
		t.Fatalf(
			"dedicated spool unexpectedly rejected: %v",
			err,
		)
	}
}
