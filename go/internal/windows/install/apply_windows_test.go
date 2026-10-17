// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestWritePostInstallConvergenceFailureIncludesFailedChecksAndMutations(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Checks: []Check{
			{
				Detail: "state ACL still differs",
				Name:   "FI state directory desired ACL contract",
				Status: checkFail,
			},
			{
				Detail: "informational",
				Name:   "other",
				Status: checkInfo,
			},
		},
	}
	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "ACL",
				Detail:    "state ACL still differs",
				Target:    `C:\ProgramData\FI\state`,
			},
			{
				Action:    planActionNoChange,
				Authority: "SCM",
				Target:    "FICollector",
			},
		},
	}

	var output strings.Builder
	writePostInstallConvergenceFailure(
		&output,
		report,
		plan,
	)
	text := output.String()

	if !strings.Contains(
		text,
		"FI state directory desired ACL contract",
	) {
		t.Fatal(
			"failed discovery check was not printed",
		)
	}
	if !strings.Contains(
		text,
		`C:\ProgramData\FI\state`,
	) {
		t.Fatal(
			"remaining reconcile action was not printed",
		)
	}
	if strings.Contains(
		text,
		"FICollector",
	) {
		t.Fatal(
			"NO CHANGE action was unexpectedly printed",
		)
	}
}
