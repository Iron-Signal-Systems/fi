// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestApproval2ExecutionRouteAcceptsPackageRuntimeOnlyRecovery(
	t *testing.T,
) {
	t.Parallel()

	plan :=
		InstallPlan{
			Actions: []PlanAction{
				{
					Action:    planActionReconcile,
					Authority: "RUNTIME",
					Target:    "FICollector",
					Detail:    "controlled restart after Approval 2",
				},
				{
					Action:    planActionReconcile,
					Authority: "PACKAGE",
					Target:    "installed FI executables",
					Detail:    "interrupted executable-name migration state",
				},
			},
		}

	approval1Required, approval2Required :=
		ApprovalRequirements(
			plan,
		)

	if approval1Required {
		t.Fatal(
			"PACKAGE/RUNTIME recovery unexpectedly requires Approval 1",
		)
	}

	if !approval2Required {
		t.Fatal(
			"PACKAGE/RUNTIME recovery did not require Approval 2",
		)
	}

	if !RequiresApproval2Controller(
		plan,
	) {
		t.Fatal(
			"PACKAGE/RUNTIME recovery cannot enter the Approval-2 controller",
		)
	}
}

func TestApproval2ExecutionSourceDoesNotUseLegacyRouteForControllerGuard(
	t *testing.T,
) {
	t.Parallel()

	_, current, _, ok :=
		runtime.Caller(
			0,
		)
	if !ok {
		t.Fatal(
			"resolve current source path",
		)
	}

	root :=
		filepath.Dir(
			current,
		)

	entries, err :=
		os.ReadDir(
			root,
		)
	if err != nil {
		t.Fatal(err)
	}

	const (
		staleError = "plan does not require the Server 2016 local Approval 2 repair controller"

		genericError = "plan does not require the local Approval 2 controller"
	)

	foundGenericGuard :=
		false

	for _, entry := range entries {
		if entry.IsDir() ||
			!strings.HasSuffix(
				entry.Name(),
				".go",
			) ||
			strings.HasSuffix(
				entry.Name(),
				"_test.go",
			) {
			continue
		}

		path :=
			filepath.Join(
				root,
				entry.Name(),
			)

		raw, err :=
			os.ReadFile(
				path,
			)
		if err != nil {
			t.Fatal(err)
		}

		text :=
			string(
				raw,
			)

		if strings.Contains(
			text,
			staleError,
		) {
			t.Fatalf(
				"stale Server-2016 Approval-2 execution guard remains in %s",
				entry.Name(),
			)
		}

		errorIndex :=
			strings.Index(
				text,
				genericError,
			)
		if errorIndex < 0 {
			continue
		}

		start :=
			errorIndex - 1600
		if start < 0 {
			start = 0
		}

		window :=
			text[start:errorIndex]

		if strings.Contains(
			window,
			"RequiresServer2016Approval2Controller(",
		) {
			t.Fatalf(
				"generic Approval-2 execution error is still guarded by legacy route in %s",
				entry.Name(),
			)
		}

		if !strings.Contains(
			window,
			"RequiresApproval2Controller(",
		) {
			t.Fatalf(
				"generic Approval-2 execution error has no generic routing predicate in %s",
				entry.Name(),
			)
		}

		foundGenericGuard =
			true
	}

	if !foundGenericGuard {
		t.Fatal(
			"generic Approval-2 controller execution guard was not found",
		)
	}
}
