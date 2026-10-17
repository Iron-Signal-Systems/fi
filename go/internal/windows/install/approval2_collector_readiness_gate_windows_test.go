// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestApproval2CollectorRuntimeReadinessRequired(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		actions []PlanAction
		want    bool
	}{
		{
			name: "sender-only activation",
			actions: []PlanAction{
				{Action: planActionReconcile, Authority: "SCM", Target: "FISender"},
				{Action: planActionReconcile, Authority: "RUNTIME", Target: "FISender"},
			},
			want: false,
		},
		{
			name: "new collector",
			actions: []PlanAction{
				{Action: planActionCreate, Authority: "SCM", Target: "FICollector"},
			},
			want: true,
		},
		{
			name: "existing collector SCM adjustment only",
			actions: []PlanAction{
				{Action: planActionReconcile, Authority: "SCM", Target: "FICollector"},
			},
			want: false,
		},
		{
			name: "collector runtime reconciliation",
			actions: []PlanAction{
				{Action: planActionReconcile, Authority: "RUNTIME", Target: "FICollector"},
			},
			want: true,
		},
		{
			name: "package replacement restarts collector",
			actions: []PlanAction{
				{Action: planActionReconcile, Authority: "PACKAGE", Target: "installed FI executables"},
			},
			want: true,
		},
		{
			name: "no change collector",
			actions: []PlanAction{
				{Action: planActionNoChange, Authority: "RUNTIME", Target: "FICollector"},
			},
			want: false,
		},
		{
			name: "unrelated ACL",
			actions: []PlanAction{
				{Action: planActionReconcile, Authority: "ACL", Target: `C:\ProgramData\FI\state`},
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := InstallPlan{Actions: tc.actions}
			got := approval2CollectorRuntimeReadinessRequired(plan)
			if got != tc.want {
				t.Fatalf("collector readiness required=%v, want %v", got, tc.want)
			}
			if tc.name == "sender-only activation" &&
				!approval2ServiceStabilityRequired(plan) {
				t.Fatal("sender-only activation must retain service stability check")
			}
		})
	}
}
