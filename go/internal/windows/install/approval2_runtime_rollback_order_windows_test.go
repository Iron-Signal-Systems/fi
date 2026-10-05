// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"strings"
	"testing"
)

func TestApproval2RuntimeSnapshotFromReportPreservesStablePreState(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Services: []ServiceState{
			{
				Name:     "FICollector",
				Presence: presencePresent,
				State:    "Running",
			},
			{
				Name:     "FISender",
				Presence: presencePresent,
				State:    "Stopped",
			},
			{
				Name:     "FICRLRefresher",
				Presence: presenceAbsent,
				State:    notKnown,
			},
		},
	}

	snapshots, err :=
		approval2RuntimeSnapshotFromReport(
			report,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(snapshots) != 2 {
		t.Fatalf(
			"snapshot count=%d want=2",
			len(snapshots),
		)
	}

	if snapshots[0].Name != "FICollector" ||
		!snapshots[0].WasRunning {
		t.Fatalf(
			"collector snapshot=%+v want Running",
			snapshots[0],
		)
	}

	if snapshots[1].Name != "FISender" ||
		snapshots[1].WasRunning {
		t.Fatalf(
			"sender snapshot=%+v want Stopped",
			snapshots[1],
		)
	}
}

func TestApproval2RuntimeSnapshotRejectsTransientState(
	t *testing.T,
) {
	t.Parallel()

	_, err :=
		approval2RuntimeSnapshotFromReport(
			Report{
				Services: []ServiceState{
					{
						Name:     "FISender",
						Presence: presencePresent,
						State:    "StartPending",
					},
				},
			},
		)

	if err == nil {
		t.Fatal(
			"transient service state unexpectedly accepted as rollback snapshot",
		)
	}
}

func TestApproval2RuntimeSnapshotRejectsDuplicateService(
	t *testing.T,
) {
	t.Parallel()

	_, err :=
		approval2RuntimeSnapshotFromReport(
			Report{
				Services: []ServiceState{
					{
						Name:     "FISender",
						Presence: presencePresent,
						State:    "Running",
					},
					{
						Name:     "fisender",
						Presence: presencePresent,
						State:    "Running",
					},
				},
			},
		)

	if err == nil {
		t.Fatal(
			"duplicate service unexpectedly accepted in rollback snapshot",
		)
	}
}

func TestApproval2RollbackRestoresRuntimeAfterPersistentState(
	t *testing.T,
) {
	t.Parallel()

	events := make(
		[]string,
		0,
		3,
	)

	record := func(
		name string,
		err error,
	) func() error {
		return func() error {
			events = append(
				events,
				name,
			)

			return err
		}
	}

	found :=
		rollbackApproval2ControllerSteps(
			[]approval2ControllerStep{
				{
					name: "CONFIG transport trust",
					rollback: record(
						"rollback:config",
						nil,
					),
				},
				{
					name: "PACKAGE",
					rollback: record(
						"rollback:package",
						errors.New(
							"synthetic persistent rollback error",
						),
					),
				},
			},
			record(
				"restore:runtime",
				nil,
			),
		)

	wantEvents :=
		"rollback:package|" +
			"rollback:config|" +
			"restore:runtime"

	if strings.Join(
		events,
		"|",
	) != wantEvents {
		t.Fatalf(
			"rollback events=%v want=%s",
			events,
			wantEvents,
		)
	}

	if len(found) != 1 ||
		!strings.Contains(
			found[0],
			"PACKAGE: synthetic persistent rollback error",
		) {
		t.Fatalf(
			"rollback errors=%v",
			found,
		)
	}
}

func TestApproval2RollbackReportsFinalRuntimeRestoreFailure(
	t *testing.T,
) {
	t.Parallel()

	found :=
		rollbackApproval2ControllerSteps(
			nil,
			func() error {
				return errors.New(
					"synthetic runtime restoration failure",
				)
			},
		)

	if len(found) != 1 ||
		!strings.Contains(
			found[0],
			"RUNTIME SNAPSHOT: synthetic runtime restoration failure",
		) {
		t.Fatalf(
			"rollback errors=%v",
			found,
		)
	}
}
