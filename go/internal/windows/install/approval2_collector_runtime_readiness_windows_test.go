// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectApproval2CollectorRuntimeReadinessAcceptsCurrentSecurityCycle(
	t *testing.T,
) {
	t.Parallel()

	notBefore :=
		time.Date(
			2026,
			time.October,
			8,
			11,
			3,
			24,
			0,
			time.UTC,
		)

	records :=
		[]approval2CollectorRuntimeRecord{
			{
				Version:    approval2CollectorRuntimeVersion,
				RecordKind: "WindowsSecurityCatchUp",
				ObservedAt: "2026-10-08T11:03:20.000000000Z",
				Outcome:    "Failed",
				Error:      "stale failure",
			},
			{
				Version:    approval2CollectorRuntimeVersion,
				RecordKind: "ServiceStarted",
				ObservedAt: "2026-10-08T11:03:25.000000000Z",
			},
			{
				Version:    approval2CollectorRuntimeVersion,
				RecordKind: "WindowsSecurityCatchUp",
				ObservedAt: "2026-10-08T11:03:26.000000000Z",
				Outcome:    "Complete",
			},
		}

	ready, err :=
		inspectApproval2CollectorRuntimeReadiness(
			records,
			notBefore,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !ready {
		t.Fatal(
			"current-transaction Collector runtime was not accepted as ready",
		)
	}
}

func TestInspectApproval2CollectorRuntimeReadinessRejectsCurrentSecurityFailure(
	t *testing.T,
) {
	t.Parallel()

	notBefore :=
		time.Date(
			2026,
			time.October,
			8,
			11,
			3,
			24,
			0,
			time.UTC,
		)

	records :=
		[]approval2CollectorRuntimeRecord{
			{
				Version:    approval2CollectorRuntimeVersion,
				RecordKind: "ServiceStarted",
				ObservedAt: "2026-10-08T11:03:25.000000000Z",
			},
			{
				Version:    approval2CollectorRuntimeVersion,
				RecordKind: "WindowsSecurityCatchUp",
				ObservedAt: "2026-10-08T11:03:26.000000000Z",
				Outcome:    "Failed",
				Error:      "EvtOpenLog(Security): Access is denied",
			},
		}

	ready, err :=
		inspectApproval2CollectorRuntimeReadiness(
			records,
			notBefore,
		)

	if ready {
		t.Fatal(
			"failed Windows Security cycle unexpectedly satisfied Collector readiness",
		)
	}

	if err == nil {
		t.Fatal(
			"failed Windows Security cycle unexpectedly returned nil error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"EvtOpenLog(Security): Access is denied",
	) {
		t.Fatalf(
			"error = %q, missing underlying Windows Security failure",
			err,
		)
	}
}

func TestInspectApproval2CollectorRuntimeReadinessRequiresBothRecords(
	t *testing.T,
) {
	t.Parallel()

	notBefore :=
		time.Date(
			2026,
			time.October,
			8,
			11,
			3,
			24,
			0,
			time.UTC,
		)

	records :=
		[]approval2CollectorRuntimeRecord{
			{
				Version:    approval2CollectorRuntimeVersion,
				RecordKind: "ServiceStarted",
				ObservedAt: "2026-10-08T11:03:25.000000000Z",
			},
		}

	ready, err :=
		inspectApproval2CollectorRuntimeReadiness(
			records,
			notBefore,
		)
	if err != nil {
		t.Fatal(err)
	}

	if ready {
		t.Fatal(
			"ServiceStarted without WindowsSecurityCatchUp unexpectedly satisfied readiness",
		)
	}
}
func TestResolveApproval2CollectorRuntimeStateDirRejectsAbsentConfiguration(
	t *testing.T,
) {
	t.Parallel()

	_, err :=
		resolveApproval2CollectorRuntimeStateDir(
			func() Report {
				return Report{
					Config: ConfigState{
						Presence: presenceAbsent,
					},
				}
			},
		)

	if err == nil {
		t.Fatal(
			"absent installed configuration unexpectedly supplied runtime state directory",
		)
	}

	if !strings.Contains(
		err.Error(),
		"requires an installed FI operational configuration",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestResolveApproval2CollectorRuntimeStateDirRejectsNilRediscovery(
	t *testing.T,
) {
	t.Parallel()

	if _, err :=
		resolveApproval2CollectorRuntimeStateDir(
			nil,
		); err == nil {
		t.Fatal(
			"nil readiness rediscovery unexpectedly accepted",
		)
	}
}

func TestResolveApproval2CollectorRuntimeStateDirUsesAuthoritativeInstalledConfiguration(
	t *testing.T,
) {
	t.Parallel()

	const expected = `D:\FI\authoritative-state`

	actual, err :=
		resolveApproval2CollectorRuntimeStateDir(
			func() Report {
				return Report{
					Config: ConfigState{
						Presence: presencePresent,
						StateDir: expected,
					},
				}
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if actual != expected {
		t.Fatalf(
			"state directory = %q, want %q",
			actual,
			expected,
		)
	}
}
func writeApproval2CollectorRuntimeRecordsForTest(
	t *testing.T,
	stateDir string,
	records []approval2CollectorRuntimeRecord,
) {
	t.Helper()

	path :=
		filepath.Join(
			stateDir,
			approval2CollectorRuntimeLogName,
		)

	file, err :=
		os.OpenFile(
			path,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
			0o600,
		)
	if err != nil {
		t.Fatal(err)
	}

	encoder :=
		json.NewEncoder(
			file,
		)

	for _, record := range records {
		if err :=
			encoder.Encode(
				record,
			); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForFICollectorRuntimeReadinessFromRediscoveryUsesInstalledConfigAndRuntimeLog(
	t *testing.T,
) {
	t.Parallel()

	// This deliberately models the exact virgin-install condition that caused
	// M22K4B2 to fail: the sealed pre-CONFIG report has no StateDir.
	preMutation :=
		Report{
			Config: ConfigState{
				Presence: presenceAbsent,
			},
		}

	if strings.TrimSpace(
		preMutation.Config.StateDir,
	) != "" {
		t.Fatal(
			"test precondition failed: pre-mutation StateDir is not empty",
		)
	}

	stateDir :=
		t.TempDir()

	transactionStart :=
		time.Date(
			2026,
			time.October,
			8,
			22,
			15,
			0,
			0,
			time.UTC,
		)

	transactionID :=
		transactionStart.Format(
			approval2TransactionTimestampLayout,
		)

	writeApproval2CollectorRuntimeRecordsForTest(
		t,
		stateDir,
		[]approval2CollectorRuntimeRecord{
			{
				Version: approval2CollectorRuntimeVersion,

				RecordKind: "WindowsSecurityCatchUp",

				ObservedAt: transactionStart.
					Add(-time.Second).
					Format(time.RFC3339Nano),

				Outcome: "Failed",

				Error: "stale failure from a prior transaction",
			},
			{
				Version: approval2CollectorRuntimeVersion,

				RecordKind: "ServiceStarted",

				ObservedAt: transactionStart.
					Add(time.Millisecond).
					Format(time.RFC3339Nano),
			},
			{
				Version: approval2CollectorRuntimeVersion,

				RecordKind: "WindowsSecurityCatchUp",

				ObservedAt: transactionStart.
					Add(2 * time.Millisecond).
					Format(time.RFC3339Nano),

				Outcome: "Complete",
			},
		},
	)

	rediscoveryCalls := 0

	err :=
		waitForFICollectorRuntimeReadinessFromRediscovery(
			func() Report {
				rediscoveryCalls++

				return Report{
					Config: ConfigState{
						Presence: presencePresent,
						StateDir: stateDir,
					},
				}
			},
			transactionID,
			250*time.Millisecond,
		)
	if err != nil {
		t.Fatal(err)
	}

	if rediscoveryCalls != 1 {
		t.Fatalf(
			"rediscovery calls = %d, want 1",
			rediscoveryCalls,
		)
	}
}

func TestWaitForFICollectorRuntimeReadinessFromRediscoveryReturnsCurrentSecurityFailure(
	t *testing.T,
) {
	t.Parallel()

	stateDir :=
		t.TempDir()

	transactionStart :=
		time.Date(
			2026,
			time.October,
			8,
			22,
			20,
			0,
			0,
			time.UTC,
		)

	transactionID :=
		transactionStart.Format(
			approval2TransactionTimestampLayout,
		)

	const expectedFailure = "synthetic EvtOpenLog Security failure"

	writeApproval2CollectorRuntimeRecordsForTest(
		t,
		stateDir,
		[]approval2CollectorRuntimeRecord{
			{
				Version: approval2CollectorRuntimeVersion,

				RecordKind: "ServiceStarted",

				ObservedAt: transactionStart.
					Add(time.Millisecond).
					Format(time.RFC3339Nano),
			},
			{
				Version: approval2CollectorRuntimeVersion,

				RecordKind: "WindowsSecurityCatchUp",

				ObservedAt: transactionStart.
					Add(2 * time.Millisecond).
					Format(time.RFC3339Nano),

				Outcome: "Failed",
				Error:   expectedFailure,
			},
		},
	)

	err :=
		waitForFICollectorRuntimeReadinessFromRediscovery(
			func() Report {
				return Report{
					Config: ConfigState{
						Presence: presencePresent,
						StateDir: stateDir,
					},
				}
			},
			transactionID,
			250*time.Millisecond,
		)

	if err == nil {
		t.Fatal(
			"failed current Windows Security cycle unexpectedly satisfied readiness",
		)
	}

	if !strings.Contains(
		err.Error(),
		expectedFailure,
	) {
		t.Fatalf(
			"error = %q, want underlying Security failure %q",
			err,
			expectedFailure,
		)
	}
}
