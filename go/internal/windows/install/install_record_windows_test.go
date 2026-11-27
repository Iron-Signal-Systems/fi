// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildInstallRecordCapturesApprovedMutationsAndVerification(
	t *testing.T,
) {
	t.Parallel()

	before := Report{
		Host: HostState{
			BuildNumber: 14393,
			Computer:    "ISS-FS-01",
			DomainDNS:   "iss.local",
			ProductName: "Windows Server 2016 Standard Evaluation",
			Profile: WindowsProfile{
				BuildNumber: 14393,
				Name:        "Windows Server 2016",
			},
		},
		Package: PackageState{
			ReleaseID: "server2016-test",
			Files: []PackageManifestFileState{
				{
					ActualSHA256:                        "OLD",
					ExpectedSHA256:                      "NEW",
					Name:                                "fi-collector.exe",
					PayloadAuthenticodeSignerAuthorized: true,
					PayloadAuthenticodeSignerCertSHA256: "CERT",
					PayloadAuthenticodeSignerID:         "signer-a",
					PayloadAuthenticodeSignerSPKISHA256: "SPKI",
					PayloadAuthenticodeSignerSubject:    "CN=Signer",
					PayloadAuthenticodeTrusted:          true,
					PayloadSHA256:                       "NEW",
					Role:                                "FICollector",
				},
			},
		},
	}
	final := before
	final.Package.Files = append(
		[]PackageManifestFileState(nil),
		before.Package.Files...,
	)
	final.Package.Files[0].ActualSHA256 = "NEW"

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "PACKAGE",
				Detail:    "replace runtime",
				Target:    `C:\Program Files\FI`,
			},
		},
	}
	finalPlan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionNoChange,
				Authority: "PACKAGE",
				Detail:    "runtime matches",
				Target:    `C:\Program Files\FI`,
			},
		},
	}
	approval := ApprovalState{
		Approval2Given:    true,
		Approval2Required: true,
		PlanSHA256:        strings.Repeat("A", 64),
	}
	context := newInstallRecordContext(
		before,
		plan,
		approval,
		"20260927T190005.000000000Z",
		time.Date(2026, 9, 27, 19, 0, 5, 0, time.UTC),
	)

	record := buildInstallRecord(
		context,
		[]AppliedMutation{
			{
				Authority: "PACKAGE",
				Target:    `C:\Program Files\FI`,
			},
		},
		"PASS",
		nil,
		false,
		make([]string, 0),
		&final,
		&finalPlan,
		final,
		finalPlan,
	)

	if record.Result != "PASS" {
		t.Fatalf("result=%q want PASS", record.Result)
	}
	if len(record.Approval.Mutations) != 1 {
		t.Fatalf(
			"approved mutations=%d want 1",
			len(record.Approval.Mutations),
		)
	}
	if len(record.Applied) != 1 {
		t.Fatalf(
			"applied mutations=%d want 1",
			len(record.Applied),
		)
	}
	if len(record.Payloads) != 1 ||
		record.Payloads[0].InstalledBeforeSHA256 != "OLD" ||
		record.Payloads[0].InstalledFinalSHA256 != "NEW" {
		t.Fatalf(
			"unexpected payload audit state: %+v",
			record.Payloads,
		)
	}
	if !record.Verification.PostMutation.ConvergedToNoChange ||
		!record.Verification.Final.ConvergedToNoChange {
		t.Fatal(
			"successful record verification did not converge",
		)
	}

	encoded, err := json.Marshal(
		record,
	)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if strings.Contains(
		string(encoded),
		":null",
	) {
		t.Fatalf(
			"install record contains a null field: %s",
			encoded,
		)
	}
}

func TestInstallRecordFileTokenRejectsWindowsUnsafeCharacters(
	t *testing.T,
) {
	t.Parallel()

	got := installRecordFileToken(
		"2026-09-27T19:00:05Z",
	)
	if strings.ContainsAny(
		got,
		`:\/*?"<>|`,
	) {
		t.Fatalf(
			"unsafe install record token %q",
			got,
		)
	}
}

func TestBuildInstallRecordFailureKeepsPostMutationAndFinalState(
	t *testing.T,
) {
	t.Parallel()

	before := Report{
		Host: HostState{
			BuildNumber: 14393,
			Computer:    "ISS-FS-01",
			Profile: WindowsProfile{
				BuildNumber: 14393,
				Name:        "Windows Server 2016",
			},
		},
	}
	post := Report{
		Checks: []Check{
			{
				Status: checkFail,
				Name:   "spool ACL",
				Detail: "still differs",
			},
		},
	}
	postPlan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "ACL",
				Target:    `Y:\FI-Gate1\spool`,
				Detail:    "still differs",
			},
		},
	}
	final := before
	finalPlan := InstallPlan{}
	context := newInstallRecordContext(
		before,
		InstallPlan{},
		ApprovalState{PlanSHA256: strings.Repeat("B", 64)},
		"tx-fail",
		time.Now().UTC(),
	)

	record := buildInstallRecord(
		context,
		make([]AppliedMutation, 0),
		"FAIL",
		assertionError("apply failed"),
		true,
		[]string{"ACL: rollback failed"},
		&post,
		&postPlan,
		final,
		finalPlan,
	)

	if record.Verification.PostMutation.ConvergedToNoChange {
		t.Fatal("failed post-mutation verification unexpectedly converged")
	}
	if len(record.Verification.PostMutation.DiscoveryFailures) != 1 {
		t.Fatalf(
			"post-mutation failures=%d want 1",
			len(record.Verification.PostMutation.DiscoveryFailures),
		)
	}
	if len(record.Verification.PostMutation.RemainingMutations) != 1 {
		t.Fatalf(
			"post-mutation remaining=%d want 1",
			len(record.Verification.PostMutation.RemainingMutations),
		)
	}
	if !record.Rollback.Attempted || len(record.Rollback.Errors) != 1 {
		t.Fatalf(
			"unexpected rollback record: %+v",
			record.Rollback,
		)
	}
}

type assertionError string

func (err assertionError) Error() string {
	return string(err)
}
