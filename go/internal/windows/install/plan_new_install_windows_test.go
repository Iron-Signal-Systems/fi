// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestInstallPlanModeAuthoritativeAbsenceIsNewInstall(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Config: ConfigState{
			Presence: presenceAbsent,
		},
		Services: []ServiceState{
			{Name: "FICollector", Presence: presenceAbsent},
			{Name: "FIUSNReader", Presence: presenceAbsent},
			{Name: "FIObjReader", Presence: presenceAbsent},
			{Name: "FICRLRefresher", Presence: presenceAbsent},
			{Name: "FISender", Presence: presenceAbsent},
		},
		Binaries: []BinaryState{
			{Name: "FICollector", Presence: presenceAbsent},
			{Name: "FIUSNReader", Presence: presenceAbsent},
			{Name: "FIObjReader", Presence: presenceAbsent},
			{Name: "FICRLRefresher", Presence: presenceAbsent},
			{Name: "FISender", Presence: presenceAbsent},
		},
	}

	if got := installPlanMode(report); got != "NEW INSTALL" {
		t.Fatalf(
			"installPlanMode()=%q, want NEW INSTALL",
			got,
		)
	}
}

func TestInstallPlanModeUnknownDoesNotBecomeNewInstall(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Config: ConfigState{
			Presence: presenceAbsent,
		},
		Services: []ServiceState{
			{Name: "FICollector", Presence: presenceUnknown},
			{Name: "FIUSNReader", Presence: presenceAbsent},
			{Name: "FIObjReader", Presence: presenceAbsent},
			{Name: "FICRLRefresher", Presence: presenceAbsent},
			{Name: "FISender", Presence: presenceAbsent},
		},
		Binaries: []BinaryState{
			{Name: "FICollector", Presence: presenceAbsent},
			{Name: "FIUSNReader", Presence: presenceAbsent},
			{Name: "FIObjReader", Presence: presenceAbsent},
			{Name: "FICRLRefresher", Presence: presenceAbsent},
			{Name: "FISender", Presence: presenceAbsent},
		},
	}

	if got := installPlanMode(report); got != "DISCOVERY INCOMPLETE" {
		t.Fatalf(
			"installPlanMode()=%q, want DISCOVERY INCOMPLETE",
			got,
		)
	}
}

func TestPlanConfigurationNewInstallExactInputs(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Config: ConfigState{
			Path:     `C:\ProgramData\FI\config\fi.conf`,
			Presence: presenceAbsent,
		},
		Host: HostState{
			Computer:  "ISS-FS-02",
			DomainDNS: "iss.local",
		},
	}
	inputs := PlanInputs{
		GovernedRoots: []string{
			`E:\Shares`,
			`F:\Records`,
		},
		ReceiverAddress: "192.168.1.119:8443",
		ReceiverName:    "fi-receiver-a.iss.local",
		SpoolDir:        `E:\FI\spool`,
		PKIChoice:       "enroll",
	}

	var plan InstallPlan
	planConfiguration(
		&plan,
		&report,
		inputs,
	)

	if plan.HasQuestions() {
		t.Fatalf(
			"unexpected questions: %v",
			plan.Questions,
		)
	}
	if report.Config.SourceID != "iss-fs-02.iss.local" {
		t.Fatalf(
			"source id=%q",
			report.Config.SourceID,
		)
	}
	if report.Config.StageDir != `C:\ProgramData\FI\transport-v2-drain\stage` {
		t.Fatalf(
			"stage=%q",
			report.Config.StageDir,
		)
	}
	if report.Config.StateDir != `C:\ProgramData\FI\state` {
		t.Fatalf(
			"state=%q",
			report.Config.StateDir,
		)
	}

	action, ok := findPlanActionForTest(
		plan,
		"CONFIG",
		`C:\ProgramData\FI\config\fi.conf`,
	)
	if !ok {
		t.Fatal(
			"missing CONFIG action for operational configuration",
		)
	}
	if action.Action != planActionCreate {
		t.Fatalf(
			"CONFIG action=%q, want CREATE",
			action.Action,
		)
	}
	if !strings.Contains(
		action.Detail,
		"source=iss-fs-02.iss.local",
	) {
		t.Fatalf(
			"CONFIG detail does not contain derived source: %s",
			action.Detail,
		)
	}
}

func TestPlanConfigurationNewInstallReportsOnlyMissingInputs(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Config: ConfigState{
			Path:     `C:\ProgramData\FI\config\fi.conf`,
			Presence: presenceAbsent,
		},
		Host: HostState{
			Computer:  "ISS-FS-02",
			DomainDNS: "iss.local",
		},
	}
	inputs := PlanInputs{
		ReceiverAddress: "192.168.1.119:8443",
		ReceiverName:    "fi-receiver-a.iss.local",
		SpoolDir:        `E:\FI\spool`,
	}

	var plan InstallPlan
	planConfiguration(
		&plan,
		&report,
		inputs,
	)

	if !plan.HasQuestions() {
		t.Fatal(
			"expected one missing deployment-input question",
		)
	}
	if len(plan.Questions) != 1 {
		t.Fatalf(
			"questions=%v, want exactly one",
			plan.Questions,
		)
	}
	if !strings.Contains(
		plan.Questions[0],
		"governed root",
	) {
		t.Fatalf(
			"unexpected question=%q",
			plan.Questions[0],
		)
	}
}

func TestPlanServicesAuthoritativeAbsenceCreates(
	t *testing.T,
) {
	t.Parallel()

	identities, err := DeriveDesiredFIIdentities(
		"ISS-FS-02",
		"ISS",
	)
	if err != nil {
		t.Fatal(err)
	}

	report := Report{
		Services: []ServiceState{
			{Name: "FICollector", Presence: presenceAbsent},
			{Name: "FIUSNReader", Presence: presenceAbsent},
			{Name: "FIObjReader", Presence: presenceAbsent},
			{Name: "FICRLRefresher", Presence: presenceAbsent},
			{Name: "FISender", Presence: presenceAbsent},
		},
	}

	var plan InstallPlan
	planServices(
		&plan,
		report,
		identities,
		nil,
	)

	creates := 0
	for _, action := range plan.Actions {
		if action.Authority == "SCM" &&
			action.Action == planActionCreate {
			creates++
		}
		if action.Authority == "SCM" &&
			action.Action == planActionBlocked {
			t.Fatalf(
				"unexpected blocked action: %+v",
				action,
			)
		}
	}
	if creates != 5 {
		t.Fatalf(
			"SCM CREATE actions=%d, want 5",
			creates,
		)
	}
}

func TestPlanServicesUnknownBlocksInsteadOfCreate(
	t *testing.T,
) {
	t.Parallel()

	identities, err := DeriveDesiredFIIdentities(
		"ISS-FS-02",
		"ISS",
	)
	if err != nil {
		t.Fatal(err)
	}

	report := Report{
		Services: []ServiceState{
			{Name: "FICollector", Presence: presenceUnknown},
			{Name: "FIUSNReader", Presence: presenceAbsent},
			{Name: "FIObjReader", Presence: presenceAbsent},
			{Name: "FICRLRefresher", Presence: presenceAbsent},
			{Name: "FISender", Presence: presenceAbsent},
		},
	}

	var plan InstallPlan
	planServices(
		&plan,
		report,
		identities,
		nil,
	)

	action, ok := findPlanActionForTest(
		plan,
		"SCM",
		"FICollector",
	)
	if !ok {
		t.Fatal(
			"missing FICollector SCM action",
		)
	}
	if action.Action != planActionBlocked {
		t.Fatalf(
			"FICollector action=%q, want BLOCKED",
			action.Action,
		)
	}
}

func TestPlanPKIChoiceCreateIsExplicitApprovalOneAction(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Trust: TransportTrustState{
			Presence: presenceAbsent,
		},
	}
	var plan InstallPlan

	planPKI(
		&plan,
		report,
		PlanInputs{
			PKIChoice: "create",
		},
	)

	action, ok := findPlanActionForTest(
		plan,
		"PKI",
		"FI transport PKI",
	)
	if !ok {
		t.Fatal(
			"missing PKI action",
		)
	}
	if action.Action != planActionCreate {
		t.Fatalf(
			"PKI action=%q, want CREATE",
			action.Action,
		)
	}
	if plan.HasQuestions() {
		t.Fatalf(
			"unexpected questions: %v",
			plan.Questions,
		)
	}
}

func TestPlanPackageUnknownInstalledStateBlocksInsteadOfCreateOrReconcile(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Binaries: []BinaryState{
			{
				Name:     "FICollector",
				Path:     `C:\Program Files\FI\fi.exe`,
				Presence: presenceUnknown,
				SHA256:   notKnown,
			},
			{
				Name:     "FIUSNReader",
				Path:     `C:\Program Files\FI\fi-usn.exe`,
				Presence: presenceAbsent,
				SHA256:   notKnown,
			},
			{
				Name:     "FIObjReader",
				Path:     `C:\Program Files\FI\fi-obj.exe`,
				Presence: presenceAbsent,
				SHA256:   notKnown,
			},
			{
				Name:     "FICRLRefresher",
				Path:     `C:\Program Files\FI\fi-crl-refresh.exe`,
				Presence: presenceAbsent,
				SHA256:   notKnown,
			},
			{
				Name:     "FISender",
				Path:     `C:\Program Files\FI\fi-sender.exe`,
				Presence: presenceAbsent,
				SHA256:   notKnown,
			},
		},
		Package: PackageState{
			ManifestValid:      true,
			PayloadHashesMatch: true,
			ReleaseID:          "test-release",
		},
	}

	var plan InstallPlan
	planPackage(
		&plan,
		report,
	)

	action, ok := findPlanActionForTest(
		plan,
		"PACKAGE",
		"installed FI executables",
	)
	if !ok {
		t.Fatal(
			"missing installed FI executables action",
		)
	}
	if action.Action != planActionBlocked {
		t.Fatalf(
			"installed executable action=%q, want BLOCKED",
			action.Action,
		)
	}
}

func findPlanActionForTest(
	plan InstallPlan,
	authority string,
	target string,
) (PlanAction, bool) {
	for _, action := range plan.Actions {
		if action.Authority == authority &&
			action.Target == target {
			return action, true
		}
	}
	return PlanAction{}, false
}

func TestPlanLocalGMSAPendingADCreationIsSequencedNotBlocked(t *testing.T) {
	t.Parallel()

	report := Report{
		GMSAs: []GMSAState{
			{
				Account:        `ISS\gFI-USN-ADMINBOX$`,
				Role:           "FIUSNReader",
				SAMAccountName: `gFI-USN-ADMINBOX$`,
				State:          "pending_ad_creation",
			},
		},
	}
	identities := DesiredFIIdentities{
		USNReader: DesiredFIIdentity{
			Account:        `ISS\gFI-USN-ADMINBOX$`,
			SAMAccountName: `gFI-USN-ADMINBOX$`,
		},
	}

	var plan InstallPlan
	planLocalGMSAs(
		&plan,
		report,
		identities,
		nil,
	)

	var found bool
	for _, action := range plan.Actions {
		if action.Target != `ISS\gFI-USN-ADMINBOX$` {
			continue
		}
		found = true
		if action.Action != planActionReconcile {
			t.Fatalf(
				"pending AD creation action=%s, want %s",
				action.Action,
				planActionReconcile,
			)
		}
		if strings.Contains(
			strings.ToUpper(action.Detail),
			"UNKNOWN",
		) {
			t.Fatalf(
				"pending AD creation was represented as unknown: %s",
				action.Detail,
			)
		}
	}
	if !found {
		t.Fatal("pending AD creation local-ID action not found")
	}
}

func TestPlanACLDoesNotMutateUnknownSpoolTarget(t *testing.T) {
	t.Parallel()

	report := Report{
		Config: ConfigState{
			StateDir: `C:\ProgramData\FI\state`,
			SpoolDir: notKnown,
			StageDir: `C:\ProgramData\FI\transport-v2-drain\stage`,
		},
	}

	var plan InstallPlan
	planACLs(
		&plan,
		report,
	)

	for _, action := range plan.Actions {
		if action.Authority != "ACL" {
			continue
		}
		if action.Target == notKnown &&
			action.Action != planActionQuestion {
			t.Fatalf(
				"ACL planned mutation against not_known target: %+v",
				action,
			)
		}
	}

	var question bool
	for _, action := range plan.Actions {
		if action.Authority == "ACL" &&
			action.Action == planActionQuestion &&
			action.Target == "FI spool directory desired ACL contract" {
			question = true
			break
		}
	}
	if !question {
		t.Fatal("missing QUESTION action for unknown spool ACL target")
	}
}

func TestNamedPipePresentMissingPipeIsObservedAbsence(t *testing.T) {
	t.Parallel()

	present, err := namedPipePresent(
		"FI-M19-Definitely-Not-Present-8F74CFE2",
	)
	if err != nil {
		t.Fatalf(
			"missing named pipe returned discovery error: %v",
			err,
		)
	}
	if present {
		t.Fatal(
			"missing named pipe was reported present",
		)
	}
}

func TestPlanPackageUntrustedAuthenticodeSignerDetailIsAccurate(t *testing.T) {
	t.Parallel()

	report := Report{}
	report.Package.ManifestValid = true
	report.Package.PayloadHashesMatch = true
	report.Package.ReleaseID = "test-release"
	report.Package.AuthenticodeFilesTrusted = false
	report.Package.AuthenticodeSignerIdentitiesComplete = false

	var plan InstallPlan
	planPackage(
		&plan,
		report,
	)

	var found bool
	for _, action := range plan.Actions {
		if action.Target != "Authenticode signer identity" {
			continue
		}
		found = true
		if action.Action != planActionBlocked {
			t.Fatalf(
				"signer identity action=%s, want %s",
				action.Action,
				planActionBlocked,
			)
		}
		if strings.Contains(
			action.Detail,
			"WinVerifyTrust succeeded",
		) {
			t.Fatalf(
				"untrusted package emitted contradictory signer detail: %s",
				action.Detail,
			)
		}
		if !strings.Contains(
			action.Detail,
			"did not establish Windows trust",
		) {
			t.Fatalf(
				"untrusted package signer detail=%q",
				action.Detail,
			)
		}
	}
	if !found {
		t.Fatal(
			"Authenticode signer identity action not found",
		)
	}
}
