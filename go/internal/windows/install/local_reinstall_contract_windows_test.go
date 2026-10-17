// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalReinstallRetainedTrustRequiresApproval2Only(
	t *testing.T,
) {
	t.Parallel()

	approval1, _ :=
		approval2ControllerTestState(
			t,
		)

	report := approval1.Rediscovered

	// Model an application-layer reinstall:
	//
	//   retained:
	//     - domain / AD authority
	//     - installed gMSA identities
	//     - transport trust configuration
	//     - transport/batch PKI identity
	//     - release trust
	//     - package payload
	//
	//   absent:
	//     - operational fi.conf
	//     - five SCM registrations
	//     - five installed runtime executables
	//
	// The retained transport trust is deliberately authoritative. This
	// scenario must not require a new Approval-1 PKI transaction or a typed
	// Approval-1 PKI handoff.

	report.Config = ConfigState{
		Path:     `C:\ProgramData\FI\config\fi.conf`,
		Presence: presenceAbsent,
	}

	report.Trust = TransportTrustState{
		BatchSigningCertificateSHA256: strings.Repeat(
			"B",
			64,
		),

		Path: `C:\ProgramData\FI\config\fi-transport-trust.conf`,

		Presence: presencePresent,

		RootCertificateSHA256: strings.Repeat(
			"R",
			64,
		),

		TransportCertificateSHA256: strings.Repeat(
			"T",
			64,
		),

		TransportCRLPath: `C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem`,

		TransportIssuerSHA256: strings.Repeat(
			"I",
			64,
		),

		VersionID: "1.0",
	}

	report.PKI = []TrustObjectState{
		{
			Name:  "transport root certificate",
			State: checkPass,
		},
		{
			Name:  "transport issuer certificate",
			State: checkPass,
		},
		{
			Name:  "source transport signing identity",
			State: checkPass,
		},
		{
			Name:  "batch signing identity",
			State: checkPass,
		},
		{
			Name:  "transport CRL",
			State: checkPass,
		},
	}

	report.Services = []ServiceState{
		{
			Name:     "FICollector",
			Presence: presenceAbsent,
		},
		{
			Name:     "FIUSNReader",
			Presence: presenceAbsent,
		},
		{
			Name:     "FIObjReader",
			Presence: presenceAbsent,
		},
		{
			Name:     "FICRLRefresher",
			Presence: presenceAbsent,
		},
		{
			Name:     "FISender",
			Presence: presenceAbsent,
		},
	}

	report.Binaries = []BinaryState{
		{
			Name:     "FICollector",
			Path:     `C:\Program Files\FI\fi-collector.exe`,
			Presence: presenceAbsent,
			SHA256:   notKnown,
		},
		{
			Name:     "FIUSNReader",
			Path:     `C:\Program Files\FI\fi-usn-reader.exe`,
			Presence: presenceAbsent,
			SHA256:   notKnown,
		},
		{
			Name:     "FIObjReader",
			Path:     `C:\Program Files\FI\fi-obj-reader.exe`,
			Presence: presenceAbsent,
			SHA256:   notKnown,
		},
		{
			Name:     "FICRLRefresher",
			Path:     `C:\Program Files\FI\fi-crl-refresher.exe`,
			Presence: presenceAbsent,
			SHA256:   notKnown,
		},
		{
			Name:     "FISender",
			Path:     `C:\Program Files\FI\fi-sender.exe`,
			Presence: presenceAbsent,
			SHA256:   notKnown,
		},
	}

	report.Package.InstalledHashesMatch = false

	inputs := PlanInputs{
		GovernedRoots: []string{
			`C:\FI-Lab`,
		},

		ReceiverAddress: "192.168.1.219:8443",

		ReceiverName: "fi-receiver-b.iss.local",

		SpoolDir: `C:\ProgramData\FI\spool`,

		StageDir: `C:\ProgramData\FI\transport-v2-drain\stage`,

		StateDir: `C:\ProgramData\FI\state`,
	}

	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		t.Fatal(err)
	}

	var plan InstallPlan

	// Build the local-reinstall slice directly so this test characterizes the
	// exact contracts involved without fabricating unrelated AD/group/ACL
	// discovery state.
	working := report

	planConfiguration(
		&plan,
		&working,
		inputs,
	)

	planPKI(
		&plan,
		working,
		inputs,
	)

	planServices(
		&plan,
		working,
		identities,
		nil,
	)

	planPackage(
		&plan,
		working,
	)

	if plan.HasBlockers() {
		t.Fatalf(
			"local reinstall plan contains blockers: %+v",
			plan.Actions,
		)
	}

	if plan.HasQuestions() {
		t.Fatalf(
			"local reinstall plan contains questions: %v",
			plan.Questions,
		)
	}

	if !transportPKIComplete(
		working,
	) {
		t.Fatal(
			"retained transport PKI was not recognized as complete",
		)
	}

	pkiAction, found := findPlanActionForTest(
		plan,
		"PKI",
		"FI transport PKI",
	)
	if !found {
		t.Fatal(
			"local reinstall plan is missing the PKI action",
		)
	}

	if pkiAction.Action != planActionNoChange {
		t.Fatalf(
			"retained PKI action=%s want=%s detail=%s",
			pkiAction.Action,
			planActionNoChange,
			pkiAction.Detail,
		)
	}

	configAction, found := findPlanActionForTest(
		plan,
		"CONFIG",
		`C:\ProgramData\FI\config\fi.conf`,
	)
	if !found {
		t.Fatal(
			"local reinstall plan is missing operational CONFIG",
		)
	}

	if configAction.Action != planActionCreate {
		t.Fatalf(
			"operational CONFIG action=%s want=%s",
			configAction.Action,
			planActionCreate,
		)
	}

	sourceAction, found := findPlanActionForTest(
		plan,
		"CONFIG",
		"source.id=adminbox.iss.local",
	)
	if !found {
		t.Fatal(
			"local reinstall plan is missing derived source.id CONFIG",
		)
	}

	if sourceAction.Action != planActionCreate {
		t.Fatalf(
			"source.id CONFIG action=%s want=%s",
			sourceAction.Action,
			planActionCreate,
		)
	}

	serviceCreates := 0

	for _, action := range plan.Actions {
		if action.Authority == "SCM" &&
			action.Action == planActionCreate {
			serviceCreates++
		}
	}

	if serviceCreates != 5 {
		t.Fatalf(
			"SCM CREATE count=%d want=5 actions=%+v",
			serviceCreates,
			plan.Actions,
		)
	}

	packageAction, found := findPlanActionForTest(
		plan,
		"PACKAGE",
		"installed FI executables",
	)
	if !found {
		t.Fatal(
			"local reinstall plan is missing PACKAGE action",
		)
	}

	if packageAction.Action != planActionCreate {
		t.Fatalf(
			"PACKAGE action=%s want=%s detail=%s",
			packageAction.Action,
			planActionCreate,
			packageAction.Detail,
		)
	}

	approval1Required, approval2Required :=
		ApprovalRequirements(
			plan,
		)

	if approval1Required {
		t.Fatal(
			"retained-trust local reinstall unexpectedly requires Approval 1",
		)
	}

	if !approval2Required {
		t.Fatal(
			"local reinstall did not require Approval 2",
		)
	}

	if !RequiresServer2016Approval2Controller(
		plan,
	) {
		t.Fatal(
			"local reinstall was not routed to the Approval-2 controller",
		)
	}

	if !approval2OperationalConfigRequired(
		working,
		plan,
	) {
		t.Fatal(
			"local reinstall did not require operational CONFIG creation",
		)
	}

	if !approval2TransportConfigRequired(
		working,
		plan,
		approval1PKIHandoff{},
	) {
		t.Fatal(
			"retained transport trust CRL path migration was not routed through Approval 2 CONFIG",
		)
	}

	if !approval2RemainingLocalRequired(
		plan,
	) {
		t.Fatal(
			"local reinstall did not require PACKAGE/SCM local-system mutation",
		)
	}

	if err := validateApproval2ControllerPlan(
		working,
		plan,
		approval1PKIHandoff{},
	); err != nil {
		t.Fatalf(
			"retained-trust local reinstall is not eligible for Approval 2: %v",
			err,
		)
	}

	sealed, err := localApproval2SealedState(
		working,
		plan,
	)
	if err != nil {
		t.Fatalf(
			"seal retained-trust local reinstall: %v",
			err,
		)
	}

	if sealed.Approval1.Required ||
		sealed.Approval1.Given {
		t.Fatalf(
			"local reinstall unexpectedly carries Approval-1 authority: %+v",
			sealed.Approval1,
		)
	}

	if !sealed.Approval2Required {
		t.Fatal(
			"sealed local reinstall did not require Approval 2",
		)
	}

	if strings.TrimSpace(
		sealed.Approval2SHA256,
	) == "" {
		t.Fatal(
			"sealed local reinstall Approval-2 digest is empty",
		)
	}
}

func TestPrepareApproval2OwnedDirectoriesPreservesExistingState(
	t *testing.T,
) {
	root := t.TempDir()

	existingSpool := filepath.Join(
		root,
		"spool",
	)

	existingState := filepath.Join(
		root,
		"state",
	)

	existingStage := filepath.Join(
		root,
		"stage",
	)

	newDirectory := filepath.Join(
		root,
		"transaction-created",
	)

	for _, path := range []string{
		existingSpool,
		existingState,
		existingStage,
	} {
		if err := os.Mkdir(
			path,
			0o700,
		); err != nil {
			t.Fatal(err)
		}
	}

	marker := filepath.Join(
		existingState,
		"preexisting-state.marker",
	)

	if err := os.WriteFile(
		marker,
		[]byte(
			"must survive Approval-2 rollback",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	created, err := prepareApproval2OwnedDirectories(
		[]string{
			existingSpool,
			existingState,
			existingStage,
			newDirectory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(created) != 1 {
		t.Fatalf(
			"created directories=%v want exactly one transaction-created directory",
			created,
		)
	}

	if !strings.EqualFold(
		filepath.Clean(
			created[0],
		),
		filepath.Clean(
			newDirectory,
		),
	) {
		t.Fatalf(
			"created directory=%q want=%q",
			created[0],
			newDirectory,
		)
	}

	if err := rollbackApproval2CreatedDirectories(
		created,
	); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		existingSpool,
		existingState,
		existingStage,
	} {
		info, err := os.Stat(
			path,
		)
		if err != nil {
			t.Fatalf(
				"preexisting directory %s did not survive rollback: %v",
				path,
				err,
			)
		}

		if !info.IsDir() {
			t.Fatalf(
				"preexisting path %s is no longer a directory",
				path,
			)
		}
	}

	value, err := os.ReadFile(
		marker,
	)
	if err != nil {
		t.Fatalf(
			"preexisting state marker did not survive rollback: %v",
			err,
		)
	}

	if string(value) !=
		"must survive Approval-2 rollback" {
		t.Fatalf(
			"preexisting state marker changed: %q",
			string(value),
		)
	}

	if _, err := os.Stat(
		newDirectory,
	); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"transaction-created directory survived rollback; err=%v",
			err,
		)
	}
}
