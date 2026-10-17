// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestRetainedTransportCRLMigrationPlanning(
	t *testing.T,
) {
	t.Parallel()

	report :=
		Report{
			Trust: TransportTrustState{
				BatchSigningCertificateSHA256: strings.Repeat(
					"B",
					64,
				),

				Path: `C:\ProgramData\FI\config\fi-transport-trust.conf`,

				Presence: presencePresent,

				RootCertificateSHA256: strings.Repeat(
					"A",
					64,
				),

				TransportCertificateSHA256: strings.Repeat(
					"C",
					64,
				),

				TransportCRLPath: `C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem`,

				TransportIssuerSHA256: strings.Repeat(
					"A",
					64,
				),

				VersionID: "1.0",
			},

			PKI: []TrustObjectState{
				{
					Name: "transport root certificate",

					State: checkPass,
				},
				{
					Name: "transport issuer certificate",

					State: checkPass,
				},
				{
					Name: "source transport signing identity",

					State: checkPass,
				},
				{
					Name: "batch signing identity",

					State: checkPass,
				},
				{
					Name: "transport CRL",

					State: checkPass,
				},
			},
		}

	if !retainedTransportCRLMigrationRequired(
		report,
	) {
		t.Fatal(
			"retained transport CRL migration was not detected",
		)
	}

	var plan InstallPlan

	planPKI(
		&plan,
		report,
		PlanInputs{},
	)

	crlAction, found :=
		findPlanActionForTest(
			plan,
			"CONFIG",
			approval1TransportCRLDestination,
		)
	if !found {
		t.Fatal(
			"retained migration is missing canonical CRL CONFIG action",
		)
	}

	if crlAction.Action !=
		planActionReconcile {
		t.Fatalf(
			"canonical CRL migration action=%s want=%s",
			crlAction.Action,
			planActionReconcile,
		)
	}

	trustAction, found :=
		findPlanActionForTest(
			plan,
			"CONFIG",
			report.Trust.Path,
		)
	if !found {
		t.Fatal(
			"retained migration is missing transport-trust CONFIG action",
		)
	}

	if trustAction.Action !=
		planActionReconcile {
		t.Fatalf(
			"transport-trust migration action=%s want=%s",
			trustAction.Action,
			planActionReconcile,
		)
	}

	if !approval2TransportConfigRequired(
		report,
		plan,
		approval1PKIHandoff{},
	) {
		t.Fatal(
			"retained migration did not route through Approval 2 transport CONFIG",
		)
	}

	if err :=
		validateApproval2ControllerMutationScope(
			report,
			plan,
			approval1PKIHandoff{},
		); err != nil {
		t.Fatalf(
			"retained migration plan is not valid Approval-2 scope: %v",
			err,
		)
	}

	report.Trust.TransportCRLPath =
		approval1TransportCRLDestination

	if retainedTransportCRLMigrationRequired(
		report,
	) {
		t.Fatal(
			"canonical CRL path still requests migration",
		)
	}

	var converged InstallPlan

	planPKI(
		&converged,
		report,
		PlanInputs{},
	)

	for _, action := range converged.Actions {
		if action.Authority ==
			"CONFIG" &&
			planActionMutates(
				action.Action,
			) {
			t.Fatalf(
				"canonical retained trust still contains CONFIG mutation: %+v",
				action,
			)
		}
	}
}
