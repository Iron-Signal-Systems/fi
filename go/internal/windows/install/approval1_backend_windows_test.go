// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestApplyApproval1PKIHandoffMovesTrustBindingToApproval2(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Trust: TransportTrustState{
			Path:     `C:\ProgramData\FI\config\fi-transport-trust.conf`,
			Presence: presenceAbsent,
		},
	}

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "PKI",
				Detail:    "enroll FI source identities",
				Target:    "FI transport PKI",
			},
			{
				Action:    planActionCreate,
				Authority: "CONFIG",
				Detail:    "create operational configuration",
				Target:    `C:\ProgramData\FI\config\fi.conf`,
			},
		},
	}

	handoff := approval1PKIHandoff{
		BatchCertificateSHA256:     strings.Repeat("B", 64),
		BatchTemplateOID:           "1.2.3.5",
		TransportCertificateSHA256: strings.Repeat("A", 64),
		TransportTemplateOID:       "1.2.3.4",
	}

	post := applyApproval1PKIHandoffToPlan(
		report,
		plan,
		handoff,
	)

	if post.HasBlockers() {
		t.Fatalf(
			"post-handoff plan unexpectedly blocked: %+v",
			post.Actions,
		)
	}

	for _, action := range post.Actions {
		if action.Authority == "PKI" &&
			planActionMutates(action.Action) {
			t.Fatalf(
				"Approval 1 PKI mutation remained after durable handoff: %+v",
				action,
			)
		}
	}

	approval1, approval2 := ApprovalRequirements(
		post,
	)
	if approval1 {
		t.Fatal(
			"Approval 1 remained required after durable PKI handoff",
		)
	}
	if !approval2 {
		t.Fatal(
			"Approval 2 was not required for local trust binding",
		)
	}

	foundTrustBinding := false
	for _, action := range post.Actions {
		if action.Authority != "CONFIG" ||
			action.Target != report.Trust.Path {
			continue
		}

		foundTrustBinding = true
		if action.Action != planActionCreate {
			t.Fatalf(
				"transport-trust action=%s want=%s",
				action.Action,
				planActionCreate,
			)
		}

		if !strings.Contains(
			action.Detail,
			handoff.TransportCertificateSHA256,
		) ||
			!strings.Contains(
				action.Detail,
				handoff.BatchCertificateSHA256,
			) {
			t.Fatalf(
				"transport-trust action does not commit to durable certificate identities: %s",
				action.Detail,
			)
		}
	}

	if !foundTrustBinding {
		t.Fatal(
			"post-handoff plan did not create an Approval 2 transport-trust binding action",
		)
	}
}

func TestApplyApproval1PKIHandoffRejectsIncompleteState(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Trust: TransportTrustState{
			Path:     `C:\ProgramData\FI\config\fi-transport-trust.conf`,
			Presence: presenceAbsent,
		},
	}

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "PKI",
				Detail:    "enroll FI source identities",
				Target:    "FI transport PKI",
			},
		},
	}

	post := applyApproval1PKIHandoffToPlan(
		report,
		plan,
		approval1PKIHandoff{},
	)

	if !post.HasBlockers() {
		t.Fatal(
			"incomplete durable PKI handoff was unexpectedly accepted",
		)
	}
}

func TestDiscoverApproval1PKIHandoffRediscoversBothDurableIdentities(
	t *testing.T,
) {
	t.Parallel()

	report, _ := approval1PKITestState()

	backend := &fakeApproval1PKIBackend{
		reusable: map[string]localMachinePKICertificate{
			fiTransportClientTemplateName: {
				CertificateSHA256: strings.Repeat(
					"A",
					64,
				),
			},
			fiBatchSigningTemplateName: {
				CertificateSHA256: strings.Repeat(
					"B",
					64,
				),
			},
		},
		templateOIDs: map[string]string{
			fiTransportClientTemplateName: "1.2.3.4",
			fiBatchSigningTemplateName:    "1.2.3.5",
		},
	}

	handoff, err := discoverApproval1PKIHandoff(
		report,
		backend,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !handoff.complete() {
		t.Fatalf(
			"durable handoff is incomplete: %+v",
			handoff,
		)
	}

	wantEvents := []string{
		"resolve:" + fiTransportClientTemplateName,
		"resolve:" + fiBatchSigningTemplateName,
		"reuse:" + fiTransportClientTemplateName,
		"reuse:" + fiBatchSigningTemplateName,
	}

	if strings.Join(
		backend.events,
		"|",
	) != strings.Join(
		wantEvents,
		"|",
	) {
		t.Fatalf(
			"events=%v want=%v",
			backend.events,
			wantEvents,
		)
	}
}

func TestValidSHA256Hex(
	t *testing.T,
) {
	t.Parallel()

	if !validSHA256Hex(
		strings.Repeat("a", 64),
	) {
		t.Fatal(
			"valid SHA-256 hex was rejected",
		)
	}

	if validSHA256Hex(
		strings.Repeat("z", 64),
	) {
		t.Fatal(
			"non-hex SHA-256 value was accepted",
		)
	}

	if validSHA256Hex(
		strings.Repeat("a", 63),
	) {
		t.Fatal(
			"short SHA-256 value was accepted",
		)
	}
}
