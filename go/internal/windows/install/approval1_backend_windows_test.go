// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestApplyApproval1PKIHandoffMovesCompleteTrustContractToApproval2(
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

	handoff := approval1CompleteTestHandoff()

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
			planActionMutates(
				action.Action,
			) {
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

	foundCRL := false
	foundTrustBinding := false

	for _, action := range post.Actions {
		if action.Authority != "CONFIG" {
			continue
		}

		switch action.Target {
		case handoff.CRLDestinationPath:
			foundCRL = true

			if action.Action != planActionCreate {
				t.Fatalf(
					"CRL action=%s want=%s",
					action.Action,
					planActionCreate,
				)
			}

			for _, expected := range []string{
				handoff.CRLDistributionPoint,
				handoff.CRLSHA256,
				handoff.CRLThisUpdate,
				handoff.CRLNextUpdate,
			} {
				if !strings.Contains(
					action.Detail,
					expected,
				) {
					t.Fatalf(
						"CRL action does not commit to %q: %s",
						expected,
						action.Detail,
					)
				}
			}

		case report.Trust.Path:
			foundTrustBinding = true

			if action.Action != planActionCreate {
				t.Fatalf(
					"transport-trust action=%s want=%s",
					action.Action,
					planActionCreate,
				)
			}

			for _, expected := range []string{
				handoff.TransportCertificateSHA256,
				handoff.BatchCertificateSHA256,
				handoff.TransportIssuerSHA256,
				handoff.RootCertificateSHA256,
				handoff.CRLDestinationPath,
			} {
				if !strings.Contains(
					action.Detail,
					expected,
				) {
					t.Fatalf(
						"transport-trust action does not commit to %q: %s",
						expected,
						action.Detail,
					)
				}
			}
		}
	}

	if !foundCRL {
		t.Fatal(
			"post-handoff plan did not create an Approval 2 CRL persistence action",
		)
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

func TestDiscoverApproval1PKIIdentityHandoffRediscoversBothDurableIdentities(
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

	handoff, err := discoverApproval1PKIIdentityHandoff(
		report,
		backend,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := validateApproval1PKIIdentityHandoff(
		handoff,
	); err != nil {
		t.Fatalf(
			"durable identity handoff is invalid: %v",
			err,
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

func TestFinalizeApproval1PKIHandoffAcceptsDirectRootIssuer(
	t *testing.T,
) {
	t.Parallel()

	identity := approval1PKIHandoff{
		BatchCertificateSHA256:     strings.Repeat("B", 64),
		BatchTemplateOID:           "1.2.3.5",
		TransportCertificateSHA256: strings.Repeat("A", 64),
		TransportTemplateOID:       "1.2.3.4",
	}

	const crlSource = "ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint"

	trust := approval1TransportTrustMaterial{
		CRLDestinationPath:         approval1TransportCRLDestination,
		CRLDistributionPoint:       crlSource,
		IssuerCertificateSHA256:    strings.Repeat("D", 64),
		RootCertificateSHA256:      strings.Repeat("D", 64),
		TransportCertificateSHA256: identity.TransportCertificateSHA256,
	}

	crlDER := []byte(
		"synthetic validated CRL DER",
	)
	sum := sha256.Sum256(
		crlDER,
	)

	crl := approval1CRLMaterial{
		DER:             crlDER,
		DestinationPath: approval1TransportCRLDestination,
		NextUpdate:      "2026-10-04T09:24:13Z",
		SHA256: hex.EncodeToString(
			sum[:],
		),
		Source:     crlSource,
		ThisUpdate: "2026-09-26T21:04:13Z",
	}

	handoff, err := finalizeApproval1PKIHandoff(
		identity,
		trust,
		crl,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !handoff.complete() {
		t.Fatalf(
			"complete durable handoff was rejected: %+v",
			handoff,
		)
	}

	if handoff.TransportIssuerSHA256 !=
		handoff.RootCertificateSHA256 {
		t.Fatalf(
			"direct root issuer was not preserved: issuer=%s root=%s",
			handoff.TransportIssuerSHA256,
			handoff.RootCertificateSHA256,
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

func approval1CompleteTestHandoff() approval1PKIHandoff {
	return approval1PKIHandoff{
		BatchCertificateSHA256:     strings.Repeat("B", 64),
		BatchTemplateOID:           "1.2.3.5",
		CRLDestinationPath:         approval1TransportCRLDestination,
		CRLDistributionPoint:       "ldap:///CN=ISS-Root-CA,CN=CA,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=iss,DC=local?certificateRevocationList?base?objectClass=cRLDistributionPoint",
		CRLNextUpdate:              "2026-10-04T09:24:13Z",
		CRLSHA256:                  strings.Repeat("C", 64),
		CRLThisUpdate:              "2026-09-26T21:04:13Z",
		RootCertificateSHA256:      strings.Repeat("D", 64),
		TransportCertificateSHA256: strings.Repeat("A", 64),
		TransportIssuerSHA256:      strings.Repeat("D", 64),
		TransportTemplateOID:       "1.2.3.4",
	}
}
