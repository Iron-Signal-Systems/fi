// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"reflect"
	"strings"
	"testing"
)

func TestServer2016Approval2BackendBuildPlanUsesTypedHandoffReplay(
	t *testing.T,
) {
	t.Parallel()

	report, _ := approval1PKITestState()

	report.Trust = TransportTrustState{
		Path: `C:\ProgramData\FI\config\fi-transport-trust.conf`,

		Presence: presenceAbsent,
	}

	inputs := PlanInputs{
		PKIChoice: "enroll",
	}

	handoff := approval1CompleteTestHandoff()

	base := BuildPlanWithInputs(
		report,
		inputs,
	)

	want := applyApproval1PKIHandoffToPlan(
		report,
		base,
		handoff,
	)

	backend := &server2016Approval2Backend{}

	got := backend.BuildPlan(
		report,
		inputs,
		handoff,
	)

	if !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf(
			"native Approval 2 backend did not replay the typed PKI handoff exactly\ngot=%+v\nwant=%+v",
			got,
			want,
		)
	}
}

func TestServer2016Approval2BackendInvalidHandoffLeavesBasePlan(
	t *testing.T,
) {
	t.Parallel()

	report, _ := approval1PKITestState()

	report.Trust = TransportTrustState{
		Path: `C:\ProgramData\FI\config\fi-transport-trust.conf`,

		Presence: presenceAbsent,
	}

	inputs := PlanInputs{
		PKIChoice: "enroll",
	}

	want := BuildPlanWithInputs(
		report,
		inputs,
	)

	backend := &server2016Approval2Backend{}

	got := backend.BuildPlan(
		report,
		inputs,
		approval1PKIHandoff{},
	)

	if !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf(
			"invalid typed handoff unexpectedly changed the native Approval 2 plan\ngot=%+v\nwant=%+v",
			got,
			want,
		)
	}
}

func TestServer2016Approval2BackendRejectsUnauthorizedLocalIdentityCall(
	t *testing.T,
) {
	t.Parallel()

	backend := &server2016Approval2Backend{}

	_, err := backend.ApplyLocalIdentities(
		Report{},
		InstallPlan{},
	)
	if err == nil {
		t.Fatal(
			"LOCAL ID backend call without plan authority unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not authorize a LOCAL ID mutation",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestServer2016Approval2BackendRejectsUnauthorizedConfigCall(
	t *testing.T,
) {
	t.Parallel()

	backend := &server2016Approval2Backend{}

	_, err := backend.ApplyTransportTrust(
		Report{},
		InstallPlan{},
		approval1CompleteTestHandoff(),
		"synthetic-transaction",
	)
	if err == nil {
		t.Fatal(
			"CONFIG backend call without plan authority unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"does not authorize a CONFIG mutation",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestApproval2HTTPSCRLDoesNotOpenLDAPSession(
	t *testing.T,
) {
	t.Parallel()

	handoff := approval1CompleteTestHandoff()

	handoff.CRLDistributionPoint =
		"https://pki.example.invalid/fi-transport-ca.crl"

	session, err :=
		openApproval2TransportTrustLDAPSession(
			Report{},
			handoff,
		)
	if err != nil {
		t.Fatal(err)
	}

	if session != nil {
		session.close()

		t.Fatal(
			"HTTPS CRL acquisition unexpectedly opened an LDAP session",
		)
	}
}

func TestApproval2LDAPCRLRequiresCurrentAuthoritativeDomainController(
	t *testing.T,
) {
	t.Parallel()

	handoff := approval1CompleteTestHandoff()

	_, err :=
		openApproval2TransportTrustLDAPSession(
			Report{},
			handoff,
		)
	if err == nil {
		t.Fatal(
			"LDAP CRL acquisition without a current domain controller unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"current authoritative domain controller is unavailable",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}
