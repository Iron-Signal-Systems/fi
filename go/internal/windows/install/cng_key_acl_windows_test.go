// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestAppendCNGKeyReadACEPreservesDescriptorSections(t *testing.T) {
	t.Parallel()

	const (
		original = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(AU;SA;FA;;;WD)"
		sid      = "S-1-5-21-111-222-333-444"
	)

	value, err := appendCNGKeyReadACE(original, sid)
	if err != nil {
		t.Fatal(err)
	}

	wantACE := "(A;;0x00120089;;;" + sid + ")"
	if !strings.Contains(value, wantACE) {
		t.Fatalf("CNG Read ACE missing from %q", value)
	}

	if !strings.HasPrefix(value, "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)") {
		t.Fatalf("owner/group/DACL prefix changed: %q", value)
	}

	sacl := strings.Index(value, "S:")
	ace := strings.Index(value, wantACE)
	if sacl < 0 || ace < 0 || ace > sacl {
		t.Fatalf("CNG Read ACE was not inserted before SACL: %q", value)
	}

	if !strings.HasSuffix(value, "S:(AU;SA;FA;;;WD)") {
		t.Fatalf("SACL changed: %q", value)
	}
}

func TestCNGKeyACLTargetsFromPlanParsesExactCertificateIdentities(t *testing.T) {
	t.Parallel()

	batch := strings.Repeat("A", 64)
	transport := strings.Repeat("B", 64)

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "ACL",
				Target:    approval2BatchCNGKeyTarget(batch),
			},
			{
				Action:    planActionReconcile,
				Authority: "ACL",
				Target:    approval2TransportCNGKeyTarget(transport),
			},
			{
				Action:    planActionReconcile,
				Authority: "ACL",
				Target:    `C:\ProgramData\FI\state`,
			},
		},
	}

	targets, err := cngKeyACLTargetsFromPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("CNG target count=%d want=2", len(targets))
	}

	if !strings.EqualFold(targets[0].CertificateSHA256, batch) {
		t.Fatalf("batch SHA256=%q want=%q", targets[0].CertificateSHA256, batch)
	}
	if !strings.EqualFold(targets[1].CertificateSHA256, transport) {
		t.Fatalf("transport SHA256=%q want=%q", targets[1].CertificateSHA256, transport)
	}
}

func TestPlanApproval1CNGKeyACLsCommitsExactHashesAndIdentity(t *testing.T) {
	t.Parallel()

	batch := strings.Repeat("B", 64)
	transport := strings.Repeat("A", 64)
	account := `ISS\gFI-ADMINBOX$`

	plan := InstallPlan{
		Identities: DesiredFIIdentities{
			CollectorSender: DesiredFIIdentity{
				Account: account,
			},
		},
	}

	planApproval1CNGKeyACLs(
		&plan,
		approval1PKIHandoff{
			BatchCertificateSHA256:     batch,
			TransportCertificateSHA256: transport,
		},
	)

	if len(plan.Actions) != 2 {
		t.Fatalf("actions=%d want=2", len(plan.Actions))
	}

	for _, action := range plan.Actions {
		if action.Action != planActionReconcile || action.Authority != "ACL" {
			t.Fatalf("unexpected CNG ACL action: %+v", action)
		}
		if !strings.Contains(action.Detail, account) {
			t.Fatalf("CNG ACL action does not bind account %q: %s", account, action.Detail)
		}
	}

	if plan.Actions[0].Target != approval2BatchCNGKeyTarget(batch) {
		t.Fatalf("batch target=%q", plan.Actions[0].Target)
	}
	if plan.Actions[1].Target != approval2TransportCNGKeyTarget(transport) {
		t.Fatalf("transport target=%q", plan.Actions[1].Target)
	}
}

func TestValidCNGKeyUniqueNameRejectsPathMaterial(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"",
		".",
		"..",
		`..\key`,
		`sub\key`,
		"sub/key",
	} {
		if validCNGKeyUniqueName(value) {
			t.Fatalf("unsafe CNG unique name accepted: %q", value)
		}
	}

	if !validCNGKeyUniqueName("49bd6ed777e43ea8d258fb8175d4554d_af2b3d51-9a31-40fd-8d6b-b3b4c5c0dbce") {
		t.Fatal("valid CNG unique name rejected")
	}
}
