// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestApproval2StaleLocalGMSARebindBeforeOtherIdentities(t *testing.T) {
	report, plan := approval2LocalIdentityTestState()
	old := plan.Identities.CollectorSender
	report.GMSAs[0].State = "stale_registration"
	plan.Actions[0].Action = planActionReconcile
	backend := newFakeApproval2LocalIdentityBackend(plan.Identities)

	rollback, err := reconcileApproval2LocalIdentitiesWithBackend(report, plan, backend)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(backend.events, "|")
	if !strings.Contains(joined, "remove:"+old.SAMAccountName+"|present:"+old.SAMAccountName+"|install:"+old.SAMAccountName) {
		t.Fatalf("stale gMSA was not unlinked before relink: %s", joined)
	}
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	if !backend.present[old.SAMAccountName] {
		t.Fatal("rollback destroyed preexisting FI local identity")
	}
	for _, name := range []string{plan.Identities.USNReader.SAMAccountName, plan.Identities.ObjReader.SAMAccountName, plan.Identities.CRLRefresher.SAMAccountName} {
		if backend.present[name] {
			t.Fatalf("rollback retained newly installed %s", name)
		}
	}
}

func TestApproval2StaleLocalGMSARefusesExistingService(t *testing.T) {
	report, plan := approval2LocalIdentityTestState()
	report.GMSAs[0].State = "stale_registration"
	plan.Actions[0].Action = planActionReconcile
	report.Services = append(report.Services, ServiceState{Name: "FICollector", Presence: presencePresent})
	backend := newFakeApproval2LocalIdentityBackend(plan.Identities)
	_, err := reconcileApproval2LocalIdentitiesWithBackend(report, plan, backend)
	if err == nil {
		t.Fatal("stale rebind interrupted installed service")
	}
	if len(backend.events) != 0 {
		t.Fatalf("backend touched with service present: %v", backend.events)
	}
}

func TestApproval2StaleLocalGMSAPreflightRejectsDrift(t *testing.T) {
	report, plan := approval2LocalIdentityTestState()
	report.GMSAs[0].State = "stale_registration"
	plan.Actions[0].Action = planActionReconcile
	backend := newFakeApproval2LocalIdentityBackend(plan.Identities)
	backend.present[plan.Identities.CollectorSender.SAMAccountName] = false
	_, err := reconcileApproval2LocalIdentitiesWithBackend(report, plan, backend)
	if err == nil {
		t.Fatal("stale gMSA drift incorrectly accepted")
	}
	for _, event := range backend.events {
		if strings.HasPrefix(event, "install:") || strings.HasPrefix(event, "remove:") {
			t.Fatalf("mutation occurred after preflight drift: %v", backend.events)
		}
	}
}
