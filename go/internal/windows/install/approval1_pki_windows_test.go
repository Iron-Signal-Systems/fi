// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"strings"
	"testing"
)

type fakeApproval1PKIBackend struct {
	enrollErrors    map[string]error
	enrollMutations map[string]pkiEnrollmentMutation
	events          []string
	reusable        map[string]localMachinePKICertificate
	resolveErrors   map[string]error
	templateOIDs    map[string]string
	rollbackErrors  map[string]error
}

func (backend *fakeApproval1PKIBackend) Enroll(
	contract pkiEnrollmentContract,
) (pkiEnrollmentMutation, error) {
	backend.events = append(
		backend.events,
		"enroll:"+contract.TemplateName,
	)

	return backend.enrollMutations[contract.TemplateName],
		backend.enrollErrors[contract.TemplateName]
}

func (backend *fakeApproval1PKIBackend) FindReusable(
	contract pkiEnrollmentContract,
) (localMachinePKICertificate, bool, error) {
	backend.events = append(
		backend.events,
		"reuse:"+contract.TemplateName,
	)

	value, found := backend.reusable[contract.TemplateName]
	return value, found, nil
}

func (backend *fakeApproval1PKIBackend) ResolveTemplateOID(
	templateName string,
) (string, error) {
	backend.events = append(
		backend.events,
		"resolve:"+templateName,
	)

	return backend.templateOIDs[templateName],
		backend.resolveErrors[templateName]
}

func (backend *fakeApproval1PKIBackend) RollbackOwned(
	mutation pkiEnrollmentMutation,
) error {
	name := mutation.Certificate.TemplateOID

	backend.events = append(
		backend.events,
		"rollback:"+name,
	)

	return backend.rollbackErrors[name]
}

func TestApproval1PKIExpectedDNS(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Host: HostState{
			Computer:  "AdminBox",
			DomainDNS: "iss.local",
		},
	}

	got, err := approval1PKIExpectedDNS(
		report,
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != "AdminBox.iss.local" {
		t.Fatalf(
			"expected DNS=%q want=%q",
			got,
			"AdminBox.iss.local",
		)
	}
}

func TestApproval1PKIExpectedDNSAcceptsExistingFQDN(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Host: HostState{
			Computer:  "AdminBox.iss.local",
			DomainDNS: "iss.local",
		},
	}

	got, err := approval1PKIExpectedDNS(
		report,
	)
	if err != nil {
		t.Fatal(err)
	}

	if got != "AdminBox.iss.local" {
		t.Fatalf(
			"expected DNS=%q want=%q",
			got,
			"AdminBox.iss.local",
		)
	}
}

func TestEnsureApproval1PKIIdentityReusesDurableIdentity(
	t *testing.T,
) {
	t.Parallel()

	backend := &fakeApproval1PKIBackend{
		reusable: map[string]localMachinePKICertificate{
			fiTransportClientTemplateName: {
				CertificateSHA256: strings.Repeat(
					"A",
					64,
				),
			},
		},
	}

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiTransportClientTemplateName,
		TemplateOID:  "1.2.3.4",
	}

	result, err := ensureApproval1PKIIdentity(
		backend,
		contract,
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Disposition != "reused" {
		t.Fatalf(
			"disposition=%q want=reused",
			result.Disposition,
		)
	}

	wantEvents := []string{
		"reuse:" + fiTransportClientTemplateName,
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

func TestEnsureApproval1PKIIdentityRollsBackOwnedFailure(
	t *testing.T,
) {
	t.Parallel()

	mutation := pkiEnrollmentMutation{
		Certificate: localMachinePKICertificate{
			CertificateSHA256: strings.Repeat(
				"B",
				64,
			),
			TemplateOID: "1.2.3.4",
		},
		Owned: true,
	}

	backend := &fakeApproval1PKIBackend{
		enrollErrors: map[string]error{
			fiTransportClientTemplateName: errors.New(
				"synthetic verification failure",
			),
		},
		enrollMutations: map[string]pkiEnrollmentMutation{
			fiTransportClientTemplateName: mutation,
		},
	}

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiTransportClientTemplateName,
		TemplateOID:  "1.2.3.4",
	}

	_, err := ensureApproval1PKIIdentity(
		backend,
		contract,
	)
	if err == nil {
		t.Fatal(
			"owned failed enrollment unexpectedly succeeded",
		)
	}

	wantEvents := []string{
		"reuse:" + fiTransportClientTemplateName,
		"enroll:" + fiTransportClientTemplateName,
		"rollback:1.2.3.4",
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

func TestEnsureApproval1PKIIdentityDoesNotRollbackUnownedFailure(
	t *testing.T,
) {
	t.Parallel()

	backend := &fakeApproval1PKIBackend{
		enrollErrors: map[string]error{
			fiTransportClientTemplateName: errors.New(
				"synthetic CA denial",
			),
		},
		enrollMutations: map[string]pkiEnrollmentMutation{
			fiTransportClientTemplateName: {
				Owned: false,
			},
		},
	}

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiTransportClientTemplateName,
		TemplateOID:  "1.2.3.4",
	}

	_, err := ensureApproval1PKIIdentity(
		backend,
		contract,
	)
	if err == nil {
		t.Fatal(
			"unowned failed enrollment unexpectedly succeeded",
		)
	}

	for _, event := range backend.events {
		if strings.HasPrefix(
			event,
			"rollback:",
		) {
			t.Fatalf(
				"unowned enrollment was rolled back: %v",
				backend.events,
			)
		}
	}
}

func TestApproval1PKITransactionReusesBothIdentities(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval1PKITestState()

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

	result, err := executeApproval1PKIEnrollmentTransactionWithBackend(
		report,
		plan,
		PlanInputs{
			PKIChoice: "enroll",
		},
		backend,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Applied ||
		!result.Durable {
		t.Fatalf(
			"result=%+v",
			result,
		)
	}

	if !strings.Contains(
		result.Detail,
		"transport=reused:",
	) ||
		!strings.Contains(
			result.Detail,
			"batch=reused:",
		) {
		t.Fatalf(
			"unexpected detail=%q",
			result.Detail,
		)
	}

	for _, event := range backend.events {
		if strings.HasPrefix(
			event,
			"enroll:",
		) {
			t.Fatalf(
				"reusable identity unexpectedly caused enrollment: %v",
				backend.events,
			)
		}
	}
}

func TestApproval1PKITransactionRetainsTransportWhenBatchFails(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval1PKITestState()

	transportMutation := pkiEnrollmentMutation{
		Certificate: localMachinePKICertificate{
			CertificateSHA256: strings.Repeat(
				"C",
				64,
			),
			TemplateOID: "1.2.3.4",
		},
		Owned: true,
	}

	backend := &fakeApproval1PKIBackend{
		enrollErrors: map[string]error{
			fiBatchSigningTemplateName: errors.New(
				"synthetic batch enrollment failure",
			),
		},
		enrollMutations: map[string]pkiEnrollmentMutation{
			fiTransportClientTemplateName: transportMutation,
			fiBatchSigningTemplateName: {
				Owned: false,
			},
		},
		templateOIDs: map[string]string{
			fiTransportClientTemplateName: "1.2.3.4",
			fiBatchSigningTemplateName:    "1.2.3.5",
		},
	}

	result, err := executeApproval1PKIEnrollmentTransactionWithBackend(
		report,
		plan,
		PlanInputs{
			PKIChoice: "enroll",
		},
		backend,
	)

	if err == nil {
		t.Fatal(
			"batch failure unexpectedly succeeded",
		)
	}

	if !result.Applied ||
		!result.Durable {
		t.Fatalf(
			"durable transport state was not reported: %+v",
			result,
		)
	}

	if !strings.Contains(
		result.Detail,
		"transport=enrolled:",
	) {
		t.Fatalf(
			"transport durable state missing: %q",
			result.Detail,
		)
	}

	for _, event := range backend.events {
		if event == "rollback:1.2.3.4" {
			t.Fatalf(
				"durable transport identity was rolled back: %v",
				backend.events,
			)
		}
	}
}

func TestApproval1PKITransactionRejectsUnsupportedChoiceBeforeMutation(
	t *testing.T,
) {
	t.Parallel()

	report, plan := approval1PKITestState()
	backend := &fakeApproval1PKIBackend{}

	_, err := executeApproval1PKIEnrollmentTransactionWithBackend(
		report,
		plan,
		PlanInputs{
			PKIChoice: "create",
		},
		backend,
	)

	if err == nil {
		t.Fatal(
			"unsupported PKI choice unexpectedly succeeded",
		)
	}

	if len(backend.events) != 0 {
		t.Fatalf(
			"backend was touched before unsupported choice was rejected: %v",
			backend.events,
		)
	}
}

func approval1PKITestState() (
	Report,
	InstallPlan,
) {
	report := Report{
		Host: HostState{
			BuildNumber: 14393,
			Computer:    "AdminBox",
			DomainDNS:   "iss.local",
			Elevated:    true,
		},
		Join: DomainJoinState{
			Name:   "ISS",
			Status: "domain",
		},
	}

	plan := InstallPlan{
		Actions: []PlanAction{
			{
				Action:    planActionReconcile,
				Authority: "PKI",
				Detail:    "synthetic Approval 1 enrollment",
				Target:    "FI transport PKI",
			},
		},
	}

	return report, plan
}
