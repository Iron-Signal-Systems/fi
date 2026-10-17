// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

type fakeApproval1ControllerBackendWithoutHandoff struct {
	*fakeApproval1ControllerBackend
}

func (backend *fakeApproval1ControllerBackend) PKIHandoff() approval1PKIHandoff {
	if backend == nil {
		return approval1PKIHandoff{}
	}

	return approval1CompleteTestHandoff()
}

func (
	backend *fakeApproval1ControllerBackendWithoutHandoff,
) PKIHandoff() approval1PKIHandoff {
	return approval1PKIHandoff{}
}

func TestApproval1ControllerCarriesExactTypedPKIHandoff(
	t *testing.T,
) {
	t.Parallel()

	before, beforePlan := approval1ControllerTestState(
		t,
	)

	post := before

	postPlan := approval1ControllerPostPlan(
		beforePlan,
	)

	approval := approvalBoundaryTestState(
		t,
		before,
		beforePlan,
		approvalBoundaryInfrastructure,
	)

	backend := &fakeApproval1ControllerBackend{
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": true,
		},

		plans: []InstallPlan{
			beforePlan,
			postPlan,
		},

		rediscoveries: []Report{
			before,
			post,
		},
	}

	var output bytes.Buffer

	result, err := executeApproval1ControllerWithBackend(
		&output,
		before,
		beforePlan,
		PlanInputs{},
		approval,
		backend,
	)
	if err != nil {
		t.Fatal(err)
	}

	want := approval1CompleteTestHandoff()

	if !reflect.DeepEqual(
		result.PKI.Handoff,
		want,
	) {
		t.Fatalf(
			"typed Approval 1 PKI handoff=%+v want=%+v",
			result.PKI.Handoff,
			want,
		)
	}

	if err := result.PKI.Handoff.validate(); err != nil {
		t.Fatalf(
			"controller returned invalid typed PKI handoff: %v",
			err,
		)
	}

	if !result.Approval2Required {
		t.Fatal(
			"Approval 2 was not required after successful Approval 1",
		)
	}

	if strings.TrimSpace(
		result.Approval2SHA256,
	) == "" {
		t.Fatal(
			"Approval 2 digest was not sealed after typed PKI handoff",
		)
	}
}

func TestApproval1ControllerRejectsDurablePKIWithoutTypedHandoff(
	t *testing.T,
) {
	t.Parallel()

	before, beforePlan := approval1ControllerTestState(
		t,
	)

	approval := approvalBoundaryTestState(
		t,
		before,
		beforePlan,
		approvalBoundaryInfrastructure,
	)

	base := &fakeApproval1ControllerBackend{
		created: map[string]bool{
			"gFI-USN-ADMINBOX$": true,
			"gFI-OBJ-ADMINBOX$": true,
		},

		plans: []InstallPlan{
			beforePlan,
		},

		rediscoveries: []Report{
			before,
		},
	}

	backend :=
		&fakeApproval1ControllerBackendWithoutHandoff{
			fakeApproval1ControllerBackend: base,
		}

	var output bytes.Buffer

	result, err := executeApproval1ControllerWithBackend(
		&output,
		before,
		beforePlan,
		PlanInputs{},
		approval,
		backend,
	)
	if err == nil {
		t.Fatal(
			"durable PKI success without a typed handoff unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"complete typed PKI handoff",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	if result.PKI.Handoff.complete() {
		t.Fatal(
			"controller returned a complete PKI handoff after the backend supplied none",
		)
	}

	if !result.PKI.Durable {
		t.Fatal(
			"durable PKI identity state was lost during handoff rejection",
		)
	}

	if !result.DurablePKIRetained {
		t.Fatal(
			"durable PKI identity was not explicitly retained after handoff rejection",
		)
	}

	if !result.RollbackAttempted {
		t.Fatal(
			"transaction-created AD rollback was not attempted after handoff rejection",
		)
	}

	joined := strings.Join(
		base.events,
		"|",
	)

	expectedTail :=
		"apply:pki" +
			"|rollback-ad:gFI-OBJ-ADMINBOX$" +
			"|rollback-ad:gFI-USN-ADMINBOX$"

	if !strings.Contains(
		joined,
		expectedTail,
	) {
		t.Fatalf(
			"handoff rejection rollback order incorrect: %v",
			base.events,
		)
	}

	if !strings.Contains(
		output.String(),
		"PKI DURABLE: retain verified FI certificate/key identity",
	) {
		t.Fatalf(
			"durable PKI retention was not reported:\n%s",
			output.String(),
		)
	}
}
