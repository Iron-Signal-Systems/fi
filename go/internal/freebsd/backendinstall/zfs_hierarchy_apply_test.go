// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
	"testing"
)

type fakeFIHierarchyMutator struct {
	afterCreate func(fiDatasetSpec)
	calls       []fiDatasetSpec
	err         error
	probe       *fakeHostProbe
}

func (mutator *fakeFIHierarchyMutator) CreateFIDataset(
	spec fiDatasetSpec,
) error {
	mutator.calls = append(
		mutator.calls,
		spec,
	)

	if mutator.err != nil {
		return mutator.err
	}

	if mutator.afterCreate != nil {
		mutator.afterCreate(spec)
		return nil
	}

	addExpectedFIDatasetToProbe(
		mutator.probe,
		spec,
	)

	return nil
}

func addExpectedFIDatasetToProbe(
	probe *fakeHostProbe,
	spec fiDatasetSpec,
) {
	key := "zfs list -H -t filesystem -o name"
	response := probe.responses[key]

	if response.output != "" &&
		!strings.HasSuffix(response.output, "\n") {
		response.output += "\n"
	}

	response.output += spec.Target + "\n"
	probe.responses[key] = response

	setExpectedFIDatasetResponses(
		probe,
		spec,
	)
}

func setAllExpectedFIDatasets(
	probe *fakeHostProbe,
	specs []fiDatasetSpec,
) {
	output := "zroot\nzroot/fi\n"

	for _, spec := range specs {
		output += spec.Target + "\n"

		setExpectedFIDatasetResponses(
			probe,
			spec,
		)
	}

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: output,
		}
}

func TestApplyFIHierarchyCreatesInAcceptedOrder(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()
	specs := fiHierarchySpecs(config)

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	mutator := &fakeFIHierarchyMutator{
		probe: &probe,
	}

	if err := applyFIHierarchy(
		config,
		&probe,
		mutator,
	); err != nil {
		t.Fatalf(
			"applyFIHierarchy() error = %v",
			err,
		)
	}

	if len(mutator.calls) != len(specs) {
		t.Fatalf(
			"create call count = %d, want %d",
			len(mutator.calls),
			len(specs),
		)
	}

	for index := range specs {
		if mutator.calls[index] != specs[index] {
			t.Fatalf(
				"create call %d = %#v, want %#v",
				index,
				mutator.calls[index],
				specs[index],
			)
		}
	}

	for _, spec := range specs {
		state := inspectFIDatasetState(
			&probe,
			spec,
		)

		if state != fiDatasetOwnedMatch {
			t.Fatalf(
				"post-apply state for %s = %s, want %s",
				spec.Target,
				state,
				fiDatasetOwnedMatch,
			)
		}
	}
}

func TestApplyFIHierarchyExactSecondApplyIsNoOp(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()
	specs := fiHierarchySpecs(config)

	setAllExpectedFIDatasets(
		&probe,
		specs,
	)

	mutator := &fakeFIHierarchyMutator{
		probe: &probe,
	}

	if err := applyFIHierarchy(
		config,
		&probe,
		mutator,
	); err != nil {
		t.Fatalf(
			"applyFIHierarchy() error = %v",
			err,
		)
	}

	if len(mutator.calls) != 0 {
		t.Fatalf(
			"exact apply made %d create calls, want 0",
			len(mutator.calls),
		)
	}
}

func TestApplyFIHierarchyReinspectsBeforeEachCreate(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()
	specs := fiHierarchySpecs(config)

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	mutator := &fakeFIHierarchyMutator{
		probe: &probe,
	}

	mutator.afterCreate = func(spec fiDatasetSpec) {
		addExpectedFIDatasetToProbe(
			&probe,
			spec,
		)

		if spec.Target == specs[0].Target {
			key := "zfs list -H -t filesystem -o name"
			response := probe.responses[key]
			response.output += specs[1].Target + "\n"
			probe.responses[key] = response

			probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed "+
				specs[1].Target] = fakeHostProbeResponse{
				output: "-\t-\n",
			}
		}
	}

	err := applyFIHierarchy(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIHierarchy() unexpectedly accepted resource changed after precheck",
		)
	}

	if !strings.Contains(
		err.Error(),
		"FOREIGN_COLLISION",
	) {
		t.Fatalf(
			"applyFIHierarchy() error = %v, want FOREIGN_COLLISION",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		specs[1].Target,
	) {
		t.Fatalf(
			"applyFIHierarchy() error = %v, want target %s",
			err,
			specs[1].Target,
		)
	}

	if len(mutator.calls) != 1 {
		t.Fatalf(
			"create call count = %d, want 1",
			len(mutator.calls),
		)
	}
}

func TestApplyFIHierarchyRequiresPostCreateMatch(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	mutator := &fakeFIHierarchyMutator{
		probe: &probe,
	}

	mutator.afterCreate = func(spec fiDatasetSpec) {
		key := "zfs list -H -t filesystem -o name"
		response := probe.responses[key]
		response.output += spec.Target + "\n"
		probe.responses[key] = response

		probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed "+
			spec.Target] = fakeHostProbeResponse{
			output: "-\t-\n",
		}
	}

	err := applyFIHierarchy(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIHierarchy() unexpectedly accepted failed post-create verification",
		)
	}

	if !strings.Contains(
		err.Error(),
		"did not verify as OWNED_MATCH",
	) {
		t.Fatalf(
			"applyFIHierarchy() error = %v, want post-create verification failure",
			err,
		)
	}

	if len(mutator.calls) != 1 {
		t.Fatalf(
			"create call count = %d, want 1",
			len(mutator.calls),
		)
	}
}

func TestApplyFIHierarchyReportsCreateFailure(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	mutator := &fakeFIHierarchyMutator{
		err:   fmt.Errorf("create failed"),
		probe: &probe,
	}

	err := applyFIHierarchy(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIHierarchy() unexpectedly accepted create failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"create failed",
	) {
		t.Fatalf(
			"applyFIHierarchy() error = %v, want create failure",
			err,
		)
	}

	if len(mutator.calls) != 1 {
		t.Fatalf(
			"create call count = %d, want 1",
			len(mutator.calls),
		)
	}
}
