// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
	"testing"
)

type fakeFIRootMutator struct {
	afterCreate func()
	calls       []string
	err         error
}

func (mutator *fakeFIRootMutator) CreateFIRoot(target string) error {
	mutator.calls = append(
		mutator.calls,
		target,
	)

	if mutator.err != nil {
		return mutator.err
	}

	if mutator.afterCreate != nil {
		mutator.afterCreate()
	}

	return nil
}

func TestApplyFIRootNoOpWhenRootMatches(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	setExpectedFIRootContractResponses(&probe)

	mutator := &fakeFIRootMutator{}

	if err := applyFIRoot(
		config,
		&probe,
		mutator,
	); err != nil {
		t.Fatalf(
			"applyFIRoot() error = %v",
			err,
		)
	}

	if len(mutator.calls) != 0 {
		t.Fatalf(
			"CreateFIRoot() calls = %v, want none",
			mutator.calls,
		)
	}
}

func TestApplyFIRootBlocksExistingForeignRoot(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\nzroot/fi\n",
		}

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:managed zroot/fi"] =
		fakeHostProbeResponse{
			output: "-\t-\n",
		}

	mutator := &fakeFIRootMutator{}

	err := applyFIRoot(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIRoot() expected blocked-root error",
		)
	}

	if len(mutator.calls) != 0 {
		t.Fatalf(
			"CreateFIRoot() calls = %v, want none",
			mutator.calls,
		)
	}
}

func TestApplyFIRootBlocksMountpointCollision(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	probe.paths["/var/db/fi"] = fakeHostPathResponse{
		exists: true,
	}

	mutator := &fakeFIRootMutator{}

	err := applyFIRoot(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIRoot() expected mountpoint collision",
		)
	}

	if len(mutator.calls) != 0 {
		t.Fatalf(
			"CreateFIRoot() calls = %v, want none",
			mutator.calls,
		)
	}
}

func TestApplyFIRootCreatesAndVerifiesRoot(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	mutator := &fakeFIRootMutator{
		afterCreate: func() {
			probe.responses["zfs list -H -t filesystem -o name"] =
				fakeHostProbeResponse{
					output: "zroot\nzroot/fi\n",
				}

			setExpectedFIRootContractResponses(&probe)
		},
	}

	if err := applyFIRoot(
		config,
		&probe,
		mutator,
	); err != nil {
		t.Fatalf(
			"applyFIRoot() error = %v",
			err,
		)
	}

	if len(mutator.calls) != 1 {
		t.Fatalf(
			"CreateFIRoot() call count = %d, want 1",
			len(mutator.calls),
		)
	}

	if mutator.calls[0] != "zroot/fi" {
		t.Fatalf(
			"CreateFIRoot() target = %q, want %q",
			mutator.calls[0],
			"zroot/fi",
		)
	}
}

func TestApplyFIRootFailsWhenCreatedRootDoesNotVerify(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	mutator := &fakeFIRootMutator{
		afterCreate: func() {
			probe.responses["zfs list -H -t filesystem -o name"] =
				fakeHostProbeResponse{
					output: "zroot\nzroot/fi\n",
				}

			setExpectedFIRootContractResponses(&probe)

			probe.responses["zfs get -H -o value,source org.ironsignal.fi:role zroot/fi"] =
				fakeHostProbeResponse{
					output: "wrong-role\tlocal\n",
				}
		},
	}

	err := applyFIRoot(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIRoot() expected post-create verification error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"did not verify",
	) {
		t.Fatalf(
			"applyFIRoot() error = %v",
			err,
		)
	}

	if len(mutator.calls) != 1 {
		t.Fatalf(
			"CreateFIRoot() call count = %d, want 1",
			len(mutator.calls),
		)
	}
}

func TestFakeFIRootMutatorReturnsError(t *testing.T) {
	expected := fmt.Errorf("create failed")

	mutator := &fakeFIRootMutator{
		err: expected,
	}

	if err := mutator.CreateFIRoot("zroot/fi"); err == nil {
		t.Fatal("CreateFIRoot() expected error")
	}
}

func TestApplyFIRootBlocksInitialFilesystemEnumerationFailure(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			err: fmt.Errorf("enumeration failed"),
		}

	mutator := &fakeFIRootMutator{}

	err := applyFIRoot(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIRoot() expected initial enumeration error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"enumerate ZFS filesystems before FI root apply",
	) {
		t.Fatalf(
			"applyFIRoot() error = %v",
			err,
		)
	}

	if len(mutator.calls) != 0 {
		t.Fatalf(
			"CreateFIRoot() calls = %v, want none",
			mutator.calls,
		)
	}
}

func TestApplyFIRootBlocksMountpointInspectionFailure(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	probe.paths["/var/db/fi"] = fakeHostPathResponse{
		err: fmt.Errorf("lstat failed"),
	}

	mutator := &fakeFIRootMutator{}

	err := applyFIRoot(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIRoot() expected mountpoint inspection error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"inspect FI ZFS root mountpoint path",
	) {
		t.Fatalf(
			"applyFIRoot() error = %v",
			err,
		)
	}

	if len(mutator.calls) != 0 {
		t.Fatalf(
			"CreateFIRoot() calls = %v, want none",
			mutator.calls,
		)
	}
}

func TestApplyFIRootReportsCreateFailure(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	mutator := &fakeFIRootMutator{
		err: fmt.Errorf("create failed"),
	}

	err := applyFIRoot(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIRoot() expected create error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"create FI ZFS root zroot/fi",
	) {
		t.Fatalf(
			"applyFIRoot() error = %v",
			err,
		)
	}

	if len(mutator.calls) != 1 {
		t.Fatalf(
			"CreateFIRoot() call count = %d, want 1",
			len(mutator.calls),
		)
	}
}

func TestApplyFIRootFailsPostCreateFilesystemEnumeration(t *testing.T) {
	config := loadTestConfig(t)
	probe := validFakeHostProbe()

	probe.responses["zfs list -H -t filesystem -o name"] =
		fakeHostProbeResponse{
			output: "zroot\n",
		}

	mutator := &fakeFIRootMutator{
		afterCreate: func() {
			probe.responses["zfs list -H -t filesystem -o name"] =
				fakeHostProbeResponse{
					err: fmt.Errorf("post-create enumeration failed"),
				}
		},
	}

	err := applyFIRoot(
		config,
		&probe,
		mutator,
	)
	if err == nil {
		t.Fatal(
			"applyFIRoot() expected post-create enumeration error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"enumerate ZFS filesystems after FI root creation",
	) {
		t.Fatalf(
			"applyFIRoot() error = %v",
			err,
		)
	}

	if len(mutator.calls) != 1 {
		t.Fatalf(
			"CreateFIRoot() call count = %d, want 1",
			len(mutator.calls),
		)
	}
}
