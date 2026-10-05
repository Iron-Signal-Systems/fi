// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestSystemFIHierarchyMutatorUsesExactCreateContract(t *testing.T) {
	config := loadTestConfig(t)
	spec := fiHierarchySpecs(config)[1]

	var observedPath string
	var observedArgs []string
	var observedLstat string

	mutator := systemFIHierarchyMutator{
		lstat: func(path string) (bool, error) {
			observedLstat = path
			return false, nil
		},
		execute: func(
			path string,
			args ...string,
		) ([]byte, error) {
			observedPath = path
			observedArgs = append(
				[]string(nil),
				args...,
			)

			return nil, nil
		},
	}

	if err := mutator.CreateFIDataset(spec); err != nil {
		t.Fatalf(
			"CreateFIDataset() error = %v",
			err,
		)
	}

	if observedLstat != "/var/db/fi/custody/generation" {
		t.Fatalf(
			"Lstat path = %q, want %q",
			observedLstat,
			"/var/db/fi/custody/generation",
		)
	}

	if observedPath != "/sbin/zfs" {
		t.Fatalf(
			"command path = %q, want %q",
			observedPath,
			"/sbin/zfs",
		)
	}

	expectedArgs := []string{
		"create",
		"-o", "org.ironsignal.fi:managed=1",
		"-o", "org.ironsignal.fi:schema=1",
		"-o", "org.ironsignal.fi:role=custody-generation",
		"-o", "mountpoint=/var/db/fi/custody/generation",
		"-o", "canmount=on",
		"-o", "atime=off",
		"-o", "exec=off",
		"-o", "setuid=off",
		"-o", "devices=off",
		"zroot/fi/custody/generation",
	}

	if len(observedArgs) != len(expectedArgs) {
		t.Fatalf(
			"argument count = %d, want %d\nobserved=%v",
			len(observedArgs),
			len(expectedArgs),
			observedArgs,
		)
	}

	for index := range expectedArgs {
		if observedArgs[index] != expectedArgs[index] {
			t.Fatalf(
				"argument %d = %q, want %q",
				index,
				observedArgs[index],
				expectedArgs[index],
			)
		}
	}
}

func TestSystemFIHierarchyMutatorCreatesParentWithoutPathInspection(t *testing.T) {
	config := loadTestConfig(t)
	spec := fiHierarchySpecs(config)[0]

	lstatCalled := false
	var observedArgs []string

	mutator := systemFIHierarchyMutator{
		lstat: func(_ string) (bool, error) {
			lstatCalled = true
			return false, nil
		},
		execute: func(
			_ string,
			args ...string,
		) ([]byte, error) {
			observedArgs = append(
				[]string(nil),
				args...,
			)

			return nil, nil
		},
	}

	if err := mutator.CreateFIDataset(spec); err != nil {
		t.Fatalf(
			"CreateFIDataset() error = %v",
			err,
		)
	}

	if lstatCalled {
		t.Fatal(
			"parent dataset with mountpoint=none unexpectedly inspected filesystem path",
		)
	}

	expectedArgs := []string{
		"create",
		"-o", "org.ironsignal.fi:managed=1",
		"-o", "org.ironsignal.fi:schema=1",
		"-o", "org.ironsignal.fi:role=custody-parent",
		"-o", "mountpoint=none",
		"-o", "canmount=off",
		"-o", "atime=off",
		"-o", "exec=off",
		"-o", "setuid=off",
		"-o", "devices=off",
		"zroot/fi/custody",
	}

	if len(observedArgs) != len(expectedArgs) {
		t.Fatalf(
			"argument count = %d, want %d\nobserved=%v",
			len(observedArgs),
			len(expectedArgs),
			observedArgs,
		)
	}

	for index := range expectedArgs {
		if observedArgs[index] != expectedArgs[index] {
			t.Fatalf(
				"argument %d = %q, want %q",
				index,
				observedArgs[index],
				expectedArgs[index],
			)
		}
	}
}

func TestSystemFIHierarchyMutatorRechecksMountpointBeforeCreate(t *testing.T) {
	config := loadTestConfig(t)
	spec := fiHierarchySpecs(config)[1]

	executed := false

	mutator := systemFIHierarchyMutator{
		lstat: func(path string) (bool, error) {
			if path != spec.Mountpoint {
				t.Fatalf(
					"Lstat path = %q, want %q",
					path,
					spec.Mountpoint,
				)
			}

			return true, nil
		},
		execute: func(
			_ string,
			_ ...string,
		) ([]byte, error) {
			executed = true
			return nil, nil
		},
	}

	err := mutator.CreateFIDataset(spec)
	if err == nil {
		t.Fatal(
			"CreateFIDataset() expected mountpoint collision",
		)
	}

	if !strings.Contains(
		err.Error(),
		"FOREIGN_COLLISION",
	) {
		t.Fatalf(
			"CreateFIDataset() error = %v",
			err,
		)
	}

	if executed {
		t.Fatal(
			"ZFS create executed after mountpoint collision",
		)
	}
}

func TestSystemFIHierarchyMutatorReportsMountpointInspectionFailure(t *testing.T) {
	config := loadTestConfig(t)
	spec := fiHierarchySpecs(config)[1]

	executed := false

	mutator := systemFIHierarchyMutator{
		lstat: func(_ string) (bool, error) {
			return false, errors.New("lstat failed")
		},
		execute: func(
			_ string,
			_ ...string,
		) ([]byte, error) {
			executed = true
			return nil, nil
		},
	}

	err := mutator.CreateFIDataset(spec)
	if err == nil {
		t.Fatal(
			"CreateFIDataset() expected mountpoint inspection failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"lstat failed",
	) {
		t.Fatalf(
			"CreateFIDataset() error = %v",
			err,
		)
	}

	if executed {
		t.Fatal(
			"ZFS create executed after mountpoint inspection failure",
		)
	}
}

func TestSystemFIHierarchyMutatorReportsCreateFailure(t *testing.T) {
	config := loadTestConfig(t)
	spec := fiHierarchySpecs(config)[1]

	mutator := systemFIHierarchyMutator{
		lstat: func(_ string) (bool, error) {
			return false, nil
		},
		execute: func(
			_ string,
			_ ...string,
		) ([]byte, error) {
			return []byte(
				"cannot create dataset\n",
			), errors.New("exit status 1")
		},
	}

	err := mutator.CreateFIDataset(spec)
	if err == nil {
		t.Fatal(
			"CreateFIDataset() expected create failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"cannot create dataset",
	) {
		t.Fatalf(
			"CreateFIDataset() error = %v",
			err,
		)
	}
}
