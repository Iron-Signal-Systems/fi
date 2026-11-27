// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestSystemFIRootMutatorUsesExactCreateContract(t *testing.T) {
	var observedPath string
	var observedArgs []string

	mutator := systemFIRootMutator{
		lstat: func(_ string) (bool, error) {
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

	if err := mutator.CreateFIRoot("zroot/fi"); err != nil {
		t.Fatalf(
			"CreateFIRoot() error = %v",
			err,
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
		"-o", "org.ironsignal.fi:role=fi-root",
		"-o", "mountpoint=/var/db/fi",
		"-o", "canmount=on",
		"-o", "atime=off",
		"-o", "exec=off",
		"-o", "setuid=off",
		"-o", "devices=off",
		"zroot/fi",
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

func TestSystemFIRootMutatorReportsCreateFailure(t *testing.T) {
	mutator := systemFIRootMutator{
		lstat: func(_ string) (bool, error) {
			return false, nil
		},
		execute: func(
			_ string,
			_ ...string,
		) ([]byte, error) {
			return []byte(
				"cannot create 'zroot/fi': dataset already exists\n",
			), errors.New("exit status 1")
		},
	}

	err := mutator.CreateFIRoot("zroot/fi")
	if err == nil {
		t.Fatal(
			"CreateFIRoot() expected error",
		)
	}

	if !strings.Contains(
		err.Error(),
		"dataset already exists",
	) {
		t.Fatalf(
			"CreateFIRoot() error = %v",
			err,
		)
	}
}

func TestSystemFIRootMutatorRechecksMountpointBeforeCreate(t *testing.T) {
	executed := false

	mutator := systemFIRootMutator{
		lstat: func(path string) (bool, error) {
			if path != "/var/db/fi" {
				t.Fatalf(
					"Lstat path = %q, want %q",
					path,
					"/var/db/fi",
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

	err := mutator.CreateFIRoot("zroot/fi")
	if err == nil {
		t.Fatal(
			"CreateFIRoot() expected mountpoint collision",
		)
	}

	if !strings.Contains(
		err.Error(),
		"FOREIGN_COLLISION",
	) {
		t.Fatalf(
			"CreateFIRoot() error = %v",
			err,
		)
	}

	if executed {
		t.Fatal(
			"ZFS create executed after mountpoint collision",
		)
	}
}
