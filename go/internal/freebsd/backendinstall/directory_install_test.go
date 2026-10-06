// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDirectorySpecsMatchAcceptedContract(t *testing.T) {
	config := loadTestConfig(t)

	hostSpecs, jailSpecs, err := directorySpecs(config)
	if err != nil {
		t.Fatalf(
			"directorySpecs() error = %v",
			err,
		)
	}

	if len(hostSpecs) != 6 {
		t.Fatalf(
			"host directory count = %d, want 6",
			len(hostSpecs),
		)
	}

	if len(jailSpecs) != 3 {
		t.Fatalf(
			"jail directory set count = %d, want 3",
			len(jailSpecs),
		)
	}

	expectedModes := []os.FileMode{
		0o700,
		0o700,
		0o700,
		0o700,
		0o750,
		0o750,
	}

	for index, mode := range expectedModes {
		if hostSpecs[index].Mode != mode {
			t.Fatalf(
				"host mode %d = %#o, want %#o",
				index,
				hostSpecs[index].Mode,
				mode,
			)
		}
	}

	if hostSpecs[0].UID != 4100 ||
		hostSpecs[0].GID != 4100 ||
		hostSpecs[4].UID != 0 ||
		hostSpecs[4].GID != 4100 {
		t.Fatalf(
			"host ownership contract mismatch",
		)
	}

	if len(jailSpecs[0].Paths) != 8 ||
		len(jailSpecs[1].Paths) != 7 ||
		len(jailSpecs[2].Paths) != 3 {
		t.Fatalf(
			"unexpected jail directory path counts: %d %d %d",
			len(jailSpecs[0].Paths),
			len(jailSpecs[1].Paths),
			len(jailSpecs[2].Paths),
		)
	}

	receiverRun := jailSpecs[0].Paths[7]

	if receiverRun.Path !=
		"/usr/local/jails/containers/fi-receiver/var/run/fi" ||
		receiverRun.UID != 4100 ||
		receiverRun.GID != 4100 ||
		receiverRun.Mode != 0o700 {
		t.Fatalf(
			"receiver runtime directory = %#v",
			receiverRun,
		)
	}
}

func TestClassifyHostDirectoryAbsentWithoutMarker(t *testing.T) {
	root := t.TempDir()

	probe := validFakeHostProbe()

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:directory-schema zroot/test"] = fakeHostProbeResponse{
		output: "-\t-\n",
	}

	spec := hostDirectorySpec{
		Dataset: fiDatasetSpec{
			Target: "zroot/test",
		},
		GID:  uint64(os.Getgid()),
		Mode: 0o700,
		Name: "test",
		Path: root,
		UID:  uint64(os.Getuid()),
	}

	state := classifyHostDirectory(
		probe,
		spec,
	)

	if state != directoryAbsent {
		t.Fatalf(
			"state = %s, want %s",
			state,
			directoryAbsent,
		)
	}
}

func TestClassifyHostDirectoryMatchWithLocalMarker(t *testing.T) {
	root := t.TempDir()

	if err := os.Chmod(
		root,
		0o700,
	); err != nil {
		t.Fatalf(
			"Chmod() error = %v",
			err,
		)
	}

	probe := validFakeHostProbe()

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:directory-schema zroot/test"] = fakeHostProbeResponse{
		output: "1\tlocal\n",
	}

	info, err := os.Lstat(root)
	if err != nil {
		t.Fatalf(
			"Lstat() error = %v",
			err,
		)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal(
			"unexpected stat result type",
		)
	}

	spec := hostDirectorySpec{
		Dataset: fiDatasetSpec{
			Target: "zroot/test",
		},
		GID:  uint64(stat.Gid),
		Mode: 0o700,
		Name: "test",
		Path: root,
		UID:  uint64(stat.Uid),
	}

	state := classifyHostDirectory(
		probe,
		spec,
	)

	if state != directoryOwnedMatch {
		t.Fatalf(
			"state = %s, want %s",
			state,
			directoryOwnedMatch,
		)
	}
}

func TestClassifyJailDirectoriesRejectsPreexistingPathBeforeMarker(t *testing.T) {
	root := t.TempDir()

	target := filepath.Join(
		root,
		"var/db/fi",
	)

	if err := os.MkdirAll(
		target,
		0o755,
	); err != nil {
		t.Fatalf(
			"MkdirAll() error = %v",
			err,
		)
	}

	probe := validFakeHostProbe()

	probe.responses["zfs get -H -o value,source org.ironsignal.fi:directory-schema zroot/jail"] = fakeHostProbeResponse{
		output: "-\t-\n",
	}

	spec := jailDirectorySpec{
		Dataset: jailDatasetSpec{
			Target: "zroot/jail",
		},
		Name: "test jail",
		Paths: []managedDirectorySpec{
			{
				GID:  0,
				Mode: 0o755,
				Path: target,
				UID:  0,
			},
		},
		Root: root,
	}

	state := classifyJailDirectories(
		probe,
		spec,
	)

	if state != directoryForeignCollision {
		t.Fatalf(
			"state = %s, want %s",
			state,
			directoryForeignCollision,
		)
	}
}

func TestSystemDirectoryMutatorSetsExactMarker(t *testing.T) {
	var executable string
	var arguments []string

	mutator := systemDirectoryMutator{
		execute: func(
			path string,
			args ...string,
		) ([]byte, error) {
			executable = path
			arguments = append(
				[]string(nil),
				args...,
			)

			return nil, nil
		},
	}

	if err := mutator.SetMarker(
		"zroot/fi/ready",
	); err != nil {
		t.Fatalf(
			"SetMarker() error = %v",
			err,
		)
	}

	if executable != "/sbin/zfs" {
		t.Fatalf(
			"executable = %q",
			executable,
		)
	}

	expected := []string{
		"set",
		"org.ironsignal.fi:directory-schema=1",
		"zroot/fi/ready",
	}

	assertStringSliceEqual(
		t,
		arguments,
		expected,
	)
}
