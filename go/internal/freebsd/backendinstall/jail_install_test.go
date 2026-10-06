// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApprovedFreeBSD151AMD64BaseArtifact(t *testing.T) {
	artifact, ok := freeBSDBaseArtifacts["amd64|15.1-RELEASE"]
	if !ok {
		t.Fatal(
			"approved 15.1 amd64 base artifact missing",
		)
	}

	if artifact.SHA256 !=
		"3768988b151c20f965679062b065c63a977d6bbb9f47fd83695ec2c40790c18f" {
		t.Fatalf(
			"approved base SHA-256 = %q",
			artifact.SHA256,
		)
	}
}

func TestJailRootSpecsMatchAcceptedContract(t *testing.T) {
	config := loadTestConfig(t)
	specs := jailRootSpecs(config)

	if len(specs) != 3 {
		t.Fatalf(
			"jail root count = %d, want 3",
			len(specs),
		)
	}

	expected := []struct {
		mountpoint string
		role       string
		target     string
	}{
		{
			mountpoint: "/usr/local/jails/containers/fi-receiver",
			role:       "jail-root-receiver",
			target:     "zroot/jails/containers/fi-receiver",
		},
		{
			mountpoint: "/usr/local/jails/containers/fi-ingest",
			role:       "jail-root-ingest",
			target:     "zroot/jails/containers/fi-ingest",
		},
		{
			mountpoint: "/usr/local/jails/containers/fi-sor-db",
			role:       "jail-root-sor-db",
			target:     "zroot/jails/containers/fi-sor-db",
		},
	}

	for index := range expected {
		if specs[index].Target != expected[index].target ||
			specs[index].Mountpoint != expected[index].mountpoint ||
			specs[index].Role != expected[index].role ||
			specs[index].Origin !=
				"zroot/jails/templates/15.1-RELEASE@base-test" ||
			specs[index].Readonly != "off" ||
			specs[index].Exec != "on" ||
			specs[index].Setuid != "on" ||
			specs[index].Devices != "on" {
			t.Fatalf(
				"jail root %d = %#v",
				index,
				specs[index],
			)
		}
	}
}

func TestJailSubstrateSpecsMatchAcceptedLayout(t *testing.T) {
	config := loadTestConfig(t)

	specs, err := jailSubstrateSpecs(
		config,
		"15.1-RELEASE",
	)
	if err != nil {
		t.Fatalf(
			"jailSubstrateSpecs() error = %v",
			err,
		)
	}

	if len(specs) != 4 {
		t.Fatalf(
			"substrate dataset count = %d, want 4",
			len(specs),
		)
	}

	expectedTargets := []string{
		"zroot/jails",
		"zroot/jails/containers",
		"zroot/jails/templates",
		"zroot/jails/templates/15.1-RELEASE",
	}

	expectedMountpoints := []string{
		"/usr/local/jails",
		"/usr/local/jails/containers",
		"/usr/local/jails/templates",
		"/usr/local/jails/templates/15.1-RELEASE",
	}

	for index := range expectedTargets {
		if specs[index].Target != expectedTargets[index] {
			t.Fatalf(
				"substrate target %d = %q, want %q",
				index,
				specs[index].Target,
				expectedTargets[index],
			)
		}

		if specs[index].Mountpoint !=
			expectedMountpoints[index] {
			t.Fatalf(
				"substrate mountpoint %d = %q, want %q",
				index,
				specs[index].Mountpoint,
				expectedMountpoints[index],
			)
		}
	}

	if specs[3].Readonly != "on" {
		t.Fatalf(
			"template readonly = %q, want on",
			specs[3].Readonly,
		)
	}
}

func TestPrepareExactDirectoryCreatesExactDirectory(t *testing.T) {
	root := t.TempDir()

	parent := filepath.Join(
		root,
		"usr",
		"local",
	)

	if err := os.MkdirAll(
		parent,
		0o755,
	); err != nil {
		t.Fatalf(
			"MkdirAll() error = %v",
			err,
		)
	}

	target := filepath.Join(
		parent,
		"etc",
	)

	uid := os.Getuid()
	gid := os.Getgid()

	if err := prepareExactDirectory(
		target,
		uid,
		gid,
		0o755,
	); err != nil {
		t.Fatalf(
			"prepareExactDirectory() error = %v",
			err,
		)
	}

	exact, err := validateExactDirectory(
		target,
		uint64(uid),
		uint64(gid),
		0o755,
	)
	if err != nil {
		t.Fatalf(
			"validateExactDirectory() error = %v",
			err,
		)
	}

	if !exact {
		t.Fatal(
			"new template directory did not match requested metadata",
		)
	}
}

func TestPrepareExactDirectoryDoesNotRepairExistingDrift(t *testing.T) {
	root := t.TempDir()

	target := filepath.Join(
		root,
		"etc",
	)

	if err := os.Mkdir(
		target,
		0o700,
	); err != nil {
		t.Fatalf(
			"Mkdir() error = %v",
			err,
		)
	}

	err := prepareExactDirectory(
		target,
		os.Getuid(),
		os.Getgid(),
		0o755,
	)

	if err == nil {
		t.Fatal(
			"prepareExactDirectory() accepted existing metadata drift",
		)
	}
}

func TestValidateTemplateFilesystemRejectsMissingRequiredDirectory(t *testing.T) {
	root := t.TempDir()

	if err := validateTemplateFilesystem(root); err == nil {
		t.Fatal(
			"validateTemplateFilesystem() accepted missing /usr/local/etc",
		)
	}
}

func TestSystemJailMutatorUpdatesDistsetTemplate(t *testing.T) {
	root := "/usr/local/jails/templates/15.1-RELEASE"

	var executable string
	var arguments []string

	mutator := systemJailMutator{
		execute: func(
			command string,
			args ...string,
		) ([]byte, error) {
			executable = command
			arguments = append(
				[]string(nil),
				args...,
			)

			return nil, nil
		},
	}

	if err := mutator.UpdateTemplateDistset(
		root,
		"15.1-RELEASE",
	); err != nil {
		t.Fatalf(
			"UpdateTemplateDistset() error = %v",
			err,
		)
	}

	if executable != "/usr/sbin/freebsd-update" {
		t.Fatalf(
			"executable = %q",
			executable,
		)
	}

	expected := []string{
		"-b",
		root,
		"--currently-running",
		"15.1-RELEASE",
		"--not-running-from-cron",
		"fetch",
		"install",
	}

	if len(arguments) != len(expected) {
		t.Fatalf(
			"argument count = %d, want %d: %v",
			len(arguments),
			len(expected),
			arguments,
		)
	}

	for index := range expected {
		if arguments[index] != expected[index] {
			t.Fatalf(
				"argument %d = %q, want %q",
				index,
				arguments[index],
				expected[index],
			)
		}
	}
}
