// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "testing"

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
