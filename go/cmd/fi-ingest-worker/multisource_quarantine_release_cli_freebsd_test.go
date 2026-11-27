// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"io"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
)

func m1ValidReleaseCLIArgs() []string {
	return []string{
		"-source-id", m1FS19,
		"-confirm-source-id", m1FS19,
		"-operator", "m1-test-operator",
		"-change-reference", "M1-TEST-RELEASE",
		"-reason", "Reviewed and resolved controlled conflict",
	}
}

func TestM1QuarantineReleaseCLIRequiresConfirmation(t *testing.T) {
	valid := m1ValidReleaseCLIArgs()

	options, err := m1ParseQuarantineReleaseOptions(
		valid, io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}

	if options.SourceID != m1FS19 ||
		options.ConfirmSourceID != m1FS19 ||
		options.Reference != "M1-TEST-RELEASE" {
		t.Fatalf("parsed release options mismatch: %+v", options)
	}

	cases := [][]string{
		{
			"-source-id", m1FS19,
			"-operator", "m1-test-operator",
			"-change-reference", "M1-TEST-RELEASE",
			"-reason", "Reviewed",
		},
		{
			"-source-id", m1FS19,
			"-confirm-source-id", m1FS22,
			"-operator", "m1-test-operator",
			"-change-reference", "M1-TEST-RELEASE",
			"-reason", "Reviewed",
		},
		{
			"-source-id", "../escape",
			"-confirm-source-id", "../escape",
			"-operator", "m1-test-operator",
			"-change-reference", "M1-TEST-RELEASE",
			"-reason", "Reviewed",
		},
		{
			"-source-id", m1FS19,
			"-confirm-source-id", m1FS19,
			"-operator", "m1-test-operator",
			"-change-reference", "M1-TEST-RELEASE",
			"-reason", "Reviewed",
			"-unexpected", "value",
		},
	}

	for index, args := range cases {
		if _, err := m1ParseQuarantineReleaseOptions(
			args, io.Discard,
		); err == nil {
			t.Errorf(
				"unsafe release command case %d accepted",
				index,
			)
		}
	}

	t.Log("PASS: Release requires exact deliberate confirmation")
	t.Log("PASS: Unsafe and unknown arguments rejected")
}

func TestM1QuarantineReleaseCLIRequiresEnabledSource(
	t *testing.T,
) {
	enabled := []string{m1FS19}

	if err := m1ValidateEnabledReleaseSource(
		m1FS19, enabled,
	); err != nil {
		t.Fatal(err)
	}

	if err := m1ValidateEnabledReleaseSource(
		m1FS22, enabled,
	); err == nil {
		t.Fatal("disabled or unregistered source accepted")
	}

	if err := m1ValidateEnabledReleaseSource(
		m1FS19, nil,
	); err == nil {
		t.Fatal("empty enrolled source registry accepted")
	}

	t.Log("PASS: Only exact enabled registry source can be released")
}

func TestM1QuarantineReleaseCLIWorkerPathAgreement(
	t *testing.T,
) {
	legacy := workerConfig{}

	if err := m1ValidateMaintenancePathAgreement(
		legacy,
	); err != nil {
		t.Fatal(err)
	}

	namespaced := m1QuarantineProductionConfiguration()
	// A legacy worker-owned lock must not be permitted in namespaced mode.
	if err := m1ValidateMaintenancePathAgreement(namespaced); err == nil {
		t.Fatal("namespaced worker accepted the legacy replaceable lock")
	}
	namespaced.LockFile = workerlock.ProtectedLockPath

	if err := m1ValidateMaintenancePathAgreement(
		namespaced,
	); err != nil {
		t.Fatal(err)
	}

	namespaced.LockFile = "/tmp/alternate.lock"

	if err := m1ValidateMaintenancePathAgreement(
		namespaced,
	); err == nil {
		t.Fatal("alternate worker lock accepted")
	}

	namespaced = m1QuarantineProductionConfiguration()
	namespaced.LockFile = workerlock.ProtectedLockPath
	namespaced.QuarantineRoot = "/tmp/other-quarantine"

	if err := m1ValidateMaintenancePathAgreement(
		namespaced,
	); err == nil {
		t.Fatal("alternate quarantine root accepted")
	}

	t.Log("PASS: Namespaced worker requires keeper-protected singleton path")
}
