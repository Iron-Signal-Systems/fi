// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import "testing"

func m1QuarantineProductionConfiguration() workerConfig {
	return workerConfig{
		SourceNamespaces: true,
		QuarantineRoot:   "/var/db/fi/ingest/quarantine",
		CustodyRoot:      "/var/db/fi/custody/generation",
		RecordedRoot:     "/var/db/fi/custody/recorded",
		ReadyRoot:        "/var/db/fi/custody/ready",
		LockFile:         "/var/run/fi/fi-ingest-worker.lock",
	}
}

func TestM1QuarantineConfigurationExplicitOptIn(t *testing.T) {
	legacy := workerConfig{}

	if err := m1ValidateQuarantineConfiguration(
		legacy,
	); err != nil {
		t.Fatalf("legacy default rejected: %v", err)
	}

	namespaced := m1QuarantineProductionConfiguration()

	if err := m1ValidateQuarantineConfiguration(
		namespaced,
	); err != nil {
		t.Fatalf("valid namespaced paths rejected: %v", err)
	}

	namespaced.QuarantineRoot = ""

	if err := m1ValidateQuarantineConfiguration(
		namespaced,
	); err == nil {
		t.Fatal("namespaces accepted without quarantine root")
	}

	legacy.QuarantineRoot = "/var/db/fi/ingest/quarantine"

	if err := m1ValidateQuarantineConfiguration(
		legacy,
	); err == nil {
		t.Fatal("legacy mode silently accepted quarantine option")
	}

	t.Log("PASS: Legacy default retained")
	t.Log("PASS: Namespaces require explicit durable quarantine")
}

func TestM1QuarantineConfigurationRejectsUnsafePaths(t *testing.T) {
	invalid := []string{
		"/",
		"relative/path",
		"/var/db/fi/ingest/../ingest/quarantine",
		"/tmp/fi-quarantine",
		"/var/tmp/fi-quarantine",
		"/var/run/fi-quarantine",
		"/run/fi-quarantine",
		"/var/db/fi/custody",
		"/var/db/fi/custody/recorded",
		"/var/db/fi/custody/recorded/sources",
		"/var/db/fi/custody/generation",
		"/var/db/fi/custody/ready",
	}

	for _, path := range invalid {
		config := m1QuarantineProductionConfiguration()
		config.QuarantineRoot = path

		if err := m1ValidateQuarantineConfiguration(
			config,
		); err == nil {
			t.Errorf(
				"unsafe quarantine root accepted: %q",
				path,
			)
		}
	}

	config := m1QuarantineProductionConfiguration()
	config.LockFile =
		"/var/db/fi/ingest/quarantine/worker.lock"

	if err := m1ValidateQuarantineConfiguration(
		config,
	); err == nil {
		t.Fatal("worker lock inside quarantine state accepted")
	}

	t.Log("PASS: Invalid, overlapping and ephemeral paths rejected")
}
