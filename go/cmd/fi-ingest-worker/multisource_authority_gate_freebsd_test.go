// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"os"
	"strings"
	"testing"
)

func TestM1AuthorityGatePreservesLegacyStartup(
	t *testing.T,
) {
	config := workerConfig{
		SourceNamespaces: false,
	}

	if err := m1ValidateQuarantineAuthorityReady(config); err != nil {
		t.Fatal(err)
	}

	t.Log("PASS: Existing flat-layout startup remains available")
}

func TestM1AuthorityGateBlocksNamespacedActivation(
	t *testing.T,
) {
	config := workerConfig{
		SourceNamespaces: true,
		QuarantineRoot:   "/var/db/fi/ingest/quarantine",
		LockFile:         "/var/run/fi/fi-ingest-worker.lock",
	}

	if err := m1ValidateQuarantineAuthorityReady(config); err == nil {
		t.Fatal("namespaced operation activated without keeper authority")
	}

	t.Log("PASS: Explicit namespace opt-in cannot bypass authority gate")
}

func TestM1AuthorityGateIsWiredToOperationalStartup(
	t *testing.T,
) {
	raw, err := os.ReadFile("main_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}

	source := string(raw)

	call := "if err := m1ValidateQuarantineAuthorityReady(config); err != nil"

	if strings.Count(source, call) != 1 {
		t.Fatal("operational worker startup lacks unique authority gate")
	}

	t.Log("PASS: Authority gate executes in production entry point")
}
