// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func m1QuarantineTestConfig(root string) workerConfig {
	return workerConfig{
		SourceNamespaces: true,
		QuarantineRoot:   root,
		SourceIDs:        []string{m1FS19, m1FS22},
		RepairInterval:   time.Minute,
	}
}

func TestM1QuarantineRestoredInNewProcess(t *testing.T) {
	root := m1PrivateQuarantineTestDir(t)
	config := m1QuarantineTestConfig(root)

	states, err := newSourceSessionStates(config)
	if err != nil {
		t.Fatal(err)
	}

	if err := m1RestoreSourceQuarantineStates(
		states, m1QuarantineStore{Root: root},
	); err != nil {
		t.Fatal(err)
	}

	conflict := &sourceReconcileConflictError{
		SourceID:     m1FS19,
		GenerationID: "m1-persisted-conflict",
		Detail:       "controlled relational conflict",
	}

	if err := quarantineSourceConflict(
		&states[0], conflict,
	); err != nil {
		t.Fatal(err)
	}

	if !states[0].Quarantined || states[1].Quarantined {
		t.Fatal("source quarantine isolation failed")
	}

	// Spawn a second operating-system process, not merely
	// another store value inside this process.
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestM1QuarantineChildRestoresState$",
		"-test.v",
	)

	command.Env = append(
		os.Environ(),
		"FI_M1_QUARANTINE_CHILD=1",
		"FI_M1_QUARANTINE_CHILD_ROOT="+root,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"worker quarantine restart test failed: %v\n%s",
			err, output,
		)
	}

	if !strings.Contains(
		string(output),
		"PASS: Child process restored source isolation",
	) {
		t.Fatalf(
			"child process did not confirm restoration:\n%s",
			output,
		)
	}

	t.Log("PASS: FS2019 durable quarantine survived separate process")
	t.Log("PASS: FS22 remained schedulable")
}

func TestM1QuarantineChildRestoresState(t *testing.T) {
	if os.Getenv("FI_M1_QUARANTINE_CHILD") != "1" {
		t.Skip("child process only")
	}

	root := os.Getenv("FI_M1_QUARANTINE_CHILD_ROOT")
	config := m1QuarantineTestConfig(root)

	states, err := newSourceSessionStates(config)
	if err != nil {
		t.Fatal(err)
	}

	if err := m1RestoreSourceQuarantineStates(
		states, m1QuarantineStore{Root: root},
	); err != nil {
		t.Fatal(err)
	}

	if !states[0].Quarantined || states[1].Quarantined {
		t.Fatal("restored quarantine identity mismatch")
	}

	calledBad := false

	err = runScheduledSourcePass(
		&states[0],
		func(*sourceSessionState) error {
			calledBad = true
			return nil
		},
	)
	if err != nil || calledBad {
		t.Fatal("quarantined FS2019 was scheduled")
	}

	calledHealthy := false

	err = runScheduledSourcePass(
		&states[1],
		func(*sourceSessionState) error {
			calledHealthy = true
			return nil
		},
	)
	if err != nil || !calledHealthy {
		t.Fatal("healthy FS22 was not scheduled")
	}

	t.Log("PASS: Child process restored source isolation")
}

func TestM1QuarantinePersistenceFailureStopsSourcePass(
	t *testing.T,
) {
	root := m1PrivateQuarantineTestDir(t)
	config := m1QuarantineTestConfig(root)

	states, err := newSourceSessionStates(config)
	if err != nil {
		t.Fatal(err)
	}

	if err := m1RestoreSourceQuarantineStates(
		states, m1QuarantineStore{Root: root},
	); err != nil {
		t.Fatal(err)
	}

	// The store becomes unsafe after successful initialization.
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}

	conflict := &sourceReconcileConflictError{
		SourceID:     m1FS19,
		GenerationID: "m1-storage-failure",
		Detail:       "controlled persistence failure",
	}

	err = runScheduledSourcePass(
		&states[0],
		func(*sourceSessionState) error {
			return conflict
		},
	)

	if err == nil ||
		!strings.Contains(err.Error(), "persist FI source") {
		t.Fatalf(
			"quarantine persistence failure was suppressed: %v",
			err,
		)
	}

	if states[0].Quarantined {
		t.Fatal(
			"worker marked source quarantined without durable marker",
		)
	}

	if _, statErr := os.Stat(
		filepath.Join(root, m1FS19+".json"),
	); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf(
			"unexpected quarantine marker after failed write: %v",
			statErr,
		)
	}

	t.Log("PASS: Persistence failure propagates to worker")
	t.Log("PASS: Source was not marked quarantined without storage")
}

func TestM1QuarantineStartupFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	config := m1QuarantineTestConfig(root)

	states, err := newSourceSessionStates(config)
	if err != nil {
		t.Fatal(err)
	}

	if err := m1RestoreSourceQuarantineStates(
		states, m1QuarantineStore{Root: root},
	); err == nil {
		t.Fatal("missing durable store accepted at startup")
	}

	if states[0].Quarantined || states[1].Quarantined {
		t.Fatal("startup failure unexpectedly modified source state")
	}

	t.Log("PASS: Missing durable store stops startup")
}
