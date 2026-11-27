// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const spoolPolicyHelperEnvironment = "FI_TEST_SPOOL_POLICY_HELPER"

func TestConfiguredPolicyIsProcessAuthoritative(t *testing.T) {
	if os.Getenv(spoolPolicyHelperEnvironment) == "1" {
		runConfiguredPolicyHelper(t)
		return
	}

	dir := t.TempDir()

	command := exec.Command(
		os.Args[0],
		"-test.run=^TestConfiguredPolicyIsProcessAuthoritative$",
	)
	command.Env = append(
		os.Environ(),
		spoolPolicyHelperEnvironment+"=1",
		"FI_TEST_SPOOL_POLICY_DIR="+dir,
		"FI_SPOOL_DIR="+filepath.Join(dir, "environment-fallback"),
	)

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"configured spool policy subprocess failed: %v\n%s",
			err,
			output,
		)
	}
}

func runConfiguredPolicyHelper(t *testing.T) {
	dir := os.Getenv("FI_TEST_SPOOL_POLICY_DIR")
	if dir == "" {
		t.Fatal("FI_TEST_SPOOL_POLICY_DIR is required")
	}

	// Invalid policy must fail without consuming the one-time
	// process configuration slot.
	if err := ConfigurePolicy(Policy{
		Directory:        dir,
		MaxBatchRecords:  0,
		MaxRecordBytes:   4096,
		TargetBatchBytes: 2048,
	}); err == nil {
		t.Fatal("ConfigurePolicy(invalid) error = nil")
	}

	policy := Policy{
		Directory:        dir,
		MaxBatchRecords:  17,
		MaxRecordBytes:   4096,
		TargetBatchBytes: 2048,
	}

	if err := ConfigurePolicy(policy); err != nil {
		t.Fatalf("ConfigurePolicy() error = %v", err)
	}

	// Reapplying exactly the same startup policy is idempotent.
	if err := ConfigurePolicy(policy); err != nil {
		t.Fatalf("ConfigurePolicy(same policy) error = %v", err)
	}

	// A different policy must not replace process startup authority.
	conflicting := policy
	conflicting.MaxBatchRecords++

	if err := ConfigurePolicy(conflicting); err == nil {
		t.Fatal("ConfigurePolicy(conflicting policy) error = nil")
	} else if !strings.Contains(
		err.Error(),
		"already configured with different startup values",
	) {
		t.Fatalf("conflicting policy error = %v", err)
	}

	// Once configured, the process policy must outrank FI_SPOOL_DIR.
	defaultDir, err := DefaultDir()
	if err != nil {
		t.Fatalf("DefaultDir() error = %v", err)
	}
	if defaultDir != dir {
		t.Fatalf(
			"DefaultDir() = %q, want configured directory %q",
			defaultDir,
			dir,
		)
	}

	writer, err := NewWriter(
		dir,
		999,
		CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: strings.Repeat("a", 64),
		},
	)
	if err != nil {
		t.Fatalf("NewWriter(configured directory) error = %v", err)
	}
	defer writer.Close()

	if writer.batchSize != policy.MaxBatchRecords {
		t.Fatalf(
			"writer batch size = %d, want %d",
			writer.batchSize,
			policy.MaxBatchRecords,
		)
	}
	if writer.targetBatchBytes != policy.TargetBatchBytes {
		t.Fatalf(
			"writer target batch bytes = %d, want %d",
			writer.targetBatchBytes,
			policy.TargetBatchBytes,
		)
	}
	if writer.maxBatchBytes != policy.MaxRecordBytes {
		t.Fatalf(
			"writer max record bytes = %d, want %d",
			writer.maxBatchBytes,
			policy.MaxRecordBytes,
		)
	}

	_, err = NewWriter(
		filepath.Join(dir, "wrong-directory"),
		999,
		CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: strings.Repeat("b", 64),
		},
	)
	if err == nil {
		t.Fatal("NewWriter(wrong directory) error = nil")
	}
	if !strings.Contains(
		err.Error(),
		"does not match configured directory",
	) {
		t.Fatalf("wrong-directory error = %v", err)
	}
}
