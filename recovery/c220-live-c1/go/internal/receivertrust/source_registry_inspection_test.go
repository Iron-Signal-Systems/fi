// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectSourceRegistryValidationAt(t *testing.T) {
	transportIssuer, batchIssuer := newSourceRegistryIssuers(t)
	directory := t.TempDir()
	registryPath := filepath.Join(directory, "sources")
	transportIssuerPath := filepath.Join(directory, "transport-ca.crt")
	batchIssuerPath := filepath.Join(directory, "batch-ca.crt")

	if err := os.Mkdir(registryPath, 0700); err != nil {
		t.Fatalf("os.Mkdir() error = %v", err)
	}

	writeIssuingCAValidationCertificate(
		t,
		transportIssuerPath,
		transportIssuer,
	)
	writeIssuingCAValidationCertificate(
		t,
		batchIssuerPath,
		batchIssuer,
	)
	writeSourceRegistryConfig(
		t,
		registryPath,
		"iss-test-01.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	state := inspectSourceRegistryValidationAt(
		registryPath,
		transportIssuerPath,
		batchIssuerPath,
	)

	if !state.Valid {
		t.Fatalf(
			"ValidationState.Valid = false, want true: %s",
			state.Detail,
		)
	}

	if state.Path != registryPath {
		t.Fatalf(
			"ValidationState.Path = %q, want %q",
			state.Path,
			registryPath,
		)
	}
}
