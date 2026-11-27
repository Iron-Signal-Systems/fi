// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInspectIssuingCAValidationInvalidIssuer(t *testing.T) {
	_, issuer := newIssuingCARelationshipCertificates(t)
	otherRoot, _ := newIssuingCARelationshipCertificatesWithName(
		t,
		"Other FI Root CA",
	)

	directory := t.TempDir()
	rootPath := filepath.Join(directory, "root.crt")
	issuerPath := filepath.Join(directory, "issuer.crt")

	writeIssuingCAValidationCertificate(t, rootPath, otherRoot)
	writeIssuingCAValidationCertificate(t, issuerPath, issuer)

	state := inspectIssuingCAValidationAt(
		issuerPath,
		rootPath,
		time.Now(),
	)

	if state.Valid {
		t.Fatal("ValidationState.Valid = true, want false")
	}

	if state.Detail == "" {
		t.Fatal("ValidationState.Detail is empty, want issuer error")
	}

	if state.Path != issuerPath {
		t.Fatalf(
			"ValidationState.Path = %q, want %q",
			state.Path,
			issuerPath,
		)
	}
}

func TestInspectIssuingCAValidationValid(t *testing.T) {
	root, issuer := newIssuingCARelationshipCertificates(t)

	directory := t.TempDir()
	rootPath := filepath.Join(directory, "root.crt")
	issuerPath := filepath.Join(directory, "issuer.crt")

	writeIssuingCAValidationCertificate(t, rootPath, root)
	writeIssuingCAValidationCertificate(t, issuerPath, issuer)

	state := inspectIssuingCAValidationAt(
		issuerPath,
		rootPath,
		time.Now(),
	)

	if !state.Valid {
		t.Fatalf(
			"ValidationState.Valid = false, want true: %s",
			state.Detail,
		)
	}

	if state.Detail != "" {
		t.Fatalf(
			"ValidationState.Detail = %q, want empty",
			state.Detail,
		)
	}

	if state.Path != issuerPath {
		t.Fatalf(
			"ValidationState.Path = %q, want %q",
			state.Path,
			issuerPath,
		)
	}
}

func writeIssuingCAValidationCertificate(
	t *testing.T,
	path string,
	certificate *x509.Certificate,
) {
	t.Helper()

	value := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}
