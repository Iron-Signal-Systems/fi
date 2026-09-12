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

func TestInspectCRLValidationAtInvalidSignature(t *testing.T) {
	_, _, crl := newCRLValidationMaterial(t, "FI CRL Inspect CA")
	otherIssuer, _, _ := newCRLValidationMaterial(
		t,
		"FI CRL Inspect CA",
	)

	directory := t.TempDir()
	issuerPath := filepath.Join(directory, "issuer.crt")
	crlPath := filepath.Join(directory, "issuer.crl")

	writeCRLInspectionCertificate(t, issuerPath, otherIssuer)
	writeCRLInspectionCRL(t, crlPath, crl)

	state := inspectCRLValidationAt(
		crlPath,
		issuerPath,
		time.Now(),
	)

	if state.Valid {
		t.Fatal("ValidationState.Valid = true, want false")
	}

	if state.Detail == "" {
		t.Fatal("ValidationState.Detail is empty, want validation error")
	}

	if state.Path != crlPath {
		t.Fatalf(
			"ValidationState.Path = %q, want %q",
			state.Path,
			crlPath,
		)
	}
}

func TestInspectCRLValidationAtValid(t *testing.T) {
	issuer, _, crl := newCRLValidationMaterial(t, "FI CRL Inspect CA")

	directory := t.TempDir()
	issuerPath := filepath.Join(directory, "issuer.crt")
	crlPath := filepath.Join(directory, "issuer.crl")

	writeCRLInspectionCertificate(t, issuerPath, issuer)
	writeCRLInspectionCRL(t, crlPath, crl)

	state := inspectCRLValidationAt(
		crlPath,
		issuerPath,
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

	if state.Path != crlPath {
		t.Fatalf(
			"ValidationState.Path = %q, want %q",
			state.Path,
			crlPath,
		)
	}
}

func writeCRLInspectionCertificate(
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

func writeCRLInspectionCRL(
	t *testing.T,
	path string,
	crl *x509.RevocationList,
) {
	t.Helper()

	value := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crl.Raw,
	})

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}
}
