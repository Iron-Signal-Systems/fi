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

func TestInspectReceiverRevocationValidationAt(t *testing.T) {
	root, issuer, leaf, issuerKey, _ := newReceiverIdentityMaterial(t)
	directory := t.TempDir()

	certificatePath := filepath.Join(directory, "receiver-fullchain.pem")
	issuerPath := filepath.Join(directory, "transport-ca.pem")
	crlPath := filepath.Join(directory, "transport-ca.crl.pem")

	writeReceiverCertificateChain(
		t,
		certificatePath,
		leaf,
		issuer,
		root,
	)
	writeReceiverCertificateChain(t, issuerPath, issuer)

	validCRL := newReceiverRevocationTestCRL(
		t,
		issuer,
		issuerKey,
		nil,
	)
	writeReceiverRevocationCRL(t, crlPath, validCRL)

	state := inspectReceiverRevocationValidationAt(
		certificatePath,
		issuerPath,
		crlPath,
		time.Now(),
	)
	if !state.Valid {
		t.Fatalf(
			"ValidationState.Valid = false, want true: %s",
			state.Detail,
		)
	}

	revokedCRL := newReceiverRevocationTestCRL(
		t,
		issuer,
		issuerKey,
		[]x509.RevocationListEntry{
			{
				SerialNumber:   leaf.SerialNumber,
				RevocationTime: time.Now().Add(-time.Minute),
			},
		},
	)
	writeReceiverRevocationCRL(t, crlPath, revokedCRL)

	state = inspectReceiverRevocationValidationAt(
		certificatePath,
		issuerPath,
		crlPath,
		time.Now(),
	)
	if state.Valid {
		t.Fatal("ValidationState.Valid = true, want false")
	}
}

func writeReceiverRevocationCRL(
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
