// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectRootCAValidationInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.crt")

	if err := os.WriteFile(path, []byte("not PEM"), 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	state := inspectRootCAValidation(path)

	if state.Valid {
		t.Fatal("ValidationState.Valid = true, want false")
	}

	if state.Detail == "" {
		t.Fatal("ValidationState.Detail is empty, want error detail")
	}

	if state.Path != path {
		t.Fatalf(
			"ValidationState.Path = %q, want %q",
			state.Path,
			path,
		)
	}
}

func TestInspectRootCAValidationSelfSignatureFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.crt")

	certificate := newRootCASelfSignatureTestCertificate(t, true, false)
	value := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	})

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	state := inspectRootCAValidation(path)

	if state.Valid {
		t.Fatal("ValidationState.Valid = true, want false")
	}

	if !strings.Contains(
		state.Detail,
		"root CA self-signature is invalid",
	) {
		t.Fatalf(
			"ValidationState.Detail = %q, want self-signature error",
			state.Detail,
		)
	}
}

func TestInspectRootCAValidationStructuralFailure(t *testing.T) {
	at := time.Date(
		2026,
		time.September,
		11,
		18,
		0,
		0,
		0,
		time.UTC,
	)
	path := filepath.Join(t.TempDir(), "root.crt")

	value := newRootCAValidationCertificatePEM(
		t,
		x509.KeyUsageCertSign,
		at.Add(-time.Hour),
		at.Add(time.Hour),
	)

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	state := inspectRootCAValidationAt(path, at)

	if state.Valid {
		t.Fatal("ValidationState.Valid = true, want false")
	}

	if state.Detail != "root CA key usage does not include CRL signing" {
		t.Fatalf(
			"ValidationState.Detail = %q, want %q",
			state.Detail,
			"root CA key usage does not include CRL signing",
		)
	}
}

func TestInspectRootCAValidationValidityFailure(t *testing.T) {
	at := time.Date(
		2026,
		time.September,
		11,
		18,
		0,
		0,
		0,
		time.UTC,
	)
	path := filepath.Join(t.TempDir(), "root.crt")

	value := newRootCAValidationCertificatePEM(
		t,
		x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
		at.Add(-2*time.Hour),
		at.Add(-time.Hour),
	)

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	state := inspectRootCAValidationAt(path, at)

	if state.Valid {
		t.Fatal("ValidationState.Valid = true, want false")
	}

	want := "root CA expired at 2026-09-11T17:00:00Z"
	if state.Detail != want {
		t.Fatalf(
			"ValidationState.Detail = %q, want %q",
			state.Detail,
			want,
		)
	}
}

func TestInspectRootCAValidationValid(t *testing.T) {
	at := time.Date(
		2026,
		time.September,
		11,
		18,
		0,
		0,
		0,
		time.UTC,
	)
	path := filepath.Join(t.TempDir(), "root.crt")

	value := newRootCAValidationCertificatePEM(
		t,
		x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
		at.Add(-time.Hour),
		at.Add(time.Hour),
	)

	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	state := inspectRootCAValidationAt(path, at)

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

	if state.Path != path {
		t.Fatalf(
			"ValidationState.Path = %q, want %q",
			state.Path,
			path,
		)
	}
}

func newRootCAValidationCertificatePEM(
	t *testing.T,
	keyUsage x509.KeyUsage,
	notBefore time.Time,
	notAfter time.Time,
) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "FI Root CA Validation Test",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})
}
