// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSourceRegistry(t *testing.T) {
	transportIssuer, batchIssuer := newSourceRegistryIssuers(t)
	registry := t.TempDir()

	writeSourceRegistryConfig(
		t,
		registry,
		"iss-test-01.iss.local",
		transportIssuer,
		batchIssuer,
		true,
	)

	if err := ValidateSourceRegistry(
		registry,
		transportIssuer,
		batchIssuer,
	); err != nil {
		t.Fatalf("ValidateSourceRegistry() error = %v", err)
	}
}

func TestValidateSourceRegistryFailures(t *testing.T) {
	transportIssuer, batchIssuer := newSourceRegistryIssuers(t)

	t.Run("empty registry", func(t *testing.T) {
		if err := ValidateSourceRegistry(
			t.TempDir(),
			transportIssuer,
			batchIssuer,
		); err == nil {
			t.Fatal("ValidateSourceRegistry() error = nil, want error")
		}
	})

	t.Run("unexpected extension", func(t *testing.T) {
		registry := t.TempDir()

		if err := os.WriteFile(
			filepath.Join(registry, "README.txt"),
			[]byte("unexpected"),
			0600,
		); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}

		if err := ValidateSourceRegistry(
			registry,
			transportIssuer,
			batchIssuer,
		); err == nil {
			t.Fatal("ValidateSourceRegistry() error = nil, want error")
		}
	})

	t.Run("filename mismatch", func(t *testing.T) {
		registry := t.TempDir()

		path := writeSourceRegistryConfig(
			t,
			registry,
			"iss-test-01.iss.local",
			transportIssuer,
			batchIssuer,
			true,
		)

		if err := os.Rename(
			path,
			filepath.Join(registry, "wrong-name.conf"),
		); err != nil {
			t.Fatalf("os.Rename() error = %v", err)
		}

		if err := ValidateSourceRegistry(
			registry,
			transportIssuer,
			batchIssuer,
		); err == nil {
			t.Fatal("ValidateSourceRegistry() error = nil, want error")
		}
	})

	t.Run("transport CA pin mismatch", func(t *testing.T) {
		registry := t.TempDir()
		_, otherTransportIssuer := newIssuingCARelationshipCertificatesWithName(
			t,
			"Other Source Registry Root",
		)

		writeSourceRegistryConfig(
			t,
			registry,
			"iss-test-01.iss.local",
			otherTransportIssuer,
			batchIssuer,
			true,
		)

		if err := ValidateSourceRegistry(
			registry,
			transportIssuer,
			batchIssuer,
		); err == nil {
			t.Fatal("ValidateSourceRegistry() error = nil, want error")
		}
	})

	t.Run("batch CA pin mismatch", func(t *testing.T) {
		registry := t.TempDir()
		_, otherBatchIssuer := newIssuingCARelationshipCertificatesWithName(
			t,
			"Other Batch Source Registry Root",
		)

		writeSourceRegistryConfig(
			t,
			registry,
			"iss-test-01.iss.local",
			transportIssuer,
			otherBatchIssuer,
			true,
		)

		if err := ValidateSourceRegistry(
			registry,
			transportIssuer,
			batchIssuer,
		); err == nil {
			t.Fatal("ValidateSourceRegistry() error = nil, want error")
		}
	})

	t.Run("disabled source remains structurally valid", func(t *testing.T) {
		registry := t.TempDir()

		writeSourceRegistryConfig(
			t,
			registry,
			"iss-test-01.iss.local",
			transportIssuer,
			batchIssuer,
			false,
		)

		if err := ValidateSourceRegistry(
			registry,
			transportIssuer,
			batchIssuer,
		); err != nil {
			t.Fatalf("ValidateSourceRegistry() error = %v", err)
		}
	})
}

func newSourceRegistryIssuers(
	t *testing.T,
) (*x509.Certificate, *x509.Certificate) {
	t.Helper()

	_, transportIssuer := newIssuingCARelationshipCertificatesWithName(
		t,
		"FI Source Registry Transport Root",
	)

	_, batchIssuer := newIssuingCARelationshipCertificatesWithName(
		t,
		"FI Source Registry Batch Root",
	)

	return transportIssuer, batchIssuer
}

func sourceRegistryCertificateSHA256(
	t *testing.T,
	certificate *x509.Certificate,
) string {
	t.Helper()

	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:])
}

func writeSourceRegistryConfig(
	t *testing.T,
	registry string,
	sourceID string,
	transportIssuer *x509.Certificate,
	batchIssuer *x509.Certificate,
	enabled bool,
) string {
	t.Helper()

	value := fmt.Sprintf(
		`version_id: 1.0
source_id: %s
enabled: %t
transport_common_name: %s
transport_organizational_unit: FI Shipper Transport
transport_certificate_sha256: %s
transport_issuing_ca_sha256: %s
batch_signing_common_name: %s
batch_signing_organizational_unit: FI Batch Signing
batch_signing_certificate_sha256: %s
batch_signing_issuing_ca_sha256: %s
`,
		sourceID,
		enabled,
		sourceID,
		strings.Repeat("1", 64),
		sourceRegistryCertificateSHA256(t, transportIssuer),
		sourceID,
		strings.Repeat("2", 64),
		sourceRegistryCertificateSHA256(t, batchIssuer),
	)

	path := filepath.Join(registry, sourceID+".conf")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", path, err)
	}

	return path
}
