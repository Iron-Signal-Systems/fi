// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestIdentityFromCertificate(t *testing.T) {
	certificate := &x509.Certificate{
		Raw: []byte("FI transport certificate"),
		Subject: pkix.Name{
			CommonName:         "iss-fs-01.iss.local",
			OrganizationalUnit: []string{"FI Shipper Transport"},
		},
	}

	issuer := &x509.Certificate{
		Raw: []byte("FI Transport Issuing CA"),
	}

	identity, err := IdentityFromCertificate(certificate, issuer)
	if err != nil {
		t.Fatalf("IdentityFromCertificate() error = %v", err)
	}

	if identity.CommonName != "iss-fs-01.iss.local" {
		t.Fatalf(
			"CommonName = %q, want %q",
			identity.CommonName,
			"iss-fs-01.iss.local",
		)
	}

	if identity.OrganizationalUnit != "FI Shipper Transport" {
		t.Fatalf(
			"OrganizationalUnit = %q, want %q",
			identity.OrganizationalUnit,
			"FI Shipper Transport",
		)
	}

	if len(identity.CertificateSHA256) != 64 {
		t.Fatalf(
			"CertificateSHA256 length = %d, want 64",
			len(identity.CertificateSHA256),
		)
	}

	if len(identity.IssuingCASHA256) != 64 {
		t.Fatalf(
			"IssuingCASHA256 length = %d, want 64",
			len(identity.IssuingCASHA256),
		)
	}
}

func TestIdentityFromCertificateRejectsAmbiguousOrganizationalUnit(t *testing.T) {
	certificate := &x509.Certificate{
		Raw: []byte("FI transport certificate"),
		Subject: pkix.Name{
			CommonName: "iss-fs-01.iss.local",
			OrganizationalUnit: []string{
				"FI Shipper Transport",
				"Unexpected OU",
			},
		},
	}

	issuer := &x509.Certificate{
		Raw: []byte("FI Transport Issuing CA"),
	}

	if _, err := IdentityFromCertificate(certificate, issuer); err == nil {
		t.Fatal("IdentityFromCertificate() error = nil, want rejection")
	}
}
