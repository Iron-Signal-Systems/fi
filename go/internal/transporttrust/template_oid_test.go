// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestCertificateTemplateOID(t *testing.T) {
	templateID := asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 311, 21, 8, 12345, 67890,
	}

	encoded, err := asn1.Marshal(adcsCertificateTemplateInformation{
		TemplateID:   templateID,
		MajorVersion: 100,
		MinorVersion: 4,
	})
	if err != nil {
		t.Fatalf("marshal certificate template information: %v", err)
	}

	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:    adcsCertificateTemplateInformationOID,
				Value: encoded,
			},
		},
	}

	got, err := CertificateTemplateOID(certificate)
	if err != nil {
		t.Fatalf("CertificateTemplateOID() error = %v", err)
	}

	if got != templateID.String() {
		t.Fatalf(
			"CertificateTemplateOID() = %q, want %q",
			got,
			templateID.String(),
		)
	}
}

func TestCertificateTemplateOIDRejectsMalformedExtension(t *testing.T) {
	certificate := &x509.Certificate{
		Extensions: []pkix.Extension{
			{
				Id:    adcsCertificateTemplateInformationOID,
				Value: []byte{0x30, 0x03, 0x06},
			},
		},
	}

	if _, err := CertificateTemplateOID(certificate); err == nil {
		t.Fatal("CertificateTemplateOID() accepted malformed extension")
	}
}

func TestCertificateTemplateOIDRejectsMissingExtension(t *testing.T) {
	if _, err := CertificateTemplateOID(&x509.Certificate{}); err == nil {
		t.Fatal("CertificateTemplateOID() accepted missing extension")
	}
}
