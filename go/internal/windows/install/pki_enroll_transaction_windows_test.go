// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/x509"
	"testing"
)

func TestValidatePKIEnrollmentContractRejectsIncompleteContract(
	t *testing.T,
) {
	t.Parallel()

	tests := []pkiEnrollmentContract{
		{},
		{
			TemplateName: fiTransportClientTemplateName,
		},
		{
			TemplateName: fiTransportClientTemplateName,
			TemplateOID:  "1.2.3.4",
		},
	}

	for _, test := range tests {
		if err := validatePKIEnrollmentContract(
			test,
		); err == nil {
			t.Fatalf(
				"incomplete contract unexpectedly accepted: %+v",
				test,
			)
		}
	}
}

func TestVerifyTrackedPKICertificateContractAcceptsTransport(
	t *testing.T,
) {
	t.Parallel()

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiTransportClientTemplateName,
		TemplateOID:  "1.2.3.4",
	}

	certificate := localMachinePKICertificate{
		CertificateSHA256: "0123456789abcdef",
		CommonName:        "AdminBox.iss.local",
		DNSNames: []string{
			"AdminBox.iss.local",
		},
		ExtendedKeyUsagePresent: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		PublicKeyAlgorithm: x509.RSA,
		PublicKeyBits:      3072,
		TemplateOID:        "1.2.3.4",
	}

	if err := verifyTrackedPKICertificateContract(
		certificate,
		contract,
	); err != nil {
		t.Fatalf(
			"exact transport certificate contract rejected: %v",
			err,
		)
	}
}

func TestVerifyTrackedPKICertificateContractAcceptsBatchSigning(
	t *testing.T,
) {
	t.Parallel()

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiBatchSigningTemplateName,
		TemplateOID:  "1.2.3.5",
	}

	certificate := localMachinePKICertificate{
		CertificateSHA256:       "0123456789abcdef",
		CommonName:              "AdminBox.iss.local",
		DNSNames:                []string{"AdminBox.iss.local"},
		ExtendedKeyUsagePresent: false,
		KeyUsage:                x509.KeyUsageDigitalSignature,
		PublicKeyAlgorithm:      x509.RSA,
		PublicKeyBits:           3072,
		TemplateOID:             "1.2.3.5",
	}

	if err := verifyTrackedPKICertificateContract(
		certificate,
		contract,
	); err != nil {
		t.Fatalf(
			"exact batch-signing certificate contract rejected: %v",
			err,
		)
	}
}

func TestVerifyTrackedPKICertificateContractRejectsWrongDNS(
	t *testing.T,
) {
	t.Parallel()

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiTransportClientTemplateName,
		TemplateOID:  "1.2.3.4",
	}

	certificate := localMachinePKICertificate{
		CertificateSHA256: "0123456789abcdef",
		CommonName:        "OtherHost.iss.local",
		DNSNames: []string{
			"OtherHost.iss.local",
		},
		ExtendedKeyUsagePresent: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		PublicKeyAlgorithm: x509.RSA,
		PublicKeyBits:      3072,
		TemplateOID:        "1.2.3.4",
	}

	if err := verifyTrackedPKICertificateContract(
		certificate,
		contract,
	); err == nil {
		t.Fatal(
			"wrong certificate DNS identity unexpectedly accepted",
		)
	}
}

func TestVerifyTrackedPKICertificateContractRejectsWrongTemplate(
	t *testing.T,
) {
	t.Parallel()

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiTransportClientTemplateName,
		TemplateOID:  "1.2.3.4",
	}

	certificate := localMachinePKICertificate{
		CertificateSHA256: "0123456789abcdef",
		CommonName:        "AdminBox.iss.local",
		DNSNames: []string{
			"AdminBox.iss.local",
		},
		ExtendedKeyUsagePresent: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		PublicKeyAlgorithm: x509.RSA,
		PublicKeyBits:      3072,
		TemplateOID:        "1.2.3.5",
	}

	if err := verifyTrackedPKICertificateContract(
		certificate,
		contract,
	); err == nil {
		t.Fatal(
			"wrong certificate template unexpectedly accepted",
		)
	}
}

func TestVerifyTrackedPKICertificateContractRejectsWeakRSA(
	t *testing.T,
) {
	t.Parallel()

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiTransportClientTemplateName,
		TemplateOID:  "1.2.3.4",
	}

	certificate := localMachinePKICertificate{
		CertificateSHA256:       "0123456789abcdef",
		CommonName:              "AdminBox.iss.local",
		DNSNames:                []string{"AdminBox.iss.local"},
		ExtendedKeyUsagePresent: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		PublicKeyAlgorithm: x509.RSA,
		PublicKeyBits:      2048,
		TemplateOID:        "1.2.3.4",
	}

	if err := verifyTrackedPKICertificateContract(
		certificate,
		contract,
	); err == nil {
		t.Fatal(
			"RSA-2048 certificate unexpectedly accepted",
		)
	}
}

func TestVerifyTrackedPKICertificateContractRejectsBatchEKU(
	t *testing.T,
) {
	t.Parallel()

	contract := pkiEnrollmentContract{
		ExpectedDNS:  "AdminBox.iss.local",
		TemplateName: fiBatchSigningTemplateName,
		TemplateOID:  "1.2.3.5",
	}

	certificate := localMachinePKICertificate{
		CertificateSHA256:       "0123456789abcdef",
		CommonName:              "AdminBox.iss.local",
		DNSNames:                []string{"AdminBox.iss.local"},
		ExtendedKeyUsagePresent: true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		PublicKeyAlgorithm: x509.RSA,
		PublicKeyBits:      3072,
		TemplateOID:        "1.2.3.5",
	}

	if err := verifyTrackedPKICertificateContract(
		certificate,
		contract,
	); err == nil {
		t.Fatal(
			"batch-signing certificate containing an EKU unexpectedly accepted",
		)
	}
}
