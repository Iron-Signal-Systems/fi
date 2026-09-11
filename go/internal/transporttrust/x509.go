// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// IdentityFromCertificate constructs the FI authorization identity from an
// already-parsed leaf certificate and its issuing certificate.
//
// Cryptographic chain validation, revocation checking, EKU validation, and key
// usage validation remain separate responsibilities.
func IdentityFromCertificate(
	certificate *x509.Certificate,
	issuer *x509.Certificate,
) (CertificateIdentity, error) {
	if certificate == nil {
		return CertificateIdentity{}, errors.New("certificate is required")
	}

	if issuer == nil {
		return CertificateIdentity{}, errors.New("issuer certificate is required")
	}

	if len(certificate.Raw) == 0 {
		return CertificateIdentity{}, errors.New("certificate DER is empty")
	}

	if len(issuer.Raw) == 0 {
		return CertificateIdentity{}, errors.New("issuer certificate DER is empty")
	}

	if certificate.Subject.CommonName == "" {
		return CertificateIdentity{}, errors.New("certificate common name is required")
	}

	if len(certificate.Subject.OrganizationalUnit) != 1 {
		return CertificateIdentity{}, fmt.Errorf(
			"certificate must contain exactly one organizational unit, got %d",
			len(certificate.Subject.OrganizationalUnit),
		)
	}

	certificateSHA256 := sha256.Sum256(certificate.Raw)
	issuerSHA256 := sha256.Sum256(issuer.Raw)

	return CertificateIdentity{
		CertificateSHA256:  hex.EncodeToString(certificateSHA256[:]),
		CommonName:         certificate.Subject.CommonName,
		IssuingCASHA256:    hex.EncodeToString(issuerSHA256[:]),
		OrganizationalUnit: certificate.Subject.OrganizationalUnit[0],
	}, nil
}
