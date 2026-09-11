// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"errors"
	"fmt"
	"strings"
)

// AuthorizationOutcome is the configured-source authorization result.
type AuthorizationOutcome string

const (
	AuthorizationAuthorized          AuthorizationOutcome = "AUTHORIZED"
	AuthorizationCertificateMismatch AuthorizationOutcome = "CERTIFICATE_MISMATCH"
	AuthorizationDisabled            AuthorizationOutcome = "DISABLED"
	AuthorizationIdentityMismatch    AuthorizationOutcome = "IDENTITY_MISMATCH"
)

// CertificateIdentity is the certificate identity material used after
// cryptographic certificate validation has succeeded.
type CertificateIdentity struct {
	CertificateSHA256  string
	CommonName         string
	IssuingCASHA256    string
	OrganizationalUnit string
}

// CertificateUse identifies the FI purpose for which a certificate is being
// authorized.
type CertificateUse string

const (
	CertificateUseBatchSigning CertificateUse = "batch_signing"
	CertificateUseTransport    CertificateUse = "transport"
)

// SourceAuthorization defines the explicitly enrolled identities for one FI
// source.
type SourceAuthorization struct {
	BatchSigning CertificateIdentity
	Enabled      bool
	SourceID     string
	Transport    CertificateIdentity
}

// AuthorizeSource determines whether an already-validated certificate is
// explicitly authorized for the requested FI source and certificate use.
//
// Certificate-chain validation, revocation checking, EKU validation, and key
// usage validation occur before this authorization boundary.
func AuthorizeSource(
	source SourceAuthorization,
	use CertificateUse,
	presented CertificateIdentity,
) (AuthorizationOutcome, error) {
	if source.SourceID == "" {
		return "", errors.New("source ID is required")
	}

	if !source.Enabled {
		return AuthorizationDisabled, nil
	}

	expected, err := expectedIdentity(source, use)
	if err != nil {
		return "", err
	}

	if !strings.EqualFold(presented.CommonName, expected.CommonName) {
		return AuthorizationIdentityMismatch, nil
	}

	if presented.OrganizationalUnit != expected.OrganizationalUnit {
		return AuthorizationIdentityMismatch, nil
	}

	expectedCA, err := normalizeSHA256(expected.IssuingCASHA256)
	if err != nil {
		return "", fmt.Errorf("configured issuing CA SHA-256: %w", err)
	}

	presentedCA, err := normalizeSHA256(presented.IssuingCASHA256)
	if err != nil {
		return "", fmt.Errorf("presented issuing CA SHA-256: %w", err)
	}

	if presentedCA != expectedCA {
		return AuthorizationCertificateMismatch, nil
	}

	expectedCertificate, err := normalizeSHA256(expected.CertificateSHA256)
	if err != nil {
		return "", fmt.Errorf("configured certificate SHA-256: %w", err)
	}

	presentedCertificate, err := normalizeSHA256(presented.CertificateSHA256)
	if err != nil {
		return "", fmt.Errorf("presented certificate SHA-256: %w", err)
	}

	if presentedCertificate != expectedCertificate {
		return AuthorizationCertificateMismatch, nil
	}

	return AuthorizationAuthorized, nil
}

func expectedIdentity(
	source SourceAuthorization,
	use CertificateUse,
) (CertificateIdentity, error) {
	switch use {
	case CertificateUseBatchSigning:
		return source.BatchSigning, nil
	case CertificateUseTransport:
		return source.Transport, nil
	default:
		return CertificateIdentity{}, fmt.Errorf(
			"unsupported certificate use %q",
			use,
		)
	}
}

func normalizeSHA256(value string) (string, error) {
	value = strings.ReplaceAll(strings.TrimSpace(value), ":", "")
	if len(value) != 64 {
		return "", fmt.Errorf(
			"expected 64 hexadecimal characters, got %d",
			len(value),
		)
	}

	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'f':
		case character >= 'A' && character <= 'F':
		default:
			return "", fmt.Errorf(
				"invalid hexadecimal character %q",
				character,
			)
		}
	}

	return strings.ToLower(value), nil
}
