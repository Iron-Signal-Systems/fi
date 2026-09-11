// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// VerifyTransportCertificate verifies the cryptographic and configured FI
// authorization requirements for one presented transport certificate.
//
// The leaf must:
//   - be signed by the expected FI Transport Issuing CA;
//   - chain through that issuer to the FI root;
//   - permit digital signatures;
//   - be valid for TLS client authentication;
//   - not be revoked by the current FI Transport CRL;
//   - map to the explicitly configured FI source.
func VerifyTransportCertificate(
	leaf *x509.Certificate,
	peerIntermediates []*x509.Certificate,
	root *x509.Certificate,
	issuer *x509.Certificate,
	crl *x509.RevocationList,
	source SourceAuthorization,
	currentTime time.Time,
) (AuthorizationOutcome, error) {
	if leaf == nil {
		return "", errors.New("leaf certificate is required")
	}

	if root == nil {
		return "", errors.New("root certificate is required")
	}

	if issuer == nil {
		return "", errors.New("issuing certificate is required")
	}

	if crl == nil {
		return "", errors.New("transport CRL is required")
	}

	if currentTime.IsZero() {
		return "", errors.New("current time is required")
	}

	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return "", fmt.Errorf(
			"leaf certificate is not signed by expected FI transport issuer: %w",
			err,
		)
	}

	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return "", errors.New(
			"transport certificate does not permit digital signatures",
		)
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return "", fmt.Errorf(
			"transport CRL signature validation failed: %w",
			err,
		)
	}

	if crl.ThisUpdate.After(currentTime) {
		return "", fmt.Errorf(
			"transport CRL is not yet valid: thisUpdate=%s",
			crl.ThisUpdate.UTC().Format(time.RFC3339),
		)
	}

	if crl.NextUpdate.IsZero() {
		return "", errors.New("transport CRL nextUpdate is required")
	}

	if !crl.NextUpdate.After(currentTime) {
		return "", fmt.Errorf(
			"transport CRL is expired: nextUpdate=%s",
			crl.NextUpdate.UTC().Format(time.RFC3339),
		)
	}

	if certificateIsRevoked(leaf, crl) {
		return "", fmt.Errorf(
			"transport certificate serial %s is revoked",
			leaf.SerialNumber.Text(16),
		)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)

	for _, certificate := range peerIntermediates {
		if certificate == nil {
			continue
		}

		if certificate.Equal(root) ||
			certificate.Equal(issuer) ||
			certificate.Equal(leaf) {
			continue
		}

		intermediates.AddCert(certificate)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}); err != nil {
		return "", fmt.Errorf(
			"transport certificate chain or client-auth validation failed: %w",
			err,
		)
	}

	identity, err := IdentityFromCertificate(leaf, issuer)
	if err != nil {
		return "", fmt.Errorf(
			"derive transport certificate identity: %w",
			err,
		)
	}

	outcome, err := AuthorizeSource(
		source,
		CertificateUseTransport,
		identity,
	)
	if err != nil {
		return "", fmt.Errorf("authorize FI source: %w", err)
	}

	if outcome != AuthorizationAuthorized {
		return outcome, fmt.Errorf(
			"FI source authorization rejected: %s",
			outcome,
		)
	}

	return outcome, nil
}

func certificateIsRevoked(
	certificate *x509.Certificate,
	crl *x509.RevocationList,
) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return true
		}
	}

	// Preserve compatibility with CRLs parsed into the older field.
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return true
		}
	}

	return false
}
