// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

const receiverTransportOrganizationalUnit = "FI Receiver Transport"

// ValidateReceiverCertificate validates the FI receiver TLS leaf certificate
// against the expected FI Transport Issuing CA and FI Root CA.
//
// This validation requires:
//   - a non-CA leaf certificate;
//   - exactly one organizational unit identifying the FI receiver role;
//   - digital-signature key usage;
//   - the expected Transport Issuing CA as issuer;
//   - a valid signature from that issuing CA;
//   - a valid chain to the FI Root CA at the supplied time;
//   - TLS server-auth extended key usage.
//
// Hostname/SAN identity is intentionally validated separately.
func ValidateReceiverCertificate(
	leaf *x509.Certificate,
	root *x509.Certificate,
	issuer *x509.Certificate,
	at time.Time,
) error {
	if leaf == nil {
		return errors.New("receiver certificate is nil")
	}

	if root == nil {
		return errors.New("root CA certificate is nil")
	}

	if issuer == nil {
		return errors.New("transport issuing CA certificate is nil")
	}

	if at.IsZero() {
		return errors.New("current time is required")
	}

	if leaf.IsCA {
		return errors.New("receiver certificate must not be a CA")
	}

	if len(leaf.Subject.OrganizationalUnit) != 1 {
		return fmt.Errorf(
			"receiver certificate must contain exactly one organizational unit, got %d",
			len(leaf.Subject.OrganizationalUnit),
		)
	}

	if leaf.Subject.OrganizationalUnit[0] != receiverTransportOrganizationalUnit {
		return fmt.Errorf(
			"receiver certificate organizational unit must be %q, got %q",
			receiverTransportOrganizationalUnit,
			leaf.Subject.OrganizationalUnit[0],
		)
	}

	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New(
			"receiver certificate does not permit digital signatures",
		)
	}

	if !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) {
		return errors.New(
			"receiver certificate issuer does not match transport issuing CA",
		)
	}

	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf(
			"receiver certificate signature is not valid under transport issuing CA: %w",
			err,
		)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}); err != nil {
		return fmt.Errorf(
			"receiver certificate chain or server-auth validation failed: %w",
			err,
		)
	}

	return nil
}

// ValidateReceiverKeyPair verifies that the receiver certificate file and
// private-key file form one usable TLS identity. tls.LoadX509KeyPair performs
// the public/private key correspondence check without exporting the key.
func ValidateReceiverKeyPair(
	certificatePath string,
	privateKeyPath string,
) error {
	if certificatePath == "" {
		return errors.New("receiver certificate path is required")
	}

	if privateKeyPath == "" {
		return errors.New("receiver private-key path is required")
	}

	if _, err := tls.LoadX509KeyPair(
		certificatePath,
		privateKeyPath,
	); err != nil {
		return fmt.Errorf("load receiver TLS identity: %w", err)
	}

	return nil
}
