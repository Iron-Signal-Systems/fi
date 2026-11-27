// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
)

// ValidateRootCASelfSignature verifies that the Root CA is self-issued and that
// its certificate signature was produced by the private key corresponding to
// its own public key.
//
// This validation does not evaluate validity dates, issuing relationships, or
// any other trust-policy requirement.
func ValidateRootCASelfSignature(certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("root CA certificate is required")
	}

	if !bytes.Equal(certificate.RawSubject, certificate.RawIssuer) {
		return errors.New("root CA issuer does not match subject")
	}

	if err := certificate.CheckSignature(
		certificate.SignatureAlgorithm,
		certificate.RawTBSCertificate,
		certificate.Signature,
	); err != nil {
		return fmt.Errorf(
			"root CA self-signature is invalid: %w",
			err,
		)
	}

	return nil
}
