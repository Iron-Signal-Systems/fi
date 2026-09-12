// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"errors"
)

// ValidateRootCA validates the FI structural requirements for the receiver root CA.
//
// This validation does not verify the root self-signature, validity dates,
// issuing relationships, or any other trust-policy requirement.
func ValidateRootCA(certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("root CA certificate is required")
	}

	if !certificate.BasicConstraintsValid {
		return errors.New("root CA basic constraints are not valid")
	}

	if !certificate.IsCA {
		return errors.New("root CA certificate is not a CA")
	}

	if certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("root CA key usage does not include certificate signing")
	}

	if certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("root CA key usage does not include CRL signing")
	}

	return nil
}
