// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"errors"
)

// ValidateIssuingCAStructure validates the FI structural requirements shared by
// transport and batch-signing issuing CA certificates.
//
// This validation does not verify issuer relationships, signatures, validity
// dates, or revocation state.
func ValidateIssuingCAStructure(certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("issuing CA certificate is nil")
	}

	if !certificate.BasicConstraintsValid {
		return errors.New("issuing CA basic constraints are not valid")
	}

	if !certificate.IsCA {
		return errors.New("issuing CA certificate is not a CA")
	}

	if certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("issuing CA certificate does not permit certificate signing")
	}

	if certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return errors.New("issuing CA certificate does not permit CRL signing")
	}

	return nil
}
