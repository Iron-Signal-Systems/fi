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

// ValidateIssuingCAIssuer validates that an FI issuing CA was issued and signed
// by the expected FI Root CA.
//
// This does not validate the issuing CA structure, validity dates, or
// revocation state.
func ValidateIssuingCAIssuer(
	certificate *x509.Certificate,
	root *x509.Certificate,
) error {
	if certificate == nil {
		return errors.New("issuing CA certificate is nil")
	}

	if root == nil {
		return errors.New("root CA certificate is nil")
	}

	if !bytes.Equal(certificate.RawIssuer, root.RawSubject) {
		return errors.New("issuing CA issuer does not match root CA subject")
	}

	if err := certificate.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf(
			"issuing CA signature is not valid under root CA: %w",
			err,
		)
	}

	return nil
}
