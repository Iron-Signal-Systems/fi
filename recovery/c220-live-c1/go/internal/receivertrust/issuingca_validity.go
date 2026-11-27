// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ValidateIssuingCAValidity validates that an FI issuing CA is currently within
// its X.509 validity window. The NotBefore and NotAfter boundaries are valid.
//
// This does not validate certificate structure, issuer relationships,
// signatures, or revocation state.
func ValidateIssuingCAValidity(
	certificate *x509.Certificate,
	at time.Time,
) error {
	if certificate == nil {
		return errors.New("issuing CA certificate is nil")
	}

	if at.Before(certificate.NotBefore) {
		return fmt.Errorf(
			"issuing CA is not valid before %s",
			certificate.NotBefore.UTC().Format(time.RFC3339),
		)
	}

	if at.After(certificate.NotAfter) {
		return fmt.Errorf(
			"issuing CA expired at %s",
			certificate.NotAfter.UTC().Format(time.RFC3339),
		)
	}

	return nil
}
