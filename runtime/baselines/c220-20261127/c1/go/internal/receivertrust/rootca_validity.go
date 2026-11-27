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

// ValidateRootCAValidity verifies that the Root CA is valid at the supplied
// time according to its X.509 NotBefore and NotAfter bounds.
//
// The validity interval is inclusive at both bounds. This validation does not
// evaluate certificate structure, self-signature, issuing relationships, or
// any other trust-policy requirement.
func ValidateRootCAValidity(
	certificate *x509.Certificate,
	at time.Time,
) error {
	if certificate == nil {
		return errors.New("root CA certificate is required")
	}

	if at.Before(certificate.NotBefore) {
		return fmt.Errorf(
			"root CA is not valid before %s",
			certificate.NotBefore.UTC().Format(time.RFC3339),
		)
	}

	if at.After(certificate.NotAfter) {
		return fmt.Errorf(
			"root CA expired at %s",
			certificate.NotAfter.UTC().Format(time.RFC3339),
		)
	}

	return nil
}
