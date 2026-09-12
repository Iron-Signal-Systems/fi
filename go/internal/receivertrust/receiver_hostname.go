// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// ValidateReceiverHostname verifies that the receiver TLS certificate is valid
// for the supplied runtime hostname using Go's X.509 SAN hostname rules.
//
// This does not validate certificate chains, signatures, EKUs, dates, or
// private-key correspondence; those are validated separately.
func ValidateReceiverHostname(
	certificate *x509.Certificate,
	hostname string,
) error {
	if certificate == nil {
		return errors.New("receiver certificate is nil")
	}

	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return errors.New("receiver hostname is required")
	}

	if err := certificate.VerifyHostname(hostname); err != nil {
		return fmt.Errorf(
			"receiver certificate is not valid for hostname %q: %w",
			hostname,
			err,
		)
	}

	return nil
}
