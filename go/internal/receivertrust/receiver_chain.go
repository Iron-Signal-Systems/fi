// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"errors"
	"fmt"
)

var errReceiverCertificateChainEmpty = errors.New(
	"receiver certificate chain is empty",
)

// ValidateReceiverCertificateChain validates the certificate ordering and
// contents of the receiver TLS fullchain file.
//
// The fullchain must contain:
//   - the receiver leaf first;
//   - the expected FI Transport Issuing CA second;
//   - optionally, the expected FI Root CA third.
//
// The root is optional in the served chain because TLS peers may already trust
// it. Unexpected, missing, reordered, or additional certificates are rejected.
func ValidateReceiverCertificateChain(
	chain []*x509.Certificate,
	root *x509.Certificate,
	issuer *x509.Certificate,
) error {
	if root == nil {
		return errors.New("root CA certificate is nil")
	}

	if issuer == nil {
		return errors.New("transport issuing CA certificate is nil")
	}

	switch len(chain) {
	case 0:
		return errReceiverCertificateChainEmpty
	case 2, 3:
	default:
		return fmt.Errorf(
			"receiver certificate chain contains %d certificates, want 2 or 3",
			len(chain),
		)
	}

	for index, certificate := range chain {
		if certificate == nil {
			return fmt.Errorf(
				"receiver certificate chain entry %d is nil",
				index,
			)
		}
	}

	if !chain[1].Equal(issuer) {
		return errors.New(
			"receiver certificate chain does not contain expected transport issuing CA second",
		)
	}

	if len(chain) == 3 && !chain[2].Equal(root) {
		return errors.New(
			"receiver certificate chain does not contain expected root CA third",
		)
	}

	return nil
}
