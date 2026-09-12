// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// ValidateReceiverCertificateNotRevoked verifies that the receiver TLS
// certificate serial is absent from the supplied FI Transport CRL.
//
// CRL issuer, signature, and freshness validation are separate requirements and
// must succeed before this result is treated as authoritative.
func ValidateReceiverCertificateNotRevoked(
	certificate *x509.Certificate,
	crl *x509.RevocationList,
) error {
	if certificate == nil {
		return errors.New("receiver certificate is nil")
	}

	if certificate.SerialNumber == nil {
		return errors.New("receiver certificate serial number is missing")
	}

	if crl == nil {
		return errors.New("transport CRL is nil")
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return fmt.Errorf(
				"receiver certificate serial %s is revoked",
				certificate.SerialNumber.Text(16),
			)
		}
	}

	// Preserve compatibility with CRLs parsed into the older field.
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			return fmt.Errorf(
				"receiver certificate serial %s is revoked",
				certificate.SerialNumber.Text(16),
			)
		}
	}

	return nil
}
