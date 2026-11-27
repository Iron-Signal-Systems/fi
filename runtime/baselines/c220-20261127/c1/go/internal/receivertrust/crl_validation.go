// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ValidateCRL validates an FI CRL against its expected issuing CA and current
// time.
//
// The CRL must:
//   - identify the expected issuing CA;
//   - have a valid signature under that issuing CA;
//   - not have a ThisUpdate in the future;
//   - contain NextUpdate;
//   - have a NextUpdate strictly after the current time.
//
// This validation does not inspect whether any particular certificate serial is
// revoked.
func ValidateCRL(
	crl *x509.RevocationList,
	issuer *x509.Certificate,
	at time.Time,
) error {
	if crl == nil {
		return errors.New("CRL is nil")
	}

	if issuer == nil {
		return errors.New("CRL issuing certificate is nil")
	}

	if at.IsZero() {
		return errors.New("current time is required")
	}

	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return errors.New("CRL issuer does not match expected issuing CA")
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL signature validation failed: %w", err)
	}

	if crl.ThisUpdate.After(at) {
		return fmt.Errorf(
			"CRL is not yet valid: thisUpdate=%s",
			crl.ThisUpdate.UTC().Format(time.RFC3339),
		)
	}

	if crl.NextUpdate.IsZero() {
		return errors.New("CRL nextUpdate is required")
	}

	if !crl.NextUpdate.After(at) {
		return fmt.Errorf(
			"CRL is expired: nextUpdate=%s",
			crl.NextUpdate.UTC().Format(time.RFC3339),
		)
	}

	return nil
}
