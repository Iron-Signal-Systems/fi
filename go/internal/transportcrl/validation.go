// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportcrl

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
)

var deltaCRLIndicatorOID = asn1.ObjectIdentifier{
	2,
	5,
	29,
	27,
}

func certificateRevoked(
	revocationList *x509.RevocationList,
	certificate *x509.Certificate,
) bool {
	if revocationList == nil ||
		certificate == nil ||
		certificate.SerialNumber == nil {
		return false
	}

	for _, entry := range revocationList.RevokedCertificateEntries {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(
				certificate.SerialNumber,
			) == 0 {
			return true
		}
	}

	for _, entry := range revocationList.RevokedCertificates {
		if entry.SerialNumber != nil &&
			entry.SerialNumber.Cmp(
				certificate.SerialNumber,
			) == 0 {
			return true
		}
	}

	return false
}

func RejectDeltaCRL(
	revocationList *x509.RevocationList,
) error {
	if revocationList == nil {
		return errors.New(
			"transport CRL is required",
		)
	}

	for _, extension := range revocationList.Extensions {
		if extension.Id.Equal(
			deltaCRLIndicatorOID,
		) {
			return errors.New(
				"FI transport trust does not support delta CRLs",
			)
		}
	}

	for _, extension := range revocationList.ExtraExtensions {
		if extension.Id.Equal(
			deltaCRLIndicatorOID,
		) {
			return errors.New(
				"FI transport trust does not support delta CRLs",
			)
		}
	}

	return nil
}
func ValidateDER(
	raw []byte,
	issuer *x509.Certificate,
	leaf *x509.Certificate,
	at time.Time,
) (*x509.RevocationList, error) {
	if len(raw) == 0 {
		return nil, errors.New(
			"transport CRL is empty",
		)
	}

	if issuer == nil {
		return nil, errors.New(
			"transport CRL issuer certificate is required",
		)
	}

	if leaf == nil {
		return nil, errors.New(
			"transport leaf certificate is required",
		)
	}

	if at.IsZero() {
		return nil, errors.New(
			"current time is required for transport CRL validation",
		)
	}

	revocationList, err :=
		x509.ParseRevocationList(
			raw,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"parse transport CRL DER: %w",
			err,
		)
	}

	if err := RejectDeltaCRL(
		revocationList,
	); err != nil {
		return nil, err
	}

	if err := receivertrust.ValidateCRL(
		revocationList,
		issuer,
		at,
	); err != nil {
		return nil, fmt.Errorf(
			"transport %w",
			err,
		)
	}

	if certificateRevoked(
		revocationList,
		leaf,
	) {
		return nil, fmt.Errorf(
			"transport certificate serial=%s is revoked by the retrieved CRL",
			leaf.SerialNumber.Text(
				16,
			),
		)
	}

	return revocationList, nil
}
