// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportsender"
)

var errSenderTransportTrustUnavailable = errors.New(
	"FI sender transport trust is unavailable",
)

// loadAndValidateTransportCRL loads the FI-managed transport CRL using the
// canonical shared trust representation and validates it using the shared FI
// CRL contract.
//
// Sender-specific context is added to returned errors, but CRL parsing,
// issuer/signature validation, and freshness semantics remain authoritative in
// receivertrust.
func loadAndValidateTransportCRL(
	path string,
	issuer *x509.Certificate,
	at time.Time,
) (*x509.RevocationList, error) {
	crl, err := receivertrust.LoadCRL(path)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: load FI transport CRL: %w",
			errSenderTransportTrustUnavailable,
			err,
		)
	}

	if err := receivertrust.ValidateCRL(
		crl,
		issuer,
		at,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: FI transport %w",
			errSenderTransportTrustUnavailable,
			err,
		)
	}

	return crl, nil
}

func retryableSenderTransportState(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(
		err,
		transportsender.ErrRetryableTransport,
	) || errors.Is(
		err,
		errSenderTransportTrustUnavailable,
	)
}
