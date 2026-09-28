// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

func loadLocalMachineTransportIssuer(
	issuerCertificateSHA256 string,
	rootCertificateSHA256 string,
) (*x509.Certificate, string, error) {
	store, err := transportIssuerCertificateStore(
		issuerCertificateSHA256,
		rootCertificateSHA256,
	)
	if err != nil {
		return nil, "", err
	}

	certificate, err := certstore.LoadLocalMachineCertificate(
		store,
		issuerCertificateSHA256,
	)
	if err != nil {
		return nil, "", fmt.Errorf(
			"load transport issuer SHA256=%s from LocalMachine\\%s: %w",
			issuerCertificateSHA256,
			store,
			err,
		)
	}

	if !certificate.IsCA {
		return nil, "", fmt.Errorf(
			"transport issuer SHA256=%s from LocalMachine\\%s is not a CA certificate",
			issuerCertificateSHA256,
			store,
		)
	}

	return certificate, store, nil
}

func transportIssuerCertificateStore(
	issuerCertificateSHA256 string,
	rootCertificateSHA256 string,
) (string, error) {
	issuerCertificateSHA256 = strings.TrimSpace(
		issuerCertificateSHA256,
	)
	rootCertificateSHA256 = strings.TrimSpace(
		rootCertificateSHA256,
	)

	if !validSHA256Hex(
		issuerCertificateSHA256,
	) {
		return "", errors.New(
			"transport issuer certificate SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	if !validSHA256Hex(
		rootCertificateSHA256,
	) {
		return "", errors.New(
			"transport root certificate SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	if strings.EqualFold(
		issuerCertificateSHA256,
		rootCertificateSHA256,
	) {
		return certstore.StoreRoot, nil
	}

	return certstore.StoreCA, nil
}
