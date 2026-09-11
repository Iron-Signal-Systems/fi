// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadCertificate reads and parses exactly one PEM certificate.
func LoadCertificate(path string) (*x509.Certificate, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"read certificate %q: %w",
			path,
			err,
		)
	}

	return parseCertificatePEM(path, value)
}

// LoadCertificateChain reads and parses one or more PEM certificates.
func LoadCertificateChain(path string) ([]*x509.Certificate, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"read certificate chain %q: %w",
			path,
			err,
		)
	}

	return parseCertificateChainPEM(path, value)
}

// LoadCRL reads and parses exactly one PEM X.509 CRL.
func LoadCRL(path string) (*x509.RevocationList, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(
			"read CRL %q: %w",
			path,
			err,
		)
	}

	return parseCRLPEM(path, value)
}

func parseCertificateChainPEM(
	path string,
	value []byte,
) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	remaining := value

	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, fmt.Errorf(
				"%q contains unexpected data in certificate chain",
				path,
			)
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf(
				"%q contains PEM type %q in certificate chain, want CERTIFICATE",
				path,
				block.Type,
			)
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf(
				"parse certificate chain %q: %w",
				path,
				err,
			)
		}

		certificates = append(certificates, certificate)
		remaining = rest
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf(
			"%q does not contain a certificate chain",
			path,
		)
	}

	return certificates, nil
}

func parseCertificatePEM(
	path string,
	value []byte,
) (*x509.Certificate, error) {
	block, rest := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf(
			"%q does not contain PEM data",
			path,
		)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf(
			"%q contains PEM type %q, want CERTIFICATE",
			path,
			block.Type,
		)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf(
			"%q contains unexpected data after the certificate",
			path,
		)
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"parse certificate %q: %w",
			path,
			err,
		)
	}

	return certificate, nil
}

func parseCRLPEM(
	path string,
	value []byte,
) (*x509.RevocationList, error) {
	block, rest := pem.Decode(value)
	if block == nil {
		return nil, fmt.Errorf(
			"%q does not contain PEM data",
			path,
		)
	}

	if block.Type != "X509 CRL" {
		return nil, fmt.Errorf(
			"%q contains PEM type %q, want X509 CRL",
			path,
			block.Type,
		)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf(
			"%q contains unexpected data after the CRL",
			path,
		)
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf(
			"parse CRL %q: %w",
			path,
			err,
		)
	}

	return crl, nil
}
