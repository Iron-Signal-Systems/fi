// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
)

func inspectTransportCRLFile(
	path string,
	issuer *x509.Certificate,
) (string, error) {
	return inspectTransportCRLFileAt(
		path,
		issuer,
		time.Now(),
	)
}

func inspectTransportCRLFileAt(
	path string,
	issuer *x509.Certificate,
	at time.Time,
) (string, error) {
	crl, err := receivertrust.LoadCRL(path)
	if err != nil {
		return "", fmt.Errorf(
			"load FI transport CRL: %w",
			err,
		)
	}

	if err := receivertrust.ValidateCRL(
		crl,
		issuer,
		at,
	); err != nil {
		return "", fmt.Errorf(
			"validate FI transport CRL %q: %w",
			path,
			err,
		)
	}

	return fmt.Sprintf(
		"%s this_update=%s next_update=%s",
		path,
		crl.ThisUpdate.UTC().Format(time.RFC3339),
		crl.NextUpdate.UTC().Format(time.RFC3339),
	), nil
}

func recordTransportCRLCheck(
	report *Report,
	path string,
	issuer *x509.Certificate,
) {
	recordTransportCRLCheckAt(
		report,
		path,
		issuer,
		time.Now(),
	)
}

func recordTransportCRLCheckAt(
	report *Report,
	path string,
	issuer *x509.Certificate,
	at time.Time,
) {
	detail, err := inspectTransportCRLFileAt(
		path,
		issuer,
		at,
	)
	if err != nil {
		detail = err.Error()

		report.PKI = append(
			report.PKI,
			TrustObjectState{
				Detail: detail,
				Name:   "transport CRL",
				State:  checkFail,
			},
		)
		report.addCheck(
			checkFail,
			"transport CRL",
			detail,
		)
		return
	}

	report.PKI = append(
		report.PKI,
		TrustObjectState{
			Detail: detail,
			Name:   "transport CRL",
			State:  checkPass,
		},
	)
	report.addCheck(
		checkPass,
		"transport CRL",
		detail,
	)
}
