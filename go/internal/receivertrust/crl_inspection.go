// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import "time"

// InspectBatchCRLValidation validates the installed FI batch-signing CRL
// against its expected issuing CA and the current time.
func InspectBatchCRLValidation() ValidationState {
	return inspectCRLValidationAt(
		BatchCRLPath,
		BatchIssuerPath,
		time.Now(),
	)
}

// InspectTransportCRLValidation validates the installed FI transport CRL
// against its expected issuing CA and the current time.
func InspectTransportCRLValidation() ValidationState {
	return inspectCRLValidationAt(
		TransportCRLPath,
		TransportIssuerPath,
		time.Now(),
	)
}

func inspectCRLValidationAt(
	crlPath string,
	issuerPath string,
	at time.Time,
) ValidationState {
	issuer, err := LoadCertificate(issuerPath)
	if err != nil {
		return newValidationState(crlPath, err)
	}

	crl, err := LoadCRL(crlPath)
	if err != nil {
		return newValidationState(crlPath, err)
	}

	return newValidationState(
		crlPath,
		ValidateCRL(crl, issuer, at),
	)
}
