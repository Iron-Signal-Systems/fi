// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import "time"

// InspectBatchIssuerValidation validates the installed FI batch-signing issuing
// CA against the currently implemented issuing-CA requirements.
func InspectBatchIssuerValidation() ValidationState {
	return inspectIssuingCAValidationAt(
		BatchIssuerPath,
		RootCAPath,
		time.Now(),
	)
}

// InspectTransportIssuerValidation validates the installed FI transport
// issuing CA against the currently implemented issuing-CA requirements.
func InspectTransportIssuerValidation() ValidationState {
	return inspectIssuingCAValidationAt(
		TransportIssuerPath,
		RootCAPath,
		time.Now(),
	)
}

func inspectIssuingCAValidationAt(
	issuerPath string,
	rootPath string,
	at time.Time,
) ValidationState {
	root, err := LoadCertificate(rootPath)
	if err != nil {
		return newValidationState(issuerPath, err)
	}

	certificate, err := LoadCertificate(issuerPath)
	if err != nil {
		return newValidationState(issuerPath, err)
	}

	if err := ValidateIssuingCAStructure(certificate); err != nil {
		return newValidationState(issuerPath, err)
	}

	if err := ValidateIssuingCAIssuer(certificate, root); err != nil {
		return newValidationState(issuerPath, err)
	}

	return newValidationState(
		issuerPath,
		ValidateIssuingCAValidity(certificate, at),
	)
}
