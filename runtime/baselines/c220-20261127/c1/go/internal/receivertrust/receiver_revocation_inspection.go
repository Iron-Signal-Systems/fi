// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import "time"

// InspectReceiverRevocationValidation validates that the installed receiver TLS
// certificate is not revoked by the current, valid FI Transport CRL.
func InspectReceiverRevocationValidation() ValidationState {
	return inspectReceiverRevocationValidationAt(
		ReceiverCertPath,
		TransportIssuerPath,
		TransportCRLPath,
		time.Now(),
	)
}

func inspectReceiverRevocationValidationAt(
	certificatePath string,
	issuerPath string,
	crlPath string,
	at time.Time,
) ValidationState {
	chain, err := LoadCertificateChain(certificatePath)
	if err != nil {
		return newValidationState(certificatePath, err)
	}

	if len(chain) == 0 {
		return newValidationState(
			certificatePath,
			errReceiverCertificateChainEmpty,
		)
	}

	issuer, err := LoadCertificate(issuerPath)
	if err != nil {
		return newValidationState(certificatePath, err)
	}

	crl, err := LoadCRL(crlPath)
	if err != nil {
		return newValidationState(certificatePath, err)
	}

	if err := ValidateCRL(crl, issuer, at); err != nil {
		return newValidationState(certificatePath, err)
	}

	return newValidationState(
		certificatePath,
		ValidateReceiverCertificateNotRevoked(chain[0], crl),
	)
}
