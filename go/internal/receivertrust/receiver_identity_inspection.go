// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import "time"

// InspectReceiverCertificateValidation validates the installed FI receiver TLS
// fullchain against the FI Root CA and FI Transport Issuing CA.
func InspectReceiverCertificateValidation() ValidationState {
	return inspectReceiverCertificateValidationAt(
		ReceiverCertPath,
		RootCAPath,
		TransportIssuerPath,
		time.Now(),
	)
}

// InspectReceiverKeyValidation validates that the installed FI receiver
// certificate and private key form one usable TLS identity.
func InspectReceiverKeyValidation() ValidationState {
	return inspectReceiverKeyValidationAt(
		ReceiverCertPath,
		ReceiverKeyPath,
	)
}

func inspectReceiverCertificateValidationAt(
	certificatePath string,
	rootPath string,
	issuerPath string,
	at time.Time,
) ValidationState {
	root, err := LoadCertificate(rootPath)
	if err != nil {
		return newValidationState(certificatePath, err)
	}

	issuer, err := LoadCertificate(issuerPath)
	if err != nil {
		return newValidationState(certificatePath, err)
	}

	chain, err := LoadCertificateChain(certificatePath)
	if err != nil {
		return newValidationState(certificatePath, err)
	}

	if err := ValidateReceiverCertificateChain(
		chain,
		root,
		issuer,
	); err != nil {
		return newValidationState(certificatePath, err)
	}

	return newValidationState(
		certificatePath,
		ValidateReceiverCertificate(
			chain[0],
			root,
			issuer,
			at,
		),
	)
}

func inspectReceiverKeyValidationAt(
	certificatePath string,
	keyPath string,
) ValidationState {
	return newValidationState(
		keyPath,
		ValidateReceiverKeyPair(
			certificatePath,
			keyPath,
		),
	)
}
