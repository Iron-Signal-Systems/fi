// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

// InspectSourceRegistryValidation validates the installed FI source registry
// against the installed Transport and Batch Signing issuing CAs.
func InspectSourceRegistryValidation() ValidationState {
	return inspectSourceRegistryValidationAt(
		SourceRegistryPath,
		TransportIssuerPath,
		BatchIssuerPath,
	)
}

func inspectSourceRegistryValidationAt(
	registryPath string,
	transportIssuerPath string,
	batchIssuerPath string,
) ValidationState {
	transportIssuer, err := LoadCertificate(transportIssuerPath)
	if err != nil {
		return newValidationState(registryPath, err)
	}

	batchIssuer, err := LoadCertificate(batchIssuerPath)
	if err != nil {
		return newValidationState(registryPath, err)
	}

	return newValidationState(
		registryPath,
		ValidateSourceRegistry(
			registryPath,
			transportIssuer,
			batchIssuer,
		),
	)
}
