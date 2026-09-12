// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import "os"

// InspectReceiverHostnameValidation validates that the installed receiver leaf
// certificate is valid for the receiver's current runtime hostname.
func InspectReceiverHostnameValidation() ValidationState {
	hostname, err := os.Hostname()
	if err != nil {
		return newValidationState(ReceiverCertPath, err)
	}

	return inspectReceiverHostnameValidationAt(
		ReceiverCertPath,
		hostname,
	)
}

func inspectReceiverHostnameValidationAt(
	certificatePath string,
	hostname string,
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

	return newValidationState(
		certificatePath,
		ValidateReceiverHostname(chain[0], hostname),
	)
}
