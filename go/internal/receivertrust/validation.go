// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import "time"

// ValidationState describes validation of one receiver trust object against a
// specific FI trust requirement.
type ValidationState struct {
	Detail string
	Path   string
	Valid  bool
}

// InspectRootCAValidation validates the installed receiver Root CA structural
// contract, self-signature, and current validity window without modifying
// receiver state.
//
// This does not validate any issuing relationship.
func InspectRootCAValidation() ValidationState {
	return inspectRootCAValidationAt(
		RootCAPath,
		time.Now(),
	)
}

func inspectRootCAValidation(path string) ValidationState {
	return inspectRootCAValidationAt(path, time.Now())
}

func inspectRootCAValidationAt(
	path string,
	at time.Time,
) ValidationState {
	certificate, err := LoadCertificate(path)
	if err != nil {
		return newValidationState(path, err)
	}

	if err := ValidateRootCA(certificate); err != nil {
		return newValidationState(path, err)
	}

	if err := ValidateRootCASelfSignature(certificate); err != nil {
		return newValidationState(path, err)
	}

	return newValidationState(
		path,
		ValidateRootCAValidity(certificate, at),
	)
}

func newValidationState(path string, err error) ValidationState {
	if err == nil {
		return ValidationState{
			Path:  path,
			Valid: true,
		}
	}

	return ValidationState{
		Detail: err.Error(),
		Path:   path,
		Valid:  false,
	}
}
