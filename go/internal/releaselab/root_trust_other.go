// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package releaselab

import "fmt"

type DevelopmentCodeSigningTrustState struct {
	CRLSHA256             string
	RootCertificateSHA256 string
}

func TrustDevelopmentCodeSigningMaterial(
	certificatePath string,
	crlPath string,
) (DevelopmentCodeSigningTrustState, error) {
	return DevelopmentCodeSigningTrustState{}, fmt.Errorf(
		"trust-root is supported only on Windows; certificate=%s CRL=%s",
		certificatePath,
		crlPath,
	)
}

func UntrustDevelopmentCodeSigningMaterial(
	certificateSHA256 string,
	crlSHA256 string,
) error {
	return fmt.Errorf(
		"untrust-root is supported only on Windows; certificate_SHA256=%s CRL_SHA256=%s",
		certificateSHA256,
		crlSHA256,
	)
}
