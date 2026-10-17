// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

type generationTrustBundle struct {
	BatchCRL    *x509.RevocationList
	BatchIssuer *x509.Certificate
	Root        *x509.Certificate
	Source      transporttrust.SourceAuthorization
}

type generationTrustResolver func(
	sourceID string,
) (generationTrustBundle, error)

// loadInstalledGenerationTrust is the production trust resolver.
// It uses the existing fixed receiver trust and source registry paths.
func loadInstalledGenerationTrust(
	sourceID string,
) (generationTrustBundle, error) {
	var trust generationTrustBundle

	root, err := receivertrust.LoadCertificate(
		receivertrust.RootCAPath,
	)
	if err != nil {
		return trust, err
	}

	issuer, err := receivertrust.LoadCertificate(
		receivertrust.BatchIssuerPath,
	)
	if err != nil {
		return trust, err
	}

	crl, err := receivertrust.LoadCRL(
		receivertrust.BatchCRLPath,
	)
	if err != nil {
		return trust, err
	}

	sourcePath := filepath.Join(
		receivertrust.SourceRegistryPath,
		sourceID+".conf",
	)

	sourceConfig, err := transporttrust.LoadSourceConfig(
		sourcePath,
	)
	if err != nil {
		return trust, err
	}

	if !strings.EqualFold(
		sourceConfig.Authorization.SourceID,
		sourceID,
	) {
		return trust, fmt.Errorf(
			"FI source config identity %q does not match requested source %q",
			sourceConfig.Authorization.SourceID,
			sourceID,
		)
	}

	return generationTrustBundle{
		BatchCRL:    crl,
		BatchIssuer: issuer,
		Root:        root,
		Source:      sourceConfig.Authorization,
	}, nil
}
