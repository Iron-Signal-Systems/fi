// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package receivertrust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

// ValidateSourceRegistry validates the installed FI source registry as one
// deterministic authorization set.
//
// Every registry entry must:
//   - be a regular .conf file;
//   - parse through the authoritative transporttrust source-config parser;
//   - have a safe source ID matching its exact filename;
//   - have a source ID unique under case-insensitive comparison;
//   - pin the installed FI Transport and Batch Signing issuing CAs.
//
// Disabled source entries remain structurally valid registry entries.
func ValidateSourceRegistry(
	registryPath string,
	transportIssuer *x509.Certificate,
	batchIssuer *x509.Certificate,
) error {
	if strings.TrimSpace(registryPath) == "" {
		return errors.New("source registry path is required")
	}

	transportIssuerSHA256, err := certificateSHA256(transportIssuer)
	if err != nil {
		return fmt.Errorf("transport issuing CA: %w", err)
	}

	batchIssuerSHA256, err := certificateSHA256(batchIssuer)
	if err != nil {
		return fmt.Errorf("batch signing issuing CA: %w", err)
	}

	entries, err := os.ReadDir(registryPath)
	if err != nil {
		return fmt.Errorf("read source registry %q: %w", registryPath, err)
	}

	if len(entries) == 0 {
		return errors.New("source registry contains no entries")
	}

	seenSourceIDs := make(map[string]string)
	configCount := 0

	for _, entry := range entries {
		name := entry.Name()

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf(
				"inspect source registry entry %q: %w",
				name,
				err,
			)
		}

		if !info.Mode().IsRegular() {
			return fmt.Errorf(
				"source registry entry %q is not a regular file",
				name,
			)
		}

		if filepath.Ext(name) != ".conf" {
			return fmt.Errorf(
				"source registry entry %q does not use .conf extension",
				name,
			)
		}

		configCount++

		path := filepath.Join(registryPath, name)

		config, err := transporttrust.LoadSourceConfig(path)
		if err != nil {
			return err
		}

		sourceID := config.Authorization.SourceID
		if err := validateRegistrySourceID(sourceID); err != nil {
			return fmt.Errorf(
				"source registry entry %q: %w",
				name,
				err,
			)
		}

		expectedName := sourceID + ".conf"
		if name != expectedName {
			return fmt.Errorf(
				"source registry entry %q must be named %q",
				name,
				expectedName,
			)
		}

		normalizedSourceID := strings.ToLower(sourceID)
		if existingName, exists := seenSourceIDs[normalizedSourceID]; exists {
			return fmt.Errorf(
				"source registry entries %q and %q define duplicate source ID %q",
				existingName,
				name,
				sourceID,
			)
		}
		seenSourceIDs[normalizedSourceID] = name

		if !strings.EqualFold(
			config.Authorization.Transport.IssuingCASHA256,
			transportIssuerSHA256,
		) {
			return fmt.Errorf(
				"source %q transport issuing CA SHA-256 does not match installed FI Transport Issuing CA",
				sourceID,
			)
		}

		if !strings.EqualFold(
			config.Authorization.BatchSigning.IssuingCASHA256,
			batchIssuerSHA256,
		) {
			return fmt.Errorf(
				"source %q batch-signing issuing CA SHA-256 does not match installed FI Batch Signing Issuing CA",
				sourceID,
			)
		}
	}

	if configCount == 0 {
		return errors.New("source registry contains no source configuration files")
	}

	return nil
}

func certificateSHA256(certificate *x509.Certificate) (string, error) {
	if certificate == nil {
		return "", errors.New("certificate is nil")
	}

	if len(certificate.Raw) == 0 {
		return "", errors.New("certificate DER is empty")
	}

	sum := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func validateRegistrySourceID(sourceID string) error {
	if sourceID == "" {
		return errors.New("source ID is required")
	}

	if sourceID == "." || sourceID == ".." {
		return errors.New("source ID is invalid")
	}

	if strings.ContainsAny(sourceID, `/\`) {
		return errors.New("source ID must not contain path separators")
	}

	return nil
}
