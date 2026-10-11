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
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

// SourceRegistry is one validated, deterministic FI source-authorization
// snapshot.
//
// The registry owns its internal authorization values. Callers receive copies
// and cannot mutate the loaded snapshot.
type SourceRegistry struct {
	authorizations []transporttrust.SourceAuthorization
	bySourceID     map[string]transporttrust.SourceAuthorization
}

// Authorizations returns all structurally valid FI source authorizations in
// deterministic source-ID order.
//
// Disabled sources remain present in the registry. Authorization policy decides
// whether a source may establish or submit work.
func (value SourceRegistry) Authorizations() []transporttrust.SourceAuthorization {
	result := make(
		[]transporttrust.SourceAuthorization,
		len(value.authorizations),
	)

	copy(result, value.authorizations)

	return result
}

// Len returns the number of source authorization entries in the snapshot.
func (value SourceRegistry) Len() int {
	return len(value.authorizations)
}

// LoadSourceRegistry loads and validates the installed FI source registry as
// one deterministic authorization snapshot.
//
// Every registry entry must:
//   - be a regular .conf file;
//   - parse through the authoritative transporttrust source-config parser;
//   - have a safe source ID matching its exact filename;
//   - have a source ID unique under case-insensitive comparison;
//   - pin the installed FI Transport and Batch Signing issuing CAs.
//
// Disabled source entries remain structurally valid registry entries.
func LoadSourceRegistry(
	registryPath string,
	transportIssuer *x509.Certificate,
	batchIssuer *x509.Certificate,
) (SourceRegistry, error) {
	if strings.TrimSpace(registryPath) == "" {
		return SourceRegistry{}, errors.New(
			"source registry path is required",
		)
	}

	transportIssuerSHA256, err := certificateSHA256(
		transportIssuer,
	)
	if err != nil {
		return SourceRegistry{}, fmt.Errorf(
			"transport issuing CA: %w",
			err,
		)
	}

	batchIssuerSHA256, err := certificateSHA256(
		batchIssuer,
	)
	if err != nil {
		return SourceRegistry{}, fmt.Errorf(
			"batch signing issuing CA: %w",
			err,
		)
	}

	entries, err := os.ReadDir(registryPath)
	if err != nil {
		return SourceRegistry{}, fmt.Errorf(
			"read source registry %q: %w",
			registryPath,
			err,
		)
	}

	if len(entries) == 0 {
		return SourceRegistry{}, errors.New(
			"source registry contains no entries",
		)
	}

	authorizations := make(
		[]transporttrust.SourceAuthorization,
		0,
		len(entries),
	)

	bySourceID := make(
		map[string]transporttrust.SourceAuthorization,
		len(entries),
	)

	seenSourceIDs := make(map[string]string)
	seenTransportCertificates := make(map[string]string)
	seenBatchCertificates := make(map[string]string)

	configCount := 0

	for _, entry := range entries {
		name := entry.Name()

		info, err := entry.Info()
		if err != nil {
			return SourceRegistry{}, fmt.Errorf(
				"inspect source registry entry %q: %w",
				name,
				err,
			)
		}

		if !info.Mode().IsRegular() {
			return SourceRegistry{}, fmt.Errorf(
				"source registry entry %q is not a regular file",
				name,
			)
		}

		if filepath.Ext(name) != ".conf" {
			return SourceRegistry{}, fmt.Errorf(
				"source registry entry %q does not use .conf extension",
				name,
			)
		}

		configCount++

		path := filepath.Join(
			registryPath,
			name,
		)

		config, err := transporttrust.LoadSourceConfig(path)
		if err != nil {
			return SourceRegistry{}, err
		}

		authorization := config.Authorization
		sourceID := authorization.SourceID

		if err := validateRegistrySourceID(sourceID); err != nil {
			return SourceRegistry{}, fmt.Errorf(
				"source registry entry %q: %w",
				name,
				err,
			)
		}

		expectedName := sourceID + ".conf"
		if name != expectedName {
			return SourceRegistry{}, fmt.Errorf(
				"source registry entry %q must be named %q",
				name,
				expectedName,
			)
		}

		normalizedSourceID := strings.ToLower(sourceID)

		if existingName, exists :=
			seenSourceIDs[normalizedSourceID]; exists {
			return SourceRegistry{}, fmt.Errorf(
				"source registry entries %q and %q define duplicate source ID %q",
				existingName,
				name,
				sourceID,
			)
		}

		seenSourceIDs[normalizedSourceID] = name

		transportCertificate := normalizeRegistryFingerprint(
			authorization.Transport.CertificateSHA256,
		)

		if existingName, exists :=
			seenTransportCertificates[transportCertificate]; exists {
			return SourceRegistry{}, fmt.Errorf(
				"source registry entries %q and %q define the same transport certificate",
				existingName,
				name,
			)
		}

		seenTransportCertificates[transportCertificate] = name

		batchCertificate := normalizeRegistryFingerprint(
			authorization.BatchSigning.CertificateSHA256,
		)

		if existingName, exists :=
			seenBatchCertificates[batchCertificate]; exists {
			return SourceRegistry{}, fmt.Errorf(
				"source registry entries %q and %q define the same batch-signing certificate",
				existingName,
				name,
			)
		}

		seenBatchCertificates[batchCertificate] = name

		if !strings.EqualFold(
			authorization.Transport.IssuingCASHA256,
			transportIssuerSHA256,
		) {
			return SourceRegistry{}, fmt.Errorf(
				"source %q transport issuing CA SHA-256 does not match installed FI Transport Issuing CA",
				sourceID,
			)
		}

		if !strings.EqualFold(
			authorization.BatchSigning.IssuingCASHA256,
			batchIssuerSHA256,
		) {
			return SourceRegistry{}, fmt.Errorf(
				"source %q batch-signing issuing CA SHA-256 does not match installed FI Batch Signing Issuing CA",
				sourceID,
			)
		}

		authorizations = append(
			authorizations,
			authorization,
		)

		bySourceID[normalizedSourceID] = authorization
	}

	if configCount == 0 {
		return SourceRegistry{}, errors.New(
			"source registry contains no source configuration files",
		)
	}

	sort.Slice(
		authorizations,
		func(left int, right int) bool {
			leftID := strings.ToLower(
				authorizations[left].SourceID,
			)

			rightID := strings.ToLower(
				authorizations[right].SourceID,
			)

			if leftID == rightID {
				return authorizations[left].SourceID <
					authorizations[right].SourceID
			}

			return leftID < rightID
		},
	)

	return SourceRegistry{
		authorizations: authorizations,
		bySourceID:     bySourceID,
	}, nil
}

// Lookup returns the authorization for one source ID.
//
// Source-ID lookup is case-insensitive because registry uniqueness is enforced
// case-insensitively. The authorization retains its configured canonical
// source ID.
func (value SourceRegistry) Lookup(
	sourceID string,
) (transporttrust.SourceAuthorization, bool) {
	authorization, found :=
		value.bySourceID[strings.ToLower(sourceID)]

	return authorization, found
}

// ResolveTransportCertificate resolves one presented transport certificate to
// exactly one enrolled FI source.
//
// Resolution uses the exact enrolled transport certificate fingerprint. Full
// chain, revocation, EKU, key-usage, template, common-name, issuing-CA, and
// enabled-state validation remains the responsibility of transporttrust after
// resolution.
func (value SourceRegistry) ResolveTransportCertificate(
	certificate *x509.Certificate,
) (transporttrust.SourceAuthorization, bool, error) {
	if certificate == nil {
		return transporttrust.SourceAuthorization{},
			false,
			errors.New("transport certificate is required")
	}

	if len(certificate.Raw) == 0 {
		return transporttrust.SourceAuthorization{},
			false,
			errors.New("transport certificate DER is empty")
	}

	sum := sha256.Sum256(certificate.Raw)
	fingerprint := hex.EncodeToString(sum[:])

	var (
		resolved transporttrust.SourceAuthorization
		found    bool
	)

	for _, authorization := range value.authorizations {
		if !strings.EqualFold(
			normalizeRegistryFingerprint(
				authorization.Transport.CertificateSHA256,
			),
			fingerprint,
		) {
			continue
		}

		if found {
			return transporttrust.SourceAuthorization{},
				false,
				errors.New(
					"transport certificate resolves to more than one FI source",
				)
		}

		resolved = authorization
		found = true
	}

	return resolved, found, nil
}

// ValidateSourceRegistry validates the installed FI source registry as one
// deterministic authorization set.
func ValidateSourceRegistry(
	registryPath string,
	transportIssuer *x509.Certificate,
	batchIssuer *x509.Certificate,
) error {
	_, err := LoadSourceRegistry(
		registryPath,
		transportIssuer,
		batchIssuer,
	)

	return err
}

func certificateSHA256(
	certificate *x509.Certificate,
) (string, error) {
	if certificate == nil {
		return "", errors.New("certificate is nil")
	}

	if len(certificate.Raw) == 0 {
		return "", errors.New(
			"certificate DER is empty",
		)
	}

	sum := sha256.Sum256(certificate.Raw)

	return hex.EncodeToString(sum[:]), nil
}

func normalizeRegistryFingerprint(
	value string,
) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, ":", "")
	return strings.ToLower(value)
}

func validateRegistrySourceID(
	sourceID string,
) error {
	if sourceID == "" {
		return errors.New("source ID is required")
	}

	if sourceID == "." || sourceID == ".." {
		return errors.New("source ID is invalid")
	}

	if strings.ContainsAny(sourceID, `/\`) {
		return errors.New(
			"source ID must not contain path separators",
		)
	}

	return nil
}
