// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transporttrust

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	BatchSigningOrganizationalUnit = "FI Batch Signing"
	SourceConfigVersion1           = "1.0"
	TransportOrganizationalUnit    = "FI Shipper Transport"
)

// SourceConfig is one explicitly authorized FI source.
type SourceConfig struct {
	Authorization SourceAuthorization
	VersionID     string
}

// LoadSourceConfig reads and validates one receiver source configuration file.
func LoadSourceConfig(path string) (SourceConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return SourceConfig{}, fmt.Errorf("open FI source config: %w", err)
	}
	defer file.Close()

	value, err := ParseSourceConfig(file)
	if err != nil {
		return SourceConfig{}, fmt.Errorf(
			"parse FI source config %q: %w",
			path,
			err,
		)
	}

	return value, nil
}

// ParseSourceConfig reads FI receiver source configuration version 1.0.
//
// The first meaningful line must be:
//
//	version_id: 1.0
//
// Unknown directives, duplicate directives, malformed identities, and missing
// required directives are rejected.
func ParseSourceConfig(reader io.Reader) (SourceConfig, error) {
	if reader == nil {
		return SourceConfig{}, errors.New("reader is required")
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	var value SourceConfig

	seen := make(map[string]struct{})
	seenVersion := false
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, rawValue, ok := strings.Cut(line, ":")
		if !ok {
			return SourceConfig{}, fmt.Errorf(
				"line %d: expected directive followed by ':'",
				lineNumber,
			)
		}

		key = strings.TrimSpace(key)
		rawValue = strings.TrimSpace(rawValue)

		if !seenVersion {
			if key != "version_id" {
				return SourceConfig{}, fmt.Errorf(
					"line %d: first directive must be version_id",
					lineNumber,
				)
			}

			if rawValue != SourceConfigVersion1 {
				return SourceConfig{}, fmt.Errorf(
					"line %d: unsupported version_id %q",
					lineNumber,
					rawValue,
				)
			}

			value.VersionID = rawValue
			seenVersion = true
			seen[key] = struct{}{}
			continue
		}

		if _, exists := seen[key]; exists {
			return SourceConfig{}, fmt.Errorf(
				"line %d: duplicate directive %q",
				lineNumber,
				key,
			)
		}

		switch key {
		case "batch_signing_certificate_sha256":
			normalized, err := normalizeSHA256(rawValue)
			if err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: batch_signing_certificate_sha256: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.BatchSigning.CertificateSHA256 = normalized

		case "batch_signing_common_name":
			if err := validateSourceText(
				"batch_signing_common_name",
				rawValue,
			); err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.BatchSigning.CommonName = rawValue

		case "batch_signing_issuing_ca_sha256":
			normalized, err := normalizeSHA256(rawValue)
			if err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: batch_signing_issuing_ca_sha256: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.BatchSigning.IssuingCASHA256 = normalized

		case "batch_signing_organizational_unit":
			if err := validateSourceText(
				"batch_signing_organizational_unit",
				rawValue,
			); err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.BatchSigning.OrganizationalUnit = rawValue

		case "enabled":
			switch rawValue {
			case "false":
				value.Authorization.Enabled = false
			case "true":
				value.Authorization.Enabled = true
			default:
				return SourceConfig{}, fmt.Errorf(
					"line %d: enabled must be exactly true or false",
					lineNumber,
				)
			}

		case "source_id":
			if err := validateSourceText("source_id", rawValue); err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.SourceID = rawValue

		case "transport_certificate_sha256":
			normalized, err := normalizeSHA256(rawValue)
			if err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: transport_certificate_sha256: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.Transport.CertificateSHA256 = normalized

		case "transport_common_name":
			if err := validateSourceText(
				"transport_common_name",
				rawValue,
			); err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.Transport.CommonName = rawValue

		case "transport_issuing_ca_sha256":
			normalized, err := normalizeSHA256(rawValue)
			if err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: transport_issuing_ca_sha256: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.Transport.IssuingCASHA256 = normalized

		case "transport_organizational_unit":
			if err := validateSourceText(
				"transport_organizational_unit",
				rawValue,
			); err != nil {
				return SourceConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.Authorization.Transport.OrganizationalUnit = rawValue

		case "version_id":
			return SourceConfig{}, fmt.Errorf(
				"line %d: duplicate version_id",
				lineNumber,
			)

		default:
			return SourceConfig{}, fmt.Errorf(
				"line %d: unknown directive %q",
				lineNumber,
				key,
			)
		}

		seen[key] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return SourceConfig{}, fmt.Errorf("read source config: %w", err)
	}

	if !seenVersion {
		return SourceConfig{}, errors.New("version_id is required")
	}

	required := []string{
		"batch_signing_certificate_sha256",
		"batch_signing_common_name",
		"batch_signing_issuing_ca_sha256",
		"batch_signing_organizational_unit",
		"enabled",
		"source_id",
		"transport_certificate_sha256",
		"transport_common_name",
		"transport_issuing_ca_sha256",
		"transport_organizational_unit",
	}

	for _, directive := range required {
		if _, exists := seen[directive]; !exists {
			return SourceConfig{}, fmt.Errorf(
				"required directive %q is missing",
				directive,
			)
		}
	}

	if err := validateSourceConfig(value); err != nil {
		return SourceConfig{}, err
	}

	return value, nil
}

func validateSourceConfig(value SourceConfig) error {
	authorization := value.Authorization

	if !strings.EqualFold(
		authorization.SourceID,
		authorization.Transport.CommonName,
	) {
		return errors.New(
			"source_id must match transport_common_name",
		)
	}

	if !strings.EqualFold(
		authorization.SourceID,
		authorization.BatchSigning.CommonName,
	) {
		return errors.New(
			"source_id must match batch_signing_common_name",
		)
	}

	if authorization.Transport.OrganizationalUnit !=
		TransportOrganizationalUnit {
		return fmt.Errorf(
			"transport_organizational_unit must be %q",
			TransportOrganizationalUnit,
		)
	}

	if authorization.BatchSigning.OrganizationalUnit !=
		BatchSigningOrganizationalUnit {
		return fmt.Errorf(
			"batch_signing_organizational_unit must be %q",
			BatchSigningOrganizationalUnit,
		)
	}

	if authorization.Transport.CertificateSHA256 ==
		authorization.BatchSigning.CertificateSHA256 {
		return errors.New(
			"transport and batch-signing certificates must be different",
		)
	}

	if authorization.Transport.IssuingCASHA256 ==
		authorization.BatchSigning.IssuingCASHA256 {
		return errors.New(
			"transport and batch-signing issuing CAs must be different",
		)
	}

	return nil
}

func validateSourceText(name string, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}

	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}

	return nil
}
