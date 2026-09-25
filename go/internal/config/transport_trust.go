// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const TransportTrustVersion1 = "1.0"

type TransportTrustConfig struct {
	VersionID                     string
	BatchSigningCertificateSHA256 string
	RootCertificateSHA256         string
	TransportCertificateSHA256    string
	TransportCRLPath              string
	TransportIssuerSHA256         string
}

func LoadTransportTrust(path string) (TransportTrustConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return TransportTrustConfig{}, fmt.Errorf("open FI transport trust config: %w", err)
	}
	defer file.Close()

	value, err := ParseTransportTrust(file)
	if err != nil {
		return TransportTrustConfig{}, fmt.Errorf("parse FI transport trust config %q: %w", path, err)
	}
	return value, nil
}

func ParseTransportTrust(reader io.Reader) (TransportTrustConfig, error) {
	if reader == nil {
		return TransportTrustConfig{}, errors.New("reader is required")
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	var value TransportTrustConfig
	seenVersion := false
	seen := make(map[string]struct{})
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

		if !seenVersion {
			key, rawValue, ok := strings.Cut(line, ":")
			if !ok || strings.TrimSpace(key) != "version_id" {
				return TransportTrustConfig{}, fmt.Errorf(
					"line %d: first directive must be version_id",
					lineNumber,
				)
			}
			rawValue = strings.TrimSpace(rawValue)
			if rawValue != TransportTrustVersion1 {
				return TransportTrustConfig{}, fmt.Errorf(
					"line %d: unsupported version_id %q",
					lineNumber,
					rawValue,
				)
			}
			value.VersionID = rawValue
			seenVersion = true
			continue
		}

		key, rawValue, ok := strings.Cut(line, "=")
		if !ok {
			return TransportTrustConfig{}, fmt.Errorf(
				"line %d: expected trust setting followed by '='",
				lineNumber,
			)
		}

		key = strings.TrimSpace(key)
		rawValue = strings.TrimSpace(stripInlineComment(rawValue))

		if key == "" {
			return TransportTrustConfig{}, fmt.Errorf(
				"line %d: trust setting name is required",
				lineNumber,
			)
		}
		if rawValue == "" {
			return TransportTrustConfig{}, fmt.Errorf(
				"line %d: %s value is required",
				lineNumber,
				key,
			)
		}
		if _, exists := seen[key]; exists {
			return TransportTrustConfig{}, fmt.Errorf(
				"line %d: duplicate trust setting %q",
				lineNumber,
				key,
			)
		}
		seen[key] = struct{}{}

		switch key {
		case "trust.batch_signing_cert_sha256":
			digest, err := parseSHA256Fingerprint(key, rawValue)
			if err != nil {
				return TransportTrustConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.BatchSigningCertificateSHA256 = digest

		case "trust.root_cert_sha256":
			digest, err := parseSHA256Fingerprint(key, rawValue)
			if err != nil {
				return TransportTrustConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.RootCertificateSHA256 = digest

		case "trust.transport_cert_sha256":
			digest, err := parseSHA256Fingerprint(key, rawValue)
			if err != nil {
				return TransportTrustConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.TransportCertificateSHA256 = digest

		case "trust.transport_crl":
			if err := validateWindowsPath(rawValue); err != nil {
				return TransportTrustConfig{}, fmt.Errorf(
					"line %d: trust.transport_crl: %w",
					lineNumber,
					err,
				)
			}
			value.TransportCRLPath = rawValue

		case "trust.transport_issuer_sha256":
			digest, err := parseSHA256Fingerprint(key, rawValue)
			if err != nil {
				return TransportTrustConfig{}, fmt.Errorf(
					"line %d: %w",
					lineNumber,
					err,
				)
			}
			value.TransportIssuerSHA256 = digest

		default:
			return TransportTrustConfig{}, fmt.Errorf(
				"line %d: unknown trust setting %q",
				lineNumber,
				key,
			)
		}
	}

	if err := scanner.Err(); err != nil {
		return TransportTrustConfig{}, fmt.Errorf(
			"read transport trust config: %w",
			err,
		)
	}
	if !seenVersion {
		return TransportTrustConfig{}, errors.New("version_id is required")
	}

	required := []struct {
		key   string
		value string
	}{
		{"trust.batch_signing_cert_sha256", value.BatchSigningCertificateSHA256},
		{"trust.root_cert_sha256", value.RootCertificateSHA256},
		{"trust.transport_cert_sha256", value.TransportCertificateSHA256},
		{"trust.transport_crl", value.TransportCRLPath},
		{"trust.transport_issuer_sha256", value.TransportIssuerSHA256},
	}

	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return TransportTrustConfig{}, fmt.Errorf(
				"%s is required",
				field.key,
			)
		}
	}

	return value, nil
}

func parseSHA256Fingerprint(name string, value string) (string, error) {
	if len(value) != 64 {
		return "", fmt.Errorf(
			"%s must contain exactly 64 hexadecimal characters",
			name,
		)
	}

	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf(
			"%s must contain exactly 64 hexadecimal characters",
			name,
		)
	}

	return strings.ToLower(value), nil
}
