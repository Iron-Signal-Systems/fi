// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releaselab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	signedPackageArchitecture = "amd64"
	signedPackagePlatform     = "windows"
	signedPackageProduct      = "FI Windows Source"
	signedPackageVersion      = "1.0"
)

type SignedPackageResult struct {
	ManifestPath    string
	OutputDirectory string
	Payloads        []SignedPackagePayload
}

type SignedPackagePayload struct {
	Name   string
	Role   string
	SHA256 string
}

type signedPackageManifest struct {
	Version      string                 `json:"version"`
	Product      string                 `json:"product"`
	ReleaseID    string                 `json:"release_id"`
	Platform     string                 `json:"platform"`
	Architecture string                 `json:"architecture"`
	Files        []SignedPackagePayload `json:"files"`
}

// BuildSignedPackage creates a complete development package without mutating
// any source executable. The output directory must not already exist.
//
// Authenticode changes PE bytes, so the sequencing is deliberate:
//  1. copy fi-install.exe and the four runtime binaries;
//  2. Authenticode-sign the copies;
//  3. hash the signed runtime binaries;
//  4. build manifest.json from those signed hashes;
//  5. sign manifest.json and release-trust.json.
func BuildSignedPackage(
	keysDirectory string,
	releaseID string,
	installerPath string,
	binaryRoot string,
	outputDirectory string,
) (SignedPackageResult, error) {
	releaseID = strings.TrimSpace(
		releaseID,
	)
	if releaseID == "" {
		return SignedPackageResult{}, fmt.Errorf(
			"release ID is required",
		)
	}
	if strings.ContainsAny(
		releaseID,
		"\r\n\t",
	) {
		return SignedPackageResult{}, fmt.Errorf(
			"release ID contains control whitespace",
		)
	}

	outputRoot, err := filepath.Abs(
		outputDirectory,
	)
	if err != nil {
		return SignedPackageResult{}, fmt.Errorf(
			"resolve package output directory: %w",
			err,
		)
	}
	if _, err := os.Stat(outputRoot); err == nil {
		return SignedPackageResult{}, fmt.Errorf(
			"refusing to overwrite existing package output directory %s",
			outputRoot,
		)
	} else if !os.IsNotExist(err) {
		return SignedPackageResult{}, fmt.Errorf(
			"stat package output directory %s: %w",
			outputRoot,
			err,
		)
	}

	if err := os.MkdirAll(
		filepath.Join(
			outputRoot,
			"bin",
		),
		0o755,
	); err != nil {
		return SignedPackageResult{}, fmt.Errorf(
			"create package output directory: %w",
			err,
		)
	}

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(
				outputRoot,
			)
		}
	}()

	installerOutput := filepath.Join(
		outputRoot,
		"fi-install.exe",
	)
	if err := copyRegularFile(
		installerPath,
		installerOutput,
	); err != nil {
		return SignedPackageResult{}, err
	}

	payloadSpecs := []SignedPackagePayload{
		{
			Name: "fi.exe",
			Role: "FICollector",
		},
		{
			Name: "fi-usn.exe",
			Role: "FIUSNReader",
		},
		{
			Name: "fi-obj.exe",
			Role: "FIObjReader",
		},
		{
			Name: "fi-sender.exe",
			Role: "FISender",
		},
	}

	for index := range payloadSpecs {
		source := filepath.Join(
			binaryRoot,
			payloadSpecs[index].Name,
		)
		destination := filepath.Join(
			outputRoot,
			"bin",
			payloadSpecs[index].Name,
		)
		if err := copyRegularFile(
			source,
			destination,
		); err != nil {
			return SignedPackageResult{}, err
		}
	}

	if err := SignAuthenticodeFile(
		keysDirectory,
		installerOutput,
	); err != nil {
		return SignedPackageResult{}, fmt.Errorf(
			"Authenticode-sign fi-install.exe: %w",
			err,
		)
	}

	for index := range payloadSpecs {
		path := filepath.Join(
			outputRoot,
			"bin",
			payloadSpecs[index].Name,
		)
		if err := SignAuthenticodeFile(
			keysDirectory,
			path,
		); err != nil {
			return SignedPackageResult{}, fmt.Errorf(
				"Authenticode-sign %s: %w",
				payloadSpecs[index].Name,
				err,
			)
		}

		hash, err := fileSHA256(
			path,
		)
		if err != nil {
			return SignedPackageResult{}, err
		}
		payloadSpecs[index].SHA256 = hash
	}

	manifest := signedPackageManifest{
		Version:      signedPackageVersion,
		Product:      signedPackageProduct,
		ReleaseID:    releaseID,
		Platform:     signedPackagePlatform,
		Architecture: signedPackageArchitecture,
		Files:        payloadSpecs,
	}
	manifestValue, err := json.MarshalIndent(
		manifest,
		"",
		"  ",
	)
	if err != nil {
		return SignedPackageResult{}, fmt.Errorf(
			"encode signed-package manifest: %w",
			err,
		)
	}
	manifestValue = append(
		manifestValue,
		'\n',
	)
	manifestPath := filepath.Join(
		outputRoot,
		ManifestFileName,
	)
	if err := os.WriteFile(
		manifestPath,
		manifestValue,
		0o644,
	); err != nil {
		return SignedPackageResult{}, fmt.Errorf(
			"write signed-package manifest: %w",
			err,
		)
	}

	if err := SignPackagePublicMetadata(
		keysDirectory,
		manifestPath,
		outputRoot,
	); err != nil {
		return SignedPackageResult{}, err
	}

	cleanup = false
	return SignedPackageResult{
		ManifestPath:    manifestPath,
		OutputDirectory: outputRoot,
		Payloads:        payloadSpecs,
	}, nil
}

func copyRegularFile(
	source string,
	destination string,
) error {
	info, err := os.Lstat(
		source,
	)
	if err != nil {
		return fmt.Errorf(
			"stat package input %s: %w",
			source,
			err,
		)
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return fmt.Errorf(
			"package input must be a regular non-symlink file: %s",
			source,
		)
	}

	input, err := os.Open(
		source,
	)
	if err != nil {
		return fmt.Errorf(
			"open package input %s: %w",
			source,
			err,
		)
	}
	defer input.Close()

	output, err := os.OpenFile(
		destination,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o755,
	)
	if err != nil {
		return fmt.Errorf(
			"create package output %s: %w",
			destination,
			err,
		)
	}

	if _, err := io.Copy(
		output,
		input,
	); err != nil {
		output.Close()
		return fmt.Errorf(
			"copy %s to %s: %w",
			source,
			destination,
			err,
		)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf(
			"close package output %s: %w",
			destination,
			err,
		)
	}
	return nil
}

func fileSHA256(
	path string,
) (string, error) {
	file, err := os.Open(
		path,
	)
	if err != nil {
		return "", fmt.Errorf(
			"open %s for SHA-256: %w",
			path,
			err,
		)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(
		hash,
		file,
	); err != nil {
		return "", fmt.Errorf(
			"hash %s: %w",
			path,
			err,
		)
	}

	return strings.ToUpper(
		hex.EncodeToString(
			hash.Sum(nil),
		),
	), nil
}
