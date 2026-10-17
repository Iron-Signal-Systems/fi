// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPackageManifestStrict(t *testing.T) {
	t.Parallel()

	path := filepath.Join(
		t.TempDir(),
		"manifest.json",
	)
	manifest := validTestPackageManifest()

	encoded, err := json.MarshalIndent(
		manifest,
		"",
		"  ",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	value, err := loadPackageManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.ReleaseID != manifest.ReleaseID {
		t.Fatalf(
			"release_id=%q",
			value.ReleaseID,
		)
	}
	if len(value.Files) != 5 {
		t.Fatalf(
			"files=%d",
			len(value.Files),
		)
	}
}

func TestLoadPackageManifestRejectsUnknownField(t *testing.T) {
	t.Parallel()

	path := filepath.Join(
		t.TempDir(),
		"manifest.json",
	)
	value := `{
  "version":"1.0",
  "product":"FI Windows Source",
  "release_id":"test",
  "platform":"windows",
  "architecture":"amd64",
  "unexpected":true,
  "files":[]
}`
	if err := os.WriteFile(
		path,
		[]byte(value),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	_, err := loadPackageManifest(path)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"unknown field",
		) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestValidatePackageManifestRejectsDuplicateRole(t *testing.T) {
	t.Parallel()

	manifest := validTestPackageManifest()
	manifest.Files[3] = manifest.Files[0]

	err := validatePackageManifest(manifest)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"duplicate runtime role",
		) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestValidatePackageManifestRejectsPath(t *testing.T) {
	t.Parallel()

	manifest := validTestPackageManifest()
	manifest.Files[0].Name = `bin\fi-collector.exe`

	err := validatePackageManifest(manifest)
	if err == nil {
		t.Fatal(
			"expected bare-file-name validation failure",
		)
	}
}

func TestValidatePackageManifestRejectsBadHash(t *testing.T) {
	t.Parallel()

	manifest := validTestPackageManifest()
	manifest.Files[0].SHA256 = "not-a-hash"

	err := validatePackageManifest(manifest)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"invalid SHA-256",
		) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestPackagePayloadHashComparisonInputs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}

	payload := filepath.Join(bin, "fi-collector.exe")
	if err := os.WriteFile(
		payload,
		[]byte("FI payload"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	hash, err := fileSHA256(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !isSHA256Hex(hash) {
		t.Fatalf("payload hash=%q", hash)
	}
}

func validTestPackageManifest() PackageManifest {
	hash := strings.Repeat("A", 64)

	return PackageManifest{
		Architecture: "amd64",
		Files: []PackageManifestFile{
			{
				Name:   "fi-collector.exe",
				Role:   "FICollector",
				SHA256: hash,
			},
			{
				Name:   "fi-usn-reader.exe",
				Role:   "FIUSNReader",
				SHA256: hash,
			},
			{
				Name:   "fi-obj-reader.exe",
				Role:   "FIObjReader",
				SHA256: hash,
			},
			{
				Name:   "fi-crl-refresher.exe",
				Role:   "FICRLRefresher",
				SHA256: hash,
			},
			{
				Name:   "fi-sender.exe",
				Role:   "FISender",
				SHA256: hash,
			},
		},
		Platform:  "windows",
		Product:   "FI Windows Source",
		ReleaseID: "test-release",
		Version:   "1.0",
	}
}
