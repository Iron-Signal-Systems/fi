// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyDetachedManifestSignatureRejectsMissingSignature(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	manifestPath := filepath.Join(
		root,
		"manifest.json",
	)
	signaturePath := filepath.Join(
		root,
		"manifest.p7s",
	)

	if err := os.WriteFile(
		manifestPath,
		[]byte(`{"version":"1.0"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	state := verifyDetachedManifestSignature(
		manifestPath,
		signaturePath,
	)
	if state.SignatureValid {
		t.Fatal(
			"missing detached signature unexpectedly verified",
		)
	}
	if state.Error == "" {
		t.Fatal(
			"missing detached signature did not preserve an error",
		)
	}
}

func TestVerifyDetachedManifestSignatureRejectsGarbage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	manifestPath := filepath.Join(
		root,
		"manifest.json",
	)
	signaturePath := filepath.Join(
		root,
		"manifest.p7s",
	)

	if err := os.WriteFile(
		manifestPath,
		[]byte(`{"version":"1.0"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		signaturePath,
		[]byte("not a PKCS#7 detached signature"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	state := verifyDetachedManifestSignature(
		manifestPath,
		signaturePath,
	)
	if state.SignatureValid {
		t.Fatal(
			"garbage detached signature unexpectedly verified",
		)
	}
	if state.Error == "" {
		t.Fatal(
			"garbage detached signature did not preserve an error",
		)
	}
}
