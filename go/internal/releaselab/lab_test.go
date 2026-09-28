// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releaselab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeCreatesReleaseTrustPolicy(t *testing.T) {
	t.Parallel()

	root := filepath.Join(
		t.TempDir(),
		"keys",
	)
	result, err := Initialize(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyAuthoritySPKISHA256 == "" {
		t.Fatal(
			"policy authority SPKI hash is empty",
		)
	}
	if result.ReleaseSignerCertSHA256 == "" ||
		result.ReleaseSignerSPKISHA256 == "" {
		t.Fatal(
			"release signer hashes are empty",
		)
	}

	value, err := os.ReadFile(
		filepath.Join(
			root,
			ReleaseTrustFileName,
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	var policy releaseTrustPolicy
	if err := json.Unmarshal(
		value,
		&policy,
	); err != nil {
		t.Fatal(err)
	}
	if policy.Generation != 1 ||
		policy.PreviousPolicySHA256 != "BOOTSTRAP" {
		t.Fatalf(
			"unexpected bootstrap policy: %+v",
			policy,
		)
	}
	if len(policy.ActiveSigners) != 1 {
		t.Fatalf(
			"active_signers=%d",
			len(policy.ActiveSigners),
		)
	}
}

func TestInitializeRefusesPrivateKeyOverwrite(t *testing.T) {
	t.Parallel()

	root := filepath.Join(
		t.TempDir(),
		"keys",
	)
	if _, err := Initialize(root); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(root); err == nil {
		t.Fatal(
			"second Initialize unexpectedly overwrote key material",
		)
	}
}

func TestSignPackagePublicMetadataCreatesOnlyPublicArtifacts(t *testing.T) {
	t.Parallel()

	keys := filepath.Join(
		t.TempDir(),
		"keys",
	)
	if _, err := Initialize(keys); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(
		t.TempDir(),
		ManifestFileName,
	)
	if err := os.WriteFile(
		manifestPath,
		[]byte(`{"version":"1.0"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(
		t.TempDir(),
		"public",
	)
	if err := SignPackagePublicMetadata(
		keys,
		manifestPath,
		output,
	); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		CodeSigningCRLFileName,
		CodeSigningRootCertFileName,
		ManifestFileName,
		ManifestSignatureFileName,
		ReleaseTrustFileName,
		ReleaseTrustSignatureName,
	} {
		if _, err := os.Stat(
			filepath.Join(
				output,
				name,
			),
		); err != nil {
			t.Fatalf(
				"missing public artifact %s: %v",
				name,
				err,
			)
		}
	}

	for _, name := range []string{
		CodeSigningRootKeyFileName,
		PolicyAuthorityKeyFileName,
		ReleaseSignerKeyFileName,
	} {
		if _, err := os.Stat(
			filepath.Join(
				output,
				name,
			),
		); !os.IsNotExist(err) {
			t.Fatalf(
				"private key unexpectedly copied to public output: %s err=%v",
				name,
				err,
			)
		}
	}
}
