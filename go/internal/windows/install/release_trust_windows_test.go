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

func TestLoadReleaseTrustPolicyStrict(t *testing.T) {
	t.Parallel()

	path := filepath.Join(
		t.TempDir(),
		releaseTrustPolicyFileName,
	)
	policy := validTestReleaseTrustPolicy()

	encoded, err := json.MarshalIndent(
		policy,
		"",
		"  ",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		encoded,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	value, err := loadReleaseTrustPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if value.Generation != 1 {
		t.Fatalf(
			"generation=%d",
			value.Generation,
		)
	}
	if len(value.ActiveSigners) != 1 {
		t.Fatalf(
			"active_signers=%d",
			len(value.ActiveSigners),
		)
	}
}

func TestLoadReleaseTrustPolicyRejectsUnknownField(t *testing.T) {
	t.Parallel()

	path := filepath.Join(
		t.TempDir(),
		releaseTrustPolicyFileName,
	)
	value := `{
  "version":"1.0",
  "publisher":"Iron Signal Systems",
  "generation":1,
  "previous_policy_sha256":"BOOTSTRAP",
  "active_signers":[],
  "next_signers":[],
  "unexpected":true
}`
	if err := os.WriteFile(
		path,
		[]byte(value),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	_, err := loadReleaseTrustPolicy(path)
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

func TestValidateReleaseTrustPolicyRejectsNullNextSigners(t *testing.T) {
	t.Parallel()

	policy := validTestReleaseTrustPolicy()
	policy.NextSigners = nil

	err := validateReleaseTrustPolicy(policy)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"next_signers",
		) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestValidateReleaseTrustPolicyRejectsDuplicateSPKI(t *testing.T) {
	t.Parallel()

	policy := validTestReleaseTrustPolicy()
	policy.NextSigners = []ReleaseTrustSigner{
		{
			CertificateSHA256: strings.Repeat(
				"C",
				64,
			),
			ID:         "iss-release-next",
			SPKISHA256: policy.ActiveSigners[0].SPKISHA256,
		},
	}

	err := validateReleaseTrustPolicy(policy)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"duplicate signer spki_sha256",
		) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}
}

func TestResolveReleaseTrustRejectsRollback(t *testing.T) {
	t.Parallel()

	state := ReleaseTrustState{
		Installed: ReleaseTrustDocumentState{
			Present: true,
			Valid:   true,
			Policy: ReleaseTrustPolicy{
				Generation: 2,
			},
			PolicySHA256: strings.Repeat(
				"A",
				64,
			),
		},
		Package: ReleaseTrustDocumentState{
			Present: true,
			Valid:   true,
			Policy: ReleaseTrustPolicy{
				Generation: 1,
			},
			PolicySHA256: strings.Repeat(
				"B",
				64,
			),
		},
	}

	resolveReleaseTrustState(
		&state,
		ManifestSignatureState{},
	)
	if !strings.Contains(
		state.Error,
		"rollback rejected",
	) {
		t.Fatalf(
			"error=%q",
			state.Error,
		)
	}
}

func TestResolveReleaseTrustAcceptsOneGenerationTransition(t *testing.T) {
	t.Parallel()

	active := ReleaseTrustSigner{
		CertificateSHA256: strings.Repeat(
			"A",
			64,
		),
		ID: "iss-release-a",
		SPKISHA256: strings.Repeat(
			"B",
			64,
		),
	}
	installedHash := strings.Repeat(
		"C",
		64,
	)

	state := ReleaseTrustState{
		Installed: ReleaseTrustDocumentState{
			Present: true,
			Valid:   true,
			Policy: ReleaseTrustPolicy{
				Generation: 1,
			},
			PolicySHA256: installedHash,
		},
		Package: ReleaseTrustDocumentState{
			Present: true,
			Valid:   true,
			Policy: ReleaseTrustPolicy{
				ActiveSigners: []ReleaseTrustSigner{
					active,
				},
				Generation:           2,
				NextSigners:          []ReleaseTrustSigner{},
				PreviousPolicySHA256: installedHash,
			},
			PolicySHA256: strings.Repeat(
				"D",
				64,
			),
		},
	}

	resolveReleaseTrustState(
		&state,
		ManifestSignatureState{
			SignatureValid:     true,
			SignerCertSHA256:   active.CertificateSHA256,
			SignerChainTrusted: true,
			SignerSPKISHA256:   active.SPKISHA256,
		},
	)

	if !state.TransitionAllowed {
		t.Fatalf(
			"transition_allowed=false error=%q",
			state.Error,
		)
	}
	if !state.ManifestSignerAuthorized {
		t.Fatalf(
			"manifest_signer_authorized=false error=%q",
			state.Error,
		)
	}
	if state.EffectivePolicySource != "package-transition" {
		t.Fatalf(
			"effective_source=%q",
			state.EffectivePolicySource,
		)
	}
}

func TestResolveReleaseTrustDoesNotAuthorizeNextSigner(t *testing.T) {
	t.Parallel()

	next := ReleaseTrustSigner{
		CertificateSHA256: strings.Repeat(
			"A",
			64,
		),
		ID: "iss-release-next",
		SPKISHA256: strings.Repeat(
			"B",
			64,
		),
	}

	state := ReleaseTrustState{
		Installed: ReleaseTrustDocumentState{
			Present: true,
			Valid:   true,
			Policy: ReleaseTrustPolicy{
				ActiveSigners: []ReleaseTrustSigner{
					{
						CertificateSHA256: strings.Repeat(
							"C",
							64,
						),
						ID: "iss-release-current",
						SPKISHA256: strings.Repeat(
							"D",
							64,
						),
					},
				},
				Generation:  1,
				NextSigners: []ReleaseTrustSigner{next},
			},
			PolicySHA256: strings.Repeat(
				"E",
				64,
			),
		},
	}

	resolveReleaseTrustState(
		&state,
		ManifestSignatureState{
			SignatureValid:     true,
			SignerCertSHA256:   next.CertificateSHA256,
			SignerChainTrusted: true,
			SignerSPKISHA256:   next.SPKISHA256,
		},
	)

	if state.ManifestSignerAuthorized {
		t.Fatal(
			"next signer unexpectedly authorized",
		)
	}
	if !state.ManifestSignerKnownNext {
		t.Fatalf(
			"next signer was not recognized: error=%q",
			state.Error,
		)
	}
}

func validTestReleaseTrustPolicy() ReleaseTrustPolicy {
	return ReleaseTrustPolicy{
		ActiveSigners: []ReleaseTrustSigner{
			{
				CertificateSHA256: strings.Repeat(
					"A",
					64,
				),
				ID: "iss-release-2026-a",
				SPKISHA256: strings.Repeat(
					"B",
					64,
				),
			},
		},
		Generation:           1,
		NextSigners:          []ReleaseTrustSigner{},
		PreviousPolicySHA256: releaseTrustBootstrapPreviousHash,
		Publisher:            releaseTrustPolicyPublisher,
		Version:              releaseTrustPolicyVersion,
	}
}
