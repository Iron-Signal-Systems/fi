// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	installedReleaseTrustRoot         = `C:\ProgramData\FI\release-trust`
	releaseTrustBootstrapPreviousHash = "BOOTSTRAP"
	releaseTrustMaximumPolicyBytes    = 1 << 20
	releaseTrustMaximumSigners        = 8
	releaseTrustPolicyFileName        = "release-trust.json"
	releaseTrustPolicyPublisher       = "Iron Signal Systems"
	releaseTrustPolicySignatureName   = "release-trust.p7s"
	releaseTrustPolicyVersion         = "1.0"
)

// bootstrapReleasePolicyAuthoritySPKISHA256 is intentionally empty in source.
// A release build injects the offline Iron Signal Systems release-policy
// authority SPKI SHA-256 with -ldflags -X. Keeping the default empty preserves
// fail-closed developer builds and avoids committing private-environment trust
// material into source.
var bootstrapReleasePolicyAuthoritySPKISHA256 string

type ReleaseTrustDocumentState struct {
	AuthorityPinned bool
	Error           string
	Path            string
	Policy          ReleaseTrustPolicy
	PolicySHA256    string
	Present         bool
	Signature       ManifestSignatureState
	SignaturePath   string
	Valid           bool
}

type ReleaseTrustPolicy struct {
	ActiveSigners        []ReleaseTrustSigner `json:"active_signers"`
	Generation           uint64               `json:"generation"`
	NextSigners          []ReleaseTrustSigner `json:"next_signers"`
	PreviousPolicySHA256 string               `json:"previous_policy_sha256"`
	Publisher            string               `json:"publisher"`
	Version              string               `json:"version"`
}

type ReleaseTrustSigner struct {
	CertificateSHA256 string `json:"certificate_sha256"`
	ID                string `json:"id"`
	SPKISHA256        string `json:"spki_sha256"`
}

type ReleaseTrustState struct {
	BootstrapAuthorityConfigured bool
	BootstrapAuthoritySPKISHA256 string
	EffectivePolicy              ReleaseTrustPolicy
	EffectivePolicySource        string
	Error                        string
	Installed                    ReleaseTrustDocumentState
	ManifestSignerAuthorized     bool
	ManifestSignerID             string
	ManifestSignerKnownNext      bool
	Package                      ReleaseTrustDocumentState
	TransitionAllowed            bool
}

func discoverReleaseTrust(
	report *Report,
) {
	state := ReleaseTrustState{
		BootstrapAuthorityConfigured: isSHA256Hex(
			bootstrapReleasePolicyAuthoritySPKISHA256,
		),
		BootstrapAuthoritySPKISHA256: strings.ToUpper(
			strings.TrimSpace(
				bootstrapReleasePolicyAuthoritySPKISHA256,
			),
		),
	}

	state.Installed = discoverReleaseTrustDocument(
		filepath.Join(
			installedReleaseTrustRoot,
			releaseTrustPolicyFileName,
		),
		filepath.Join(
			installedReleaseTrustRoot,
			releaseTrustPolicySignatureName,
		),
		state.BootstrapAuthoritySPKISHA256,
	)
	state.Package = discoverReleaseTrustDocument(
		filepath.Join(
			report.Package.Root,
			releaseTrustPolicyFileName,
		),
		filepath.Join(
			report.Package.Root,
			releaseTrustPolicySignatureName,
		),
		state.BootstrapAuthoritySPKISHA256,
	)

	if state.BootstrapAuthorityConfigured {
		report.addCheck(
			checkPass,
			"ISS release-policy authority pin",
			"SPKI SHA256="+state.BootstrapAuthoritySPKISHA256,
		)
	} else {
		report.addCheck(
			checkFail,
			"ISS release-policy authority pin",
			"this installer build has no pinned Iron Signal Systems release-policy authority SPKI SHA-256",
		)
	}

	addReleaseTrustDocumentCheck(
		report,
		"installed FI release-trust policy",
		state.Installed,
	)
	addReleaseTrustDocumentCheck(
		report,
		"package FI release-trust policy",
		state.Package,
	)

	resolveReleaseTrustState(
		&state,
		report.Package.ManifestSignature,
	)
	authorizePackageAuthenticodeSigners(
		report,
		state.EffectivePolicy,
	)

	if state.ManifestSignerAuthorized {
		report.addCheck(
			checkPass,
			"FI release manifest signer authorization",
			fmt.Sprintf(
				"signer_id=%s source=%s cert_sha256=%s spki_sha256=%s",
				state.ManifestSignerID,
				state.EffectivePolicySource,
				report.Package.ManifestSignature.SignerCertSHA256,
				report.Package.ManifestSignature.SignerSPKISHA256,
			),
		)
	} else {
		detail := state.Error
		if detail == "" {
			detail = "manifest signer is not authorized by an effective FI release-trust policy"
		}
		report.addCheck(
			checkFail,
			"FI release manifest signer authorization",
			detail,
		)
	}

	report.ReleaseTrust = state
}

func discoverReleaseTrustDocument(
	path string,
	signaturePath string,
	authoritySPKISHA256 string,
) ReleaseTrustDocumentState {
	state := ReleaseTrustDocumentState{
		Path:          path,
		SignaturePath: signaturePath,
	}

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state
		}
		state.Error = fmt.Sprintf(
			"stat %s: %v",
			path,
			err,
		)
		return state
	}
	if !info.Mode().IsRegular() {
		state.Present = true
		state.Error = fmt.Sprintf(
			"%s is not a regular file",
			path,
		)
		return state
	}
	state.Present = true

	policy, err := loadReleaseTrustPolicy(
		path,
	)
	if err != nil {
		state.Error = err.Error()
		return state
	}
	state.Policy = policy

	hash, err := fileSHA256(path)
	if err != nil {
		state.Error = fmt.Sprintf(
			"hash release-trust policy %s: %v",
			path,
			err,
		)
		return state
	}
	state.PolicySHA256 = hash

	state.Signature = verifyDetachedFileSignature(
		path,
		signaturePath,
		false,
	)
	if !state.Signature.SignatureValid {
		state.Error = state.Signature.Error
		return state
	}

	state.AuthorityPinned = signerSPKIMatches(
		state.Signature.SignerSPKISHA256,
		authoritySPKISHA256,
	)
	if !state.AuthorityPinned {
		if !isSHA256Hex(authoritySPKISHA256) {
			state.Error = "release-policy authority SPKI pin is not configured in this installer build"
		} else {
			state.Error = fmt.Sprintf(
				"release-trust policy signer SPKI SHA256=%s does not match pinned ISS release-policy authority SPKI SHA256=%s",
				valueOrNotKnown(
					state.Signature.SignerSPKISHA256,
				),
				authoritySPKISHA256,
			)
		}
		return state
	}

	state.Valid = true
	return state
}

func addReleaseTrustDocumentCheck(
	report *Report,
	name string,
	state ReleaseTrustDocumentState,
) {
	if !state.Present {
		report.addCheck(
			checkInfo,
			name,
			state.Path+" is not present",
		)
		return
	}

	if !state.Valid {
		detail := state.Error
		if detail == "" {
			detail = "release-trust document is not valid"
		}
		report.addCheck(
			checkFail,
			name,
			detail,
		)
		return
	}

	report.addCheck(
		checkPass,
		name,
		fmt.Sprintf(
			"path=%s generation=%d policy_sha256=%s signer=%s signer_spki_sha256=%s",
			state.Path,
			state.Policy.Generation,
			state.PolicySHA256,
			state.Signature.SignerSubject,
			state.Signature.SignerSPKISHA256,
		),
	)
}

func loadReleaseTrustPolicy(
	path string,
) (ReleaseTrustPolicy, error) {
	file, err := os.Open(path)
	if err != nil {
		return ReleaseTrustPolicy{}, fmt.Errorf(
			"open FI release-trust policy %s: %w",
			path,
			err,
		)
	}
	defer file.Close()

	decoder := json.NewDecoder(
		io.LimitReader(
			file,
			releaseTrustMaximumPolicyBytes,
		),
	)
	decoder.DisallowUnknownFields()

	var policy ReleaseTrustPolicy
	if err := decoder.Decode(&policy); err != nil {
		return ReleaseTrustPolicy{}, fmt.Errorf(
			"parse FI release-trust policy %s: %w",
			path,
			err,
		)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ReleaseTrustPolicy{}, fmt.Errorf(
				"parse FI release-trust policy %s: multiple JSON values are not allowed",
				path,
			)
		}
		return ReleaseTrustPolicy{}, fmt.Errorf(
			"parse FI release-trust policy %s trailing content: %w",
			path,
			err,
		)
	}

	if err := validateReleaseTrustPolicy(policy); err != nil {
		return ReleaseTrustPolicy{}, fmt.Errorf(
			"validate FI release-trust policy %s: %w",
			path,
			err,
		)
	}

	return policy, nil
}

func validateReleaseTrustPolicy(
	policy ReleaseTrustPolicy,
) error {
	if policy.Version != releaseTrustPolicyVersion {
		return fmt.Errorf(
			"unsupported version %q; expected %q",
			policy.Version,
			releaseTrustPolicyVersion,
		)
	}
	if policy.Publisher != releaseTrustPolicyPublisher {
		return fmt.Errorf(
			"unexpected publisher %q; expected %q",
			policy.Publisher,
			releaseTrustPolicyPublisher,
		)
	}
	if policy.Generation == 0 {
		return fmt.Errorf(
			"generation must be greater than zero",
		)
	}

	previous := strings.TrimSpace(
		policy.PreviousPolicySHA256,
	)
	if policy.Generation == 1 {
		if previous != releaseTrustBootstrapPreviousHash {
			return fmt.Errorf(
				"generation 1 previous_policy_sha256=%q expected %q",
				policy.PreviousPolicySHA256,
				releaseTrustBootstrapPreviousHash,
			)
		}
	} else if !isSHA256Hex(previous) {
		return fmt.Errorf(
			"generation %d previous_policy_sha256 must be a SHA-256 value",
			policy.Generation,
		)
	}

	if policy.ActiveSigners == nil {
		return fmt.Errorf(
			"active_signers is required and must not be null",
		)
	}
	if len(policy.ActiveSigners) == 0 {
		return fmt.Errorf(
			"active_signers must contain at least one signer",
		)
	}
	if policy.NextSigners == nil {
		return fmt.Errorf(
			"next_signers is required and must not be null; use [] when none are staged",
		)
	}
	if len(policy.ActiveSigners)+len(policy.NextSigners) >
		releaseTrustMaximumSigners {
		return fmt.Errorf(
			"active_signers + next_signers exceeds maximum=%d",
			releaseTrustMaximumSigners,
		)
	}

	seenIDs := make(map[string]struct{})
	seenCertificateHashes := make(map[string]struct{})
	seenSPKIHashes := make(map[string]struct{})

	for _, group := range []struct {
		name    string
		signers []ReleaseTrustSigner
	}{
		{
			name:    "active_signers",
			signers: policy.ActiveSigners,
		},
		{
			name:    "next_signers",
			signers: policy.NextSigners,
		},
	} {
		for index, signer := range group.signers {
			if err := validateReleaseTrustSigner(
				signer,
			); err != nil {
				return fmt.Errorf(
					"%s[%d]: %w",
					group.name,
					index,
					err,
				)
			}

			id := strings.ToLower(
				strings.TrimSpace(
					signer.ID,
				),
			)
			certificateHash := strings.ToUpper(
				strings.TrimSpace(
					signer.CertificateSHA256,
				),
			)
			spkiHash := strings.ToUpper(
				strings.TrimSpace(
					signer.SPKISHA256,
				),
			)

			if _, exists := seenIDs[id]; exists {
				return fmt.Errorf(
					"duplicate signer id %q",
					signer.ID,
				)
			}
			if _, exists := seenCertificateHashes[certificateHash]; exists {
				return fmt.Errorf(
					"duplicate signer certificate_sha256 %s",
					certificateHash,
				)
			}
			if _, exists := seenSPKIHashes[spkiHash]; exists {
				return fmt.Errorf(
					"duplicate signer spki_sha256 %s",
					spkiHash,
				)
			}

			seenIDs[id] = struct{}{}
			seenCertificateHashes[certificateHash] = struct{}{}
			seenSPKIHashes[spkiHash] = struct{}{}
		}
	}

	return nil
}

func validateReleaseTrustSigner(
	signer ReleaseTrustSigner,
) error {
	id := strings.TrimSpace(
		signer.ID,
	)
	if id == "" {
		return fmt.Errorf(
			"id is required",
		)
	}
	if len(id) > 64 {
		return fmt.Errorf(
			"id length=%d exceeds maximum=64",
			len(id),
		)
	}
	for _, value := range id {
		switch {
		case value >= 'a' && value <= 'z':
		case value >= 'A' && value <= 'Z':
		case value >= '0' && value <= '9':
		case value == '-':
		case value == '_':
		case value == '.':
		default:
			return fmt.Errorf(
				"id %q contains unsupported character %q",
				id,
				value,
			)
		}
	}

	if !isSHA256Hex(
		signer.CertificateSHA256,
	) {
		return fmt.Errorf(
			"certificate_sha256=%q is not a SHA-256 value",
			signer.CertificateSHA256,
		)
	}
	if !isSHA256Hex(
		signer.SPKISHA256,
	) {
		return fmt.Errorf(
			"spki_sha256=%q is not a SHA-256 value",
			signer.SPKISHA256,
		)
	}

	return nil
}

func resolveReleaseTrustState(
	state *ReleaseTrustState,
	manifestSigner ManifestSignatureState,
) {
	if state == nil {
		return
	}

	var effective *ReleaseTrustDocumentState

	switch {
	case state.Installed.Present && !state.Installed.Valid:
		state.Error = "installed FI release-trust policy exists but is not valid; package policy cannot replace an untrusted installed authority state"
		return

	case state.Installed.Valid && !state.Package.Present:
		effective = &state.Installed
		state.EffectivePolicySource = "installed"
		state.TransitionAllowed = true

	case state.Installed.Valid && state.Package.Present && !state.Package.Valid:
		state.Error = "package supplies a release-trust policy but that policy is not valid"
		return

	case state.Installed.Valid && state.Package.Valid:
		switch {
		case state.Package.Policy.Generation <
			state.Installed.Policy.Generation:
			state.Error = fmt.Sprintf(
				"release-trust rollback rejected: installed generation=%d package generation=%d",
				state.Installed.Policy.Generation,
				state.Package.Policy.Generation,
			)
			return

		case state.Package.Policy.Generation ==
			state.Installed.Policy.Generation:
			if !strings.EqualFold(
				state.Package.PolicySHA256,
				state.Installed.PolicySHA256,
			) {
				state.Error = fmt.Sprintf(
					"release-trust generation=%d has different installed/package policy hashes",
					state.Package.Policy.Generation,
				)
				return
			}
			effective = &state.Installed
			state.EffectivePolicySource = "installed/package-identical"
			state.TransitionAllowed = true

		case state.Package.Policy.Generation !=
			state.Installed.Policy.Generation+1:
			state.Error = fmt.Sprintf(
				"release-trust transition must advance exactly one generation: installed=%d package=%d",
				state.Installed.Policy.Generation,
				state.Package.Policy.Generation,
			)
			return

		case !strings.EqualFold(
			state.Package.Policy.PreviousPolicySHA256,
			state.Installed.PolicySHA256,
		):
			state.Error = fmt.Sprintf(
				"release-trust generation=%d previous_policy_sha256=%s does not match installed policy SHA256=%s",
				state.Package.Policy.Generation,
				state.Package.Policy.PreviousPolicySHA256,
				state.Installed.PolicySHA256,
			)
			return

		default:
			effective = &state.Package
			state.EffectivePolicySource = "package-transition"
			state.TransitionAllowed = true
		}

	case !state.Installed.Present && state.Package.Valid:
		if state.Package.Policy.Generation != 1 {
			state.Error = fmt.Sprintf(
				"first FI release-trust policy must use generation=1; package generation=%d",
				state.Package.Policy.Generation,
			)
			return
		}
		if state.Package.Policy.PreviousPolicySHA256 !=
			releaseTrustBootstrapPreviousHash {
			state.Error = fmt.Sprintf(
				"first FI release-trust policy previous_policy_sha256=%q expected %q",
				state.Package.Policy.PreviousPolicySHA256,
				releaseTrustBootstrapPreviousHash,
			)
			return
		}
		effective = &state.Package
		state.EffectivePolicySource = "package-bootstrap"
		state.TransitionAllowed = true

	case !state.Installed.Present && state.Package.Present &&
		!state.Package.Valid:
		state.Error = "no installed FI release-trust policy exists and the package release-trust policy is not valid"
		return

	default:
		state.Error = "no installed or package FI release-trust policy is available"
		return
	}

	if effective == nil {
		state.Error = "no effective FI release-trust policy could be selected"
		return
	}
	state.EffectivePolicy = effective.Policy

	if !manifestSigner.SignatureValid ||
		!manifestSigner.SignerChainTrusted {
		state.Error = "release manifest signer cannot be authorized because manifest.p7s has not established a valid trusted signer"
		return
	}

	if signer, ok := findReleaseTrustSigner(
		effective.Policy.ActiveSigners,
		manifestSigner,
	); ok {
		state.ManifestSignerAuthorized = true
		state.ManifestSignerID = signer.ID
		return
	}

	if signer, ok := findReleaseTrustSigner(
		effective.Policy.NextSigners,
		manifestSigner,
	); ok {
		state.ManifestSignerKnownNext = true
		state.ManifestSignerID = signer.ID
		state.Error = fmt.Sprintf(
			"manifest signer=%s is staged only in next_signers and is not yet authorized for releases",
			signer.ID,
		)
		return
	}

	state.Error = fmt.Sprintf(
		"manifest signer cert_sha256=%s spki_sha256=%s is not listed in active_signers for effective release-trust source=%s",
		valueOrNotKnown(
			manifestSigner.SignerCertSHA256,
		),
		valueOrNotKnown(
			manifestSigner.SignerSPKISHA256,
		),
		state.EffectivePolicySource,
	)
}

func findReleaseTrustSigner(
	signers []ReleaseTrustSigner,
	state ManifestSignatureState,
) (ReleaseTrustSigner, bool) {
	return findReleaseTrustSignerByHashes(
		signers,
		state.SignerCertSHA256,
		state.SignerSPKISHA256,
	)
}

func findReleaseTrustSignerByHashes(
	signers []ReleaseTrustSigner,
	certificateSHA256 string,
	spkiSHA256 string,
) (ReleaseTrustSigner, bool) {
	certificateHash := strings.ToUpper(
		strings.TrimSpace(
			certificateSHA256,
		),
	)
	spkiHash := strings.ToUpper(
		strings.TrimSpace(
			spkiSHA256,
		),
	)

	if !isSHA256Hex(certificateHash) ||
		!isSHA256Hex(spkiHash) {
		return ReleaseTrustSigner{}, false
	}

	for _, signer := range signers {
		if strings.EqualFold(
			signer.CertificateSHA256,
			certificateHash,
		) &&
			strings.EqualFold(
				signer.SPKISHA256,
				spkiHash,
			) {
			return signer, true
		}
	}

	return ReleaseTrustSigner{}, false
}

func authorizePackageAuthenticodeSigners(
	report *Report,
	policy ReleaseTrustPolicy,
) {
	if report == nil {
		return
	}

	report.Package.InstallerAuthenticodeSignerAuthorized = false
	report.Package.InstallerAuthenticodeSignerID = ""
	report.Package.InstallerAuthenticodeSignerKnownNext = false
	report.Package.AuthenticodeSignersAuthorized = false

	if !report.Package.AuthenticodeSignerIdentitiesComplete {
		report.addCheck(
			checkFail,
			"FI package Authenticode signer identity completeness",
			"fi-install.exe and every manifest-listed payload must expose an Authenticode signer certificate SHA-256 and SPKI SHA-256 before release authorization",
		)
	} else {
		report.addCheck(
			checkPass,
			"FI package Authenticode signer identity completeness",
			"fi-install.exe and every manifest-listed payload expose primary Authenticode signer certificate and SPKI identities",
		)
	}

	if len(policy.ActiveSigners) == 0 {
		report.addCheck(
			checkFail,
			"FI installer Authenticode signer authorization",
			"no effective FI release-trust active_signers policy is available",
		)
		for index := range report.Package.Files {
			report.addCheck(
				checkFail,
				report.Package.Files[index].Role+" package payload Authenticode signer authorization",
				"no effective FI release-trust active_signers policy is available",
			)
		}
		return
	}

	authorizeAuthenticodeSigner(
		report,
		"FI installer Authenticode signer authorization",
		report.Package.InstallerAuthenticodeSignerCertSHA256,
		report.Package.InstallerAuthenticodeSignerSPKISHA256,
		report.Package.InstallerAuthenticodeSignerSubject,
		policy,
		func(authorized bool, id string, knownNext bool) {
			report.Package.InstallerAuthenticodeSignerAuthorized = authorized
			report.Package.InstallerAuthenticodeSignerID = id
			report.Package.InstallerAuthenticodeSignerKnownNext = knownNext
		},
	)

	allAuthorized := report.Package.InstallerAuthenticodeSignerAuthorized
	for index := range report.Package.Files {
		file := &report.Package.Files[index]
		authorizeAuthenticodeSigner(
			report,
			file.Role+" package payload Authenticode signer authorization",
			file.PayloadAuthenticodeSignerCertSHA256,
			file.PayloadAuthenticodeSignerSPKISHA256,
			file.PayloadAuthenticodeSignerSubject,
			policy,
			func(authorized bool, id string, knownNext bool) {
				file.PayloadAuthenticodeSignerAuthorized = authorized
				file.PayloadAuthenticodeSignerID = id
				file.PayloadAuthenticodeSignerKnownNext = knownNext
			},
		)
		if !file.PayloadAuthenticodeSignerAuthorized {
			allAuthorized = false
		}
	}

	report.Package.AuthenticodeSignersAuthorized = allAuthorized
}

func authorizeAuthenticodeSigner(
	report *Report,
	checkName string,
	certificateSHA256 string,
	spkiSHA256 string,
	subject string,
	policy ReleaseTrustPolicy,
	apply func(bool, string, bool),
) {
	if signer, ok := findReleaseTrustSignerByHashes(
		policy.ActiveSigners,
		certificateSHA256,
		spkiSHA256,
	); ok {
		apply(true, signer.ID, false)
		report.addCheck(
			checkPass,
			checkName,
			fmt.Sprintf(
				"signer_id=%s subject=%s cert_sha256=%s spki_sha256=%s",
				signer.ID,
				valueOrNotKnown(subject),
				certificateSHA256,
				spkiSHA256,
			),
		)
		return
	}

	if signer, ok := findReleaseTrustSignerByHashes(
		policy.NextSigners,
		certificateSHA256,
		spkiSHA256,
	); ok {
		apply(false, signer.ID, true)
		report.addCheck(
			checkFail,
			checkName,
			fmt.Sprintf(
				"signer_id=%s is staged only in next_signers and is not yet authorized for releases",
				signer.ID,
			),
		)
		return
	}

	apply(false, "", false)
	report.addCheck(
		checkFail,
		checkName,
		fmt.Sprintf(
			"cert_sha256=%s spki_sha256=%s is not listed in active_signers for the effective FI release-trust policy",
			valueOrNotKnown(certificateSHA256),
			valueOrNotKnown(spkiSHA256),
		),
	)
}

func signerSPKIMatches(
	observed string,
	expected string,
) bool {
	if !isSHA256Hex(observed) ||
		!isSHA256Hex(expected) {
		return false
	}
	return strings.EqualFold(
		observed,
		expected,
	)
}

func sortedReleaseTrustSigners(
	signers []ReleaseTrustSigner,
) []ReleaseTrustSigner {
	result := append(
		[]ReleaseTrustSigner(nil),
		signers...,
	)
	sort.Slice(
		result,
		func(left int, right int) bool {
			return result[left].ID < result[right].ID
		},
	)
	return result
}
