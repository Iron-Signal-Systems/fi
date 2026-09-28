// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestAuthorizePackageAuthenticodeSignersAcceptsActiveSigner(t *testing.T) {
	t.Parallel()

	active := ReleaseTrustSigner{
		CertificateSHA256: strings.Repeat("A", 64),
		ID:                "iss-release-active",
		SPKISHA256:        strings.Repeat("B", 64),
	}
	report := Report{
		Package: PackageState{
			AuthenticodeSignerIdentitiesComplete:  true,
			InstallerAuthenticodeSignerCertSHA256: active.CertificateSHA256,
			InstallerAuthenticodeSignerSPKISHA256: active.SPKISHA256,
			InstallerAuthenticodeSignerSubject:    "CN=ISS Test Release Signer",
			Files: []PackageManifestFileState{
				{
					PayloadAuthenticodeSignerCertSHA256: active.CertificateSHA256,
					PayloadAuthenticodeSignerSPKISHA256: active.SPKISHA256,
					PayloadAuthenticodeSignerSubject:    "CN=ISS Test Release Signer",
					Role:                                "FICollector",
				},
				{
					PayloadAuthenticodeSignerCertSHA256: active.CertificateSHA256,
					PayloadAuthenticodeSignerSPKISHA256: active.SPKISHA256,
					PayloadAuthenticodeSignerSubject:    "CN=ISS Test Release Signer",
					Role:                                "FIUSNReader",
				},
			},
		},
	}

	authorizePackageAuthenticodeSigners(
		&report,
		ReleaseTrustPolicy{
			ActiveSigners: []ReleaseTrustSigner{active},
			NextSigners:   []ReleaseTrustSigner{},
		},
	)

	if !report.Package.InstallerAuthenticodeSignerAuthorized {
		t.Fatal("installer Authenticode signer was not authorized")
	}
	if report.Package.InstallerAuthenticodeSignerID != active.ID {
		t.Fatalf("installer signer_id=%q want=%q", report.Package.InstallerAuthenticodeSignerID, active.ID)
	}
	if !report.Package.AuthenticodeSignersAuthorized {
		t.Fatal("package Authenticode signers were not authorized")
	}
	for _, file := range report.Package.Files {
		if !file.PayloadAuthenticodeSignerAuthorized {
			t.Fatalf("%s signer was not authorized", file.Role)
		}
		if file.PayloadAuthenticodeSignerID != active.ID {
			t.Fatalf("%s signer_id=%q want=%q", file.Role, file.PayloadAuthenticodeSignerID, active.ID)
		}
	}
}

func TestAuthorizePackageAuthenticodeSignersRejectsWindowsTrustedButUnlistedSigner(t *testing.T) {
	t.Parallel()

	active := ReleaseTrustSigner{
		CertificateSHA256: strings.Repeat("A", 64),
		ID:                "iss-release-active",
		SPKISHA256:        strings.Repeat("B", 64),
	}
	report := Report{
		Package: PackageState{
			AuthenticodeSignerIdentitiesComplete:  true,
			InstallerAuthenticodeSignerCertSHA256: strings.Repeat("C", 64),
			InstallerAuthenticodeSignerSPKISHA256: strings.Repeat("D", 64),
			Files: []PackageManifestFileState{
				{
					PayloadAuthenticodeSignerCertSHA256: active.CertificateSHA256,
					PayloadAuthenticodeSignerSPKISHA256: active.SPKISHA256,
					Role:                                "FICollector",
				},
			},
		},
	}

	authorizePackageAuthenticodeSigners(
		&report,
		ReleaseTrustPolicy{
			ActiveSigners: []ReleaseTrustSigner{active},
			NextSigners:   []ReleaseTrustSigner{},
		},
	)

	if report.Package.InstallerAuthenticodeSignerAuthorized {
		t.Fatal("unlisted installer signer was unexpectedly authorized")
	}
	if report.Package.AuthenticodeSignersAuthorized {
		t.Fatal("package was unexpectedly authorized with an unlisted installer signer")
	}
}

func TestAuthorizePackageAuthenticodeSignersRejectsNextOnlySigner(t *testing.T) {
	t.Parallel()

	active := ReleaseTrustSigner{
		CertificateSHA256: strings.Repeat("A", 64),
		ID:                "iss-release-active",
		SPKISHA256:        strings.Repeat("B", 64),
	}
	next := ReleaseTrustSigner{
		CertificateSHA256: strings.Repeat("C", 64),
		ID:                "iss-release-next",
		SPKISHA256:        strings.Repeat("D", 64),
	}
	report := Report{
		Package: PackageState{
			AuthenticodeSignerIdentitiesComplete:  true,
			InstallerAuthenticodeSignerCertSHA256: next.CertificateSHA256,
			InstallerAuthenticodeSignerSPKISHA256: next.SPKISHA256,
			Files: []PackageManifestFileState{
				{
					PayloadAuthenticodeSignerCertSHA256: active.CertificateSHA256,
					PayloadAuthenticodeSignerSPKISHA256: active.SPKISHA256,
					Role:                                "FICollector",
				},
			},
		},
	}

	authorizePackageAuthenticodeSigners(
		&report,
		ReleaseTrustPolicy{
			ActiveSigners: []ReleaseTrustSigner{active},
			NextSigners:   []ReleaseTrustSigner{next},
		},
	)

	if report.Package.InstallerAuthenticodeSignerAuthorized {
		t.Fatal("next-only installer signer was unexpectedly authorized")
	}
	if !report.Package.InstallerAuthenticodeSignerKnownNext {
		t.Fatal("next-only installer signer was not recognized as staged")
	}
	if report.Package.AuthenticodeSignersAuthorized {
		t.Fatal("package was unexpectedly authorized with a next-only installer signer")
	}
}

func TestFindReleaseTrustSignerByHashesRequiresCertificateAndSPKI(t *testing.T) {
	t.Parallel()

	signer := ReleaseTrustSigner{
		CertificateSHA256: strings.Repeat("A", 64),
		ID:                "iss-release-active",
		SPKISHA256:        strings.Repeat("B", 64),
	}

	if _, ok := findReleaseTrustSignerByHashes(
		[]ReleaseTrustSigner{signer},
		signer.CertificateSHA256,
		signer.SPKISHA256,
	); !ok {
		t.Fatal("exact certificate/SPKI signer identity did not match")
	}

	if _, ok := findReleaseTrustSignerByHashes(
		[]ReleaseTrustSigner{signer},
		signer.CertificateSHA256,
		strings.Repeat("C", 64),
	); ok {
		t.Fatal("certificate-only match unexpectedly authorized mismatched SPKI")
	}
}
