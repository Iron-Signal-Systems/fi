// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/releaselab"
)

const (
	developmentSigningRootName = "ISS FI Development Code Signing Root"
	developmentRootFilename    = "iss-lab-code-signing-root.cer"
	developmentCRLFilename     = "iss-lab-code-signing-root.crl"
)

type firstRunSigningTrust struct {
	crlPath             string
	rootPath            string
	rootHash            string
	rootSubject         string
	signerSubject       string
	signerHash          string
	releaseID           string
	sealed              map[string]string
	executable          string
	manifestPath        string
	signaturePath       string
	policyPath          string
	policySignaturePath string
	manifest            PackageManifest
}

// FirstRunDevelopmentSigningTrust runs before ordinary discovery.
// It only offers trust bootstrap for a clean development installation
// with a cryptographically valid signed manifest and a missing Windows
// signing root. It never overrides invalid signatures or policy.
func FirstRunDevelopmentSigningTrust(
	reader io.Reader,
	writer io.Writer,
) error {
	if reader == nil || writer == nil {
		return fmt.Errorf(
			"trust bootstrap requires interactive input and output",
		)
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf(
			"resolve FI installer executable: %w",
			err,
		)
	}

	executable, err = filepath.Abs(executable)
	if err != nil {
		return fmt.Errorf(
			"resolve FI installer absolute path: %w",
			err,
		)
	}

	// An already-trusted installer proceeds to normal discovery.
	// Normal discovery still enforces FI release authorization.
	if verifyAuthenticode(executable).Trusted {
		return nil
	}

	proposal, err := prepareFirstRunSigningTrust(executable)
	if err != nil {
		return fmt.Errorf(
			"first-run signing trust refused: %w",
			err,
		)
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI INSTALLER - FIRST-RUN DEVELOPMENT SIGNING TRUST")
	fmt.Fprintln(writer, "============================================================")

	fmt.Fprintf(
		writer,
		"Release:                %s\n",
		proposal.releaseID,
	)

	fmt.Fprintf(
		writer,
		"Manifest signer:        %s\n",
		proposal.signerSubject,
	)

	fmt.Fprintf(
		writer,
		"Manifest signer SHA256: %s\n",
		proposal.signerHash,
	)

	fmt.Fprintf(
		writer,
		"Signing root:           %s\n",
		proposal.rootSubject,
	)

	fmt.Fprintf(
		writer,
		"Signing root SHA256:    %s\n",
		proposal.rootHash,
	)

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "The manifest signature, pinned FI release policy, issuer chain,")
	fmt.Fprintln(writer, "CRL signature, and listed payload hashes were verified without")
	fmt.Fprintln(writer, "changing Windows trust. Authenticode will be rechecked afterwards.")
	fmt.Fprintln(writer, "Compare the root SHA256 with a separately trusted ISS release record.")
	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "Approving adds this DEVELOPMENT root to LocalMachine\\ROOT")
	fmt.Fprintln(writer, "and its CRL to LocalMachine\\CA. This affects machine-wide trust.")
	fmt.Fprintln(writer, "Type exactly TRUST-ROOT followed by the first 16 SHA256 digits")

	fmt.Fprintf(
		writer,
		"> TRUST-ROOT %s\n",
		proposal.rootHash[:16],
	)

	fmt.Fprint(writer, "Approval: ")

	scanner := bufio.NewScanner(reader)

	if !scanner.Scan() {
		if scanner.Err() != nil {
			return fmt.Errorf(
				"read trust approval: %w",
				scanner.Err(),
			)
		}

		return fmt.Errorf(
			"development signing trust was not approved",
		)
	}

	expected := "TRUST-ROOT " + proposal.rootHash[:16]

	if strings.TrimSpace(scanner.Text()) != expected {
		return fmt.Errorf(
			"development signing trust rejected; no changes made",
		)
	}

	// Recheck all relevant files before changing the certificate stores.
	if err := verifySealedFiles(proposal.sealed); err != nil {
		return fmt.Errorf(
			"release changed before trust bootstrap: %w",
			err,
		)
	}

	result, err := releaselab.TrustDevelopmentCodeSigningMaterial(
		proposal.rootPath,
		proposal.crlPath,
	)

	if err != nil {
		// The lower-level helper may have imported the root before
		// a CRL import failure. Never claim rollback without proof.
		return fmt.Errorf(
			"install development signing root/CRL: %w (inspect machine certificate stores for partial import)",
			err,
		)
	}

	if !strings.EqualFold(
		result.RootCertificateSHA256,
		proposal.rootHash,
	) {
		return fmt.Errorf(
			"installed development root fingerprint mismatch; STOP and inspect machine trust",
		)
	}

	// Post-bootstrap authentication is mandatory.
	if err := verifySealedFiles(proposal.sealed); err != nil {
		return undoFailedFirstRunTrust(
			proposal,
			result.CRLSHA256,
			err,
		)
	}

	if err := verifyBootstrappedSigningTrust(proposal); err != nil {
		return undoFailedFirstRunTrust(
			proposal,
			result.CRLSHA256,
			err,
		)
	}

	fmt.Fprintln(
		writer,
		"PASS: Windows-trusted Authenticode, manifest and release policy",
	)
	fmt.Fprintln(
		writer,
		"Continuing normal FI installer discovery and approvals.",
	)

	return nil
}

func undoFailedFirstRunTrust(
	proposal firstRunSigningTrust,
	crlHash string,
	cause error,
) error {
	err := releaselab.UntrustDevelopmentCodeSigningMaterial(
		proposal.rootHash,
		crlHash,
	)

	if err != nil {
		return fmt.Errorf(
			"post-bootstrap verification failed: %v; rollback failed: %w",
			cause,
			err,
		)
	}

	return fmt.Errorf(
		"post-bootstrap verification failed; development root/CRL removed: %w",
		cause,
	)
}

func prepareFirstRunSigningTrust(
	executable string,
) (firstRunSigningTrust, error) {
	root := filepath.Dir(executable)

	proposal := firstRunSigningTrust{
		executable:          executable,
		rootPath:            filepath.Join(root, developmentRootFilename),
		crlPath:             filepath.Join(root, developmentCRLFilename),
		manifestPath:        filepath.Join(root, "manifest.json"),
		signaturePath:       filepath.Join(root, "manifest.p7s"),
		policyPath:          filepath.Join(root, "release-trust.json"),
		policySignaturePath: filepath.Join(root, "release-trust.p7s"),
		sealed:              make(map[string]string),
	}

	// Never replace existing FI release-trust authority state through
	// a first-run bootstrap.
	installed := filepath.Join(
		installedReleaseTrustRoot,
		releaseTrustPolicyFileName,
	)

	if _, err := os.Lstat(installed); err == nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"installed FI release-trust policy already exists; refusing first-run bootstrap",
		)
	} else if !os.IsNotExist(err) {
		return firstRunSigningTrust{}, fmt.Errorf(
			"inspect installed FI release-trust policy: %w",
			err,
		)
	}

	// CryptVerifyDetachedMessageSignature verifies signed bytes
	// independently of Windows root-store trust.
	signature := verifyDetachedFileSignature(
		proposal.manifestPath,
		proposal.signaturePath,
		false,
	)

	if !signature.SignatureValid ||
		len(signature.signerCertificateDER) == 0 {
		return firstRunSigningTrust{}, fmt.Errorf(
			"manifest detached signature is not cryptographically valid: %s",
			signature.Error,
		)
	}

	// Bootstrap only when the failure is an untrusted/missing root.
	// No approval path for revoked, expired, or invalid signing.
	windowsSignature := verifyDetachedManifestSignature(
		proposal.manifestPath,
		proposal.signaturePath,
	)

	if windowsSignature.SignerChainTrusted {
		return firstRunSigningTrust{}, fmt.Errorf(
			"manifest signer is already trusted; installer Authenticode failure must be investigated",
		)
	}

	if !strings.Contains(
		windowsSignature.Error,
		"status=0x800B010A",
	) && !strings.Contains(
		windowsSignature.Error,
		"status=0x800B0109",
	) {
		return firstRunSigningTrust{}, fmt.Errorf(
			"not a missing-root trust error: %s",
			windowsSignature.Error,
		)
	}

	policy := discoverReleaseTrustDocument(
		proposal.policyPath,
		proposal.policySignaturePath,
		bootstrapReleasePolicyAuthoritySPKISHA256,
	)

	if !policy.Valid || !policy.AuthorityPinned {
		return firstRunSigningTrust{}, fmt.Errorf(
			"release policy is not signed by the pinned ISS authority: %s",
			policy.Error,
		)
	}

	if policy.Policy.Generation != 1 ||
		policy.Policy.PreviousPolicySHA256 !=
			releaseTrustBootstrapPreviousHash {
		return firstRunSigningTrust{}, fmt.Errorf(
			"first-run release policy must use generation=1 and BOOTSTRAP predecessor",
		)
	}

	if _, authorized := findReleaseTrustSignerByHashes(
		policy.Policy.ActiveSigners,
		signature.SignerCertSHA256,
		signature.SignerSPKISHA256,
	); !authorized {
		return firstRunSigningTrust{}, fmt.Errorf(
			"manifest signer is not an active FI release-policy signer",
		)
	}

	manifest, err := loadPackageManifest(
		proposal.manifestPath,
	)
	if err != nil {
		return firstRunSigningTrust{}, err
	}

	proposal.manifest = manifest
	proposal.releaseID = manifest.ReleaseID
	proposal.signerSubject = signature.SignerSubject
	proposal.signerHash = signature.SignerCertSHA256

	rootDER, err := readBoundedFile(
		proposal.rootPath,
		1<<20,
	)

	if err != nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"read development signing root: %w",
			err,
		)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"parse development signing root: %w",
			err,
		)
	}

	if rootCert.Subject.CommonName != developmentSigningRootName ||
		!rootCert.IsCA ||
		rootCert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		rootCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return firstRunSigningTrust{}, fmt.Errorf(
			"not the expected FI development code-signing CA",
		)
	}

	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"signing root is not self-signed: %w",
			err,
		)
	}

	signer, err := x509.ParseCertificate(
		signature.signerCertificateDER,
	)
	if err != nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"parse manifest release signer: %w",
			err,
		)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	chains, err := signer.Verify(
		x509.VerifyOptions{
			Roots:       roots,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			CurrentTime: time.Now(),
		},
	)

	if err != nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"manifest signer is not a valid code signer issued by the bundled root: %w",
			err,
		)
	}

	validChain := false

	for _, chain := range chains {
		if len(chain) == 2 && chain[1].Equal(rootCert) {
			validChain = true
		}
	}

	if !validChain {
		return firstRunSigningTrust{}, fmt.Errorf(
			"manifest signer chain does not terminate at the exact bundled FI development root",
		)
	}

	crlDER, err := readBoundedFile(
		proposal.crlPath,
		4<<20,
	)

	if err != nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"read development signing CRL: %w",
			err,
		)
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"parse development signing CRL: %w",
			err,
		)
	}

	if err := crl.CheckSignatureFrom(rootCert); err != nil {
		return firstRunSigningTrust{}, fmt.Errorf(
			"development signing CRL signature invalid: %w",
			err,
		)
	}

	now := time.Now()

	if now.Before(crl.ThisUpdate) ||
		!now.Before(crl.NextUpdate) {
		return firstRunSigningTrust{}, fmt.Errorf(
			"development signing CRL is not current",
		)
	}

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(signer.SerialNumber) == 0 {
			return firstRunSigningTrust{}, fmt.Errorf(
				"FI release signer is revoked",
			)
		}
	}

	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber.Cmp(signer.SerialNumber) == 0 {
			return firstRunSigningTrust{}, fmt.Errorf(
				"FI release signer is revoked",
			)
		}
	}

	// Validate all signed payload hashes before certificate-store changes.
	for _, file := range manifest.Files {
		path := filepath.Join(
			root,
			"bin",
			file.Name,
		)

		hash, err := fileSHA256(path)

		if err != nil ||
			!strings.EqualFold(hash, file.SHA256) {
			return firstRunSigningTrust{}, fmt.Errorf(
				"signed manifest payload mismatch: %s",
				file.Name,
			)
		}
	}

	proposal.rootSubject = rootCert.Subject.String()

	hash := sha256.Sum256(rootCert.Raw)
	proposal.rootHash = fmt.Sprintf("%X", hash[:])

	paths := []string{
		proposal.executable,
		proposal.rootPath,
		proposal.crlPath,
		proposal.manifestPath,
		proposal.signaturePath,
		proposal.policyPath,
		proposal.policySignaturePath,
	}

	paths = append(
		paths,
		payloadPaths(root, manifest)...,
	)

	for _, path := range paths {
		info, err := os.Lstat(path)

		if err != nil ||
			!info.Mode().IsRegular() {
			return firstRunSigningTrust{}, fmt.Errorf(
				"expected a regular, non-reparse package file: %s",
				path,
			)
		}

		hash, err := fileSHA256(path)
		if err != nil {
			return firstRunSigningTrust{}, fmt.Errorf(
				"hash package file %s: %w",
				path,
				err,
			)
		}

		proposal.sealed[path] = hash
	}

	return proposal, nil
}

func payloadPaths(
	root string,
	manifest PackageManifest,
) []string {
	paths := make(
		[]string,
		0,
		len(manifest.Files),
	)

	for _, file := range manifest.Files {
		paths = append(
			paths,
			filepath.Join(root, "bin", file.Name),
		)
	}

	return paths
}

func verifySealedFiles(
	sealed map[string]string,
) error {
	for path, expected := range sealed {
		info, err := os.Lstat(path)

		if err != nil ||
			!info.Mode().IsRegular() {
			return fmt.Errorf(
				"package input changed or became non-regular: %s",
				path,
			)
		}

		observed, err := fileSHA256(path)

		if err != nil ||
			!strings.EqualFold(observed, expected) {
			return fmt.Errorf(
				"package input SHA256 changed: %s",
				path,
			)
		}
	}

	return nil
}

func verifyBootstrappedSigningTrust(
	proposal firstRunSigningTrust,
) error {
	signature := verifyDetachedManifestSignature(
		proposal.manifestPath,
		proposal.signaturePath,
	)

	if !signature.SignatureValid ||
		!signature.SignerChainTrusted ||
		!strings.EqualFold(
			signature.SignerCertSHA256,
			proposal.signerHash,
		) {
		return fmt.Errorf(
			"manifest did not become Windows-trusted after bootstrap: %s",
			signature.Error,
		)
	}

	policy := discoverReleaseTrustDocument(
		proposal.policyPath,
		proposal.policySignaturePath,
		bootstrapReleasePolicyAuthoritySPKISHA256,
	)

	if !policy.Valid || !policy.AuthorityPinned {
		return fmt.Errorf(
			"pinned FI release policy did not verify after bootstrap: %s",
			policy.Error,
		)
	}

	check := func(path string) error {
		trust := verifyAuthenticode(path)

		if !trust.Trusted ||
			!strings.EqualFold(
				trust.SignerCertSHA256,
				signature.SignerCertSHA256,
			) ||
			!strings.EqualFold(
				trust.SignerSPKISHA256,
				signature.SignerSPKISHA256,
			) {
			return fmt.Errorf(
				"Windows Authenticode trust or signer identity failed for %s: %s",
				path,
				trust.Error,
			)
		}

		return nil
	}

	if err := check(proposal.executable); err != nil {
		return err
	}

	for _, path := range payloadPaths(
		filepath.Dir(proposal.executable),
		proposal.manifest,
	) {
		if err := check(path); err != nil {
			return err
		}
	}

	return nil
}
