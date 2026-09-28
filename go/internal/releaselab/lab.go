// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releaselab

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/releasecms"
)

const (
	CodeSigningCRLFileName      = "iss-lab-code-signing-root.crl"
	CodeSigningRootCertFileName = "iss-lab-code-signing-root.cer"
	CodeSigningRootKeyFileName  = "iss-lab-code-signing-root-key.pem"
	ManifestFileName            = "manifest.json"
	ManifestSignatureFileName   = "manifest.p7s"
	PolicyAuthorityCertFileName = "iss-lab-policy-authority.cer"
	PolicyAuthorityKeyFileName  = "iss-lab-policy-authority-key.pem"
	PolicyAuthorityPinFileName  = "policy-authority-spki-sha256.txt"
	ReleaseSignerCertFileName   = "iss-lab-release-signer.cer"
	ReleaseSignerKeyFileName    = "iss-lab-release-signer-key.pem"
	ReleaseTrustFileName        = "release-trust.json"
	ReleaseTrustSignatureName   = "release-trust.p7s"
)

const (
	releaseTrustPublisher = "Iron Signal Systems"
	releaseTrustVersion   = "1.0"
)

type InitResult struct {
	CodeSigningRootCertSHA256 string
	OutputDirectory           string
	PolicyAuthoritySPKISHA256 string
	ReleaseSignerCertSHA256   string
	ReleaseSignerSPKISHA256   string
}

type releaseTrustPolicy struct {
	ActiveSigners        []releaseTrustSigner `json:"active_signers"`
	Generation           uint64               `json:"generation"`
	NextSigners          []releaseTrustSigner `json:"next_signers"`
	PreviousPolicySHA256 string               `json:"previous_policy_sha256"`
	Publisher            string               `json:"publisher"`
	Version              string               `json:"version"`
}

type releaseTrustSigner struct {
	CertificateSHA256 string `json:"certificate_sha256"`
	ID                string `json:"id"`
	SPKISHA256        string `json:"spki_sha256"`
}

// Initialize creates a development-only release policy authority, a development
// code-signing root, and a development release signer. It refuses to overwrite
// existing private-key material.
func Initialize(
	outputDirectory string,
) (InitResult, error) {
	root, err := filepath.Abs(
		outputDirectory,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"resolve output directory: %w",
			err,
		)
	}

	if err := os.MkdirAll(
		root,
		0o700,
	); err != nil {
		return InitResult{}, fmt.Errorf(
			"create output directory %s: %w",
			root,
			err,
		)
	}

	for _, name := range []string{
		CodeSigningRootKeyFileName,
		PolicyAuthorityKeyFileName,
		ReleaseSignerKeyFileName,
	} {
		path := filepath.Join(
			root,
			name,
		)
		if _, err := os.Stat(path); err == nil {
			return InitResult{}, fmt.Errorf(
				"refusing to overwrite existing private key %s",
				path,
			)
		} else if !os.IsNotExist(err) {
			return InitResult{}, fmt.Errorf(
				"stat private key %s: %w",
				path,
				err,
			)
		}
	}

	now := time.Now().UTC()

	policyAuthorityKey, err := rsa.GenerateKey(
		rand.Reader,
		3072,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"generate policy authority key: %w",
			err,
		)
	}
	policyAuthorityTemplate, err := certificateTemplate(
		"ISS FI Development Release Policy Authority",
		now,
		now.AddDate(10, 0, 0),
		false,
	)
	if err != nil {
		return InitResult{}, err
	}
	policyAuthorityTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	policyAuthorityDER, err := x509.CreateCertificate(
		rand.Reader,
		policyAuthorityTemplate,
		policyAuthorityTemplate,
		&policyAuthorityKey.PublicKey,
		policyAuthorityKey,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"create policy authority certificate: %w",
			err,
		)
	}
	policyAuthorityCert, err := x509.ParseCertificate(
		policyAuthorityDER,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"parse policy authority certificate: %w",
			err,
		)
	}

	codeSigningRootKey, err := rsa.GenerateKey(
		rand.Reader,
		3072,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"generate code-signing root key: %w",
			err,
		)
	}
	codeSigningRootTemplate, err := certificateTemplate(
		"ISS FI Development Code Signing Root",
		now,
		now.AddDate(10, 0, 0),
		true,
	)
	if err != nil {
		return InitResult{}, err
	}
	codeSigningRootTemplate.KeyUsage = x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign |
		x509.KeyUsageDigitalSignature
	codeSigningRootDER, err := x509.CreateCertificate(
		rand.Reader,
		codeSigningRootTemplate,
		codeSigningRootTemplate,
		&codeSigningRootKey.PublicKey,
		codeSigningRootKey,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"create code-signing root certificate: %w",
			err,
		)
	}
	codeSigningRootCert, err := x509.ParseCertificate(
		codeSigningRootDER,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"parse code-signing root certificate: %w",
			err,
		)
	}

	releaseSignerKey, err := rsa.GenerateKey(
		rand.Reader,
		3072,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"generate release signer key: %w",
			err,
		)
	}
	releaseSignerTemplate, err := certificateTemplate(
		"ISS FI Development Release Signer",
		now,
		now.AddDate(2, 0, 0),
		false,
	)
	if err != nil {
		return InitResult{}, err
	}
	releaseSignerTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	releaseSignerTemplate.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageCodeSigning,
	}
	releaseSignerTemplate.CRLDistributionPoints = []string{
		"file:///C:/Temp/" + CodeSigningCRLFileName,
	}
	releaseSignerTemplate.AuthorityKeyId = append(
		[]byte(nil),
		codeSigningRootCert.SubjectKeyId...,
	)
	releaseSignerDER, err := x509.CreateCertificate(
		rand.Reader,
		releaseSignerTemplate,
		codeSigningRootCert,
		&releaseSignerKey.PublicKey,
		codeSigningRootKey,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"create release signer certificate: %w",
			err,
		)
	}
	releaseSignerCert, err := x509.ParseCertificate(
		releaseSignerDER,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"parse release signer certificate: %w",
			err,
		)
	}

	crlTemplate := &x509.RevocationList{
		Number: big.NewInt(1),
		NextUpdate: now.Add(
			30 * 24 * time.Hour,
		),
		ThisUpdate: now.Add(
			-time.Hour,
		),
	}
	crlDER, err := x509.CreateRevocationList(
		rand.Reader,
		crlTemplate,
		codeSigningRootCert,
		codeSigningRootKey,
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"create development code-signing CRL: %w",
			err,
		)
	}

	policyAuthoritySPKI := sha256.Sum256(
		policyAuthorityCert.RawSubjectPublicKeyInfo,
	)
	releaseSignerCertHash := sha256.Sum256(
		releaseSignerCert.Raw,
	)
	releaseSignerSPKI := sha256.Sum256(
		releaseSignerCert.RawSubjectPublicKeyInfo,
	)
	codeSigningRootCertHash := sha256.Sum256(
		codeSigningRootCert.Raw,
	)

	policy := releaseTrustPolicy{
		ActiveSigners: []releaseTrustSigner{
			{
				CertificateSHA256: strings.ToUpper(
					hex.EncodeToString(
						releaseSignerCertHash[:],
					),
				),
				ID: "iss-fi-development-release-a",
				SPKISHA256: strings.ToUpper(
					hex.EncodeToString(
						releaseSignerSPKI[:],
					),
				),
			},
		},
		Generation:           1,
		NextSigners:          []releaseTrustSigner{},
		PreviousPolicySHA256: "BOOTSTRAP",
		Publisher:            releaseTrustPublisher,
		Version:              releaseTrustVersion,
	}
	policyJSON, err := json.MarshalIndent(
		policy,
		"",
		"  ",
	)
	if err != nil {
		return InitResult{}, fmt.Errorf(
			"encode release-trust policy: %w",
			err,
		)
	}
	policyJSON = append(
		policyJSON,
		'\n',
	)

	files := []struct {
		data []byte
		mode os.FileMode
		name string
	}{
		{
			data: codeSigningRootDER,
			mode: 0o644,
			name: CodeSigningRootCertFileName,
		},
		{
			data: crlDER,
			mode: 0o644,
			name: CodeSigningCRLFileName,
		},
		{
			data: policyAuthorityDER,
			mode: 0o644,
			name: PolicyAuthorityCertFileName,
		},
		{
			data: releaseSignerDER,
			mode: 0o644,
			name: ReleaseSignerCertFileName,
		},
		{
			data: policyJSON,
			mode: 0o644,
			name: ReleaseTrustFileName,
		},
		{
			data: []byte(
				strings.ToUpper(
					hex.EncodeToString(
						policyAuthoritySPKI[:],
					),
				) + "\n",
			),
			mode: 0o644,
			name: PolicyAuthorityPinFileName,
		},
	}

	for _, file := range files {
		if err := writeNewFile(
			filepath.Join(
				root,
				file.name,
			),
			file.data,
			file.mode,
		); err != nil {
			return InitResult{}, err
		}
	}

	for _, keyFile := range []struct {
		key  *rsa.PrivateKey
		name string
	}{
		{
			key:  codeSigningRootKey,
			name: CodeSigningRootKeyFileName,
		},
		{
			key:  policyAuthorityKey,
			name: PolicyAuthorityKeyFileName,
		},
		{
			key:  releaseSignerKey,
			name: ReleaseSignerKeyFileName,
		},
	} {
		encodedKey, err := x509.MarshalPKCS8PrivateKey(
			keyFile.key,
		)
		if err != nil {
			return InitResult{}, fmt.Errorf(
				"encode private key %s: %w",
				keyFile.name,
				err,
			)
		}
		value := pem.EncodeToMemory(
			&pem.Block{
				Bytes: encodedKey,
				Type:  "PRIVATE KEY",
			},
		)
		if err := writeNewFile(
			filepath.Join(
				root,
				keyFile.name,
			),
			value,
			0o600,
		); err != nil {
			return InitResult{}, err
		}
	}

	return InitResult{
		CodeSigningRootCertSHA256: strings.ToUpper(
			hex.EncodeToString(
				codeSigningRootCertHash[:],
			),
		),
		OutputDirectory: root,
		PolicyAuthoritySPKISHA256: strings.ToUpper(
			hex.EncodeToString(
				policyAuthoritySPKI[:],
			),
		),
		ReleaseSignerCertSHA256: strings.ToUpper(
			hex.EncodeToString(
				releaseSignerCertHash[:],
			),
		),
		ReleaseSignerSPKISHA256: strings.ToUpper(
			hex.EncodeToString(
				releaseSignerSPKI[:],
			),
		),
	}, nil
}

// SignPackagePublicMetadata creates only public release artifacts in outputDirectory.
// Private keys remain under keysDirectory.
func SignPackagePublicMetadata(
	keysDirectory string,
	manifestPath string,
	outputDirectory string,
) error {
	keysRoot, err := filepath.Abs(
		keysDirectory,
	)
	if err != nil {
		return fmt.Errorf(
			"resolve keys directory: %w",
			err,
		)
	}
	outputRoot, err := filepath.Abs(
		outputDirectory,
	)
	if err != nil {
		return fmt.Errorf(
			"resolve output directory: %w",
			err,
		)
	}
	if err := os.MkdirAll(
		outputRoot,
		0o755,
	); err != nil {
		return fmt.Errorf(
			"create output directory: %w",
			err,
		)
	}

	manifest, err := os.ReadFile(
		manifestPath,
	)
	if err != nil {
		return fmt.Errorf(
			"read manifest %s: %w",
			manifestPath,
			err,
		)
	}
	if len(manifest) == 0 {
		return fmt.Errorf(
			"manifest %s is empty",
			manifestPath,
		)
	}

	policy, err := os.ReadFile(
		filepath.Join(
			keysRoot,
			ReleaseTrustFileName,
		),
	)
	if err != nil {
		return fmt.Errorf(
			"read release-trust policy: %w",
			err,
		)
	}

	policyAuthorityCert, err := loadCertificate(
		filepath.Join(
			keysRoot,
			PolicyAuthorityCertFileName,
		),
	)
	if err != nil {
		return err
	}
	policyAuthorityKey, err := loadPrivateKey(
		filepath.Join(
			keysRoot,
			PolicyAuthorityKeyFileName,
		),
	)
	if err != nil {
		return err
	}

	releaseSignerCert, err := loadCertificate(
		filepath.Join(
			keysRoot,
			ReleaseSignerCertFileName,
		),
	)
	if err != nil {
		return err
	}
	releaseSignerKey, err := loadPrivateKey(
		filepath.Join(
			keysRoot,
			ReleaseSignerKeyFileName,
		),
	)
	if err != nil {
		return err
	}

	policySignature, err := releasecms.SignDetached(
		policy,
		policyAuthorityCert,
		policyAuthorityKey,
	)
	if err != nil {
		return fmt.Errorf(
			"sign release-trust policy: %w",
			err,
		)
	}
	manifestSignature, err := releasecms.SignDetached(
		manifest,
		releaseSignerCert,
		releaseSignerKey,
	)
	if err != nil {
		return fmt.Errorf(
			"sign release manifest: %w",
			err,
		)
	}

	publicCopies := []struct {
		name   string
		source string
	}{
		{
			name:   CodeSigningCRLFileName,
			source: filepath.Join(keysRoot, CodeSigningCRLFileName),
		},
		{
			name:   CodeSigningRootCertFileName,
			source: filepath.Join(keysRoot, CodeSigningRootCertFileName),
		},
	}
	for _, copySpec := range publicCopies {
		value, err := os.ReadFile(
			copySpec.source,
		)
		if err != nil {
			return fmt.Errorf(
				"read public release artifact %s: %w",
				copySpec.source,
				err,
			)
		}
		if err := os.WriteFile(
			filepath.Join(
				outputRoot,
				copySpec.name,
			),
			value,
			0o644,
		); err != nil {
			return fmt.Errorf(
				"write public release artifact %s: %w",
				copySpec.name,
				err,
			)
		}
	}

	outputs := []struct {
		data []byte
		name string
	}{
		{
			data: manifest,
			name: ManifestFileName,
		},
		{
			data: manifestSignature,
			name: ManifestSignatureFileName,
		},
		{
			data: policy,
			name: ReleaseTrustFileName,
		},
		{
			data: policySignature,
			name: ReleaseTrustSignatureName,
		},
	}
	for _, output := range outputs {
		if err := os.WriteFile(
			filepath.Join(
				outputRoot,
				output.name,
			),
			output.data,
			0o644,
		); err != nil {
			return fmt.Errorf(
				"write release artifact %s: %w",
				output.name,
				err,
			)
		}
	}

	return nil
}

func certificateTemplate(
	commonName string,
	notBefore time.Time,
	notAfter time.Time,
	isCA bool,
) (*x509.Certificate, error) {
	serialLimit := new(
		big.Int,
	).Lsh(
		big.NewInt(1),
		128,
	)
	serial, err := rand.Int(
		rand.Reader,
		serialLimit,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"generate certificate serial: %w",
			err,
		)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(
			1,
		)
	}

	subjectKeyID := make(
		[]byte,
		20,
	)
	if _, err := rand.Read(subjectKeyID); err != nil {
		return nil, fmt.Errorf(
			"generate subject key identifier: %w",
			err,
		)
	}

	return &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		NotAfter:              notAfter,
		NotBefore:             notBefore.Add(-5 * time.Minute),
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Iron Signal Systems"},
		},
		SubjectKeyId: subjectKeyID,
	}, nil
}

func loadCertificate(
	path string,
) (*x509.Certificate, error) {
	value, err := os.ReadFile(
		path,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read certificate %s: %w",
			path,
			err,
		)
	}
	certificate, err := x509.ParseCertificate(
		value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse certificate %s: %w",
			path,
			err,
		)
	}
	return certificate, nil
}

func loadPrivateKey(
	path string,
) (*rsa.PrivateKey, error) {
	value, err := os.ReadFile(
		path,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read private key %s: %w",
			path,
			err,
		)
	}
	block, rest := pem.Decode(
		value,
	)
	if block == nil {
		return nil, fmt.Errorf(
			"decode private key %s: no PEM block",
			path,
		)
	}
	if len(
		strings.TrimSpace(
			string(rest),
		),
	) != 0 {
		return nil, fmt.Errorf(
			"decode private key %s: trailing data is not allowed",
			path,
		)
	}
	privateKeyValue, err := x509.ParsePKCS8PrivateKey(
		block.Bytes,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse private key %s: %w",
			path,
			err,
		)
	}
	privateKey, ok := privateKeyValue.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(
			"private key %s is %T; RSA is required",
			path,
			privateKeyValue,
		)
	}
	return privateKey, nil
}

func writeNewFile(
	path string,
	data []byte,
	mode os.FileMode,
) error {
	file, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		mode,
	)
	if err != nil {
		return fmt.Errorf(
			"create %s: %w",
			path,
			err,
		)
	}

	if _, err := file.Write(
		data,
	); err != nil {
		file.Close()
		return fmt.Errorf(
			"write %s: %w",
			path,
			err,
		)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf(
			"close %s: %w",
			path,
			err,
		)
	}
	return nil
}
