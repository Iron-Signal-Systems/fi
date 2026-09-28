// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certChainRevocationCheckChainExcludeRoot = 0x40000000
	maxManifestSignatureBytes                = 4 << 20
	maxSignedManifestBytes                   = 1 << 20
)

var (
	crypt32DLL = windows.NewLazySystemDLL(
		"crypt32.dll",
	)
	procCryptVerifyDetachedMessageSignature = crypt32DLL.NewProc(
		"CryptVerifyDetachedMessageSignature",
	)
)

type cryptVerifyMessagePara struct {
	Size                   uint32
	MsgAndCertEncodingType uint32
	CryptProv              uintptr
	GetSignerCertificate   uintptr
	GetArg                 uintptr
	StrongSignPara         uintptr
}

type ManifestSignatureState struct {
	Error              string
	Path               string
	SignatureValid     bool
	SignerCertSHA256   string
	SignerChainTrusted bool
	SignerSPKISHA256   string
	SignerSubject      string
}

func verifyDetachedManifestSignature(
	manifestPath string,
	signaturePath string,
) ManifestSignatureState {
	return verifyDetachedFileSignature(
		manifestPath,
		signaturePath,
		true,
	)
}

func verifyDetachedFileSignature(
	contentPath string,
	signaturePath string,
	requireTrustedCodeSigningChain bool,
) ManifestSignatureState {
	state := ManifestSignatureState{
		Path: signaturePath,
	}

	manifest, err := readBoundedFile(
		contentPath,
		maxSignedManifestBytes,
	)
	if err != nil {
		state.Error = fmt.Sprintf(
			"read signed content: %v",
			err,
		)
		return state
	}

	signature, err := readBoundedFile(
		signaturePath,
		maxManifestSignatureBytes,
	)
	if err != nil {
		state.Error = fmt.Sprintf(
			"read detached signature: %v",
			err,
		)
		return state
	}

	if len(manifest) == 0 {
		state.Error = "signed content is empty"
		return state
	}
	if len(signature) == 0 {
		state.Error = "manifest.p7s is empty"
		return state
	}

	verifyPara := cryptVerifyMessagePara{
		Size: uint32(
			unsafe.Sizeof(
				cryptVerifyMessagePara{},
			),
		),
		MsgAndCertEncodingType: windows.X509_ASN_ENCODING |
			windows.PKCS_7_ASN_ENCODING,
	}

	toBeSigned := []uintptr{
		uintptr(
			unsafe.Pointer(
				&manifest[0],
			),
		),
	}
	toBeSignedLengths := []uint32{
		uint32(len(manifest)),
	}

	var signer *windows.CertContext

	result, _, callErr := procCryptVerifyDetachedMessageSignature.Call(
		uintptr(
			unsafe.Pointer(
				&verifyPara,
			),
		),
		0,
		uintptr(
			unsafe.Pointer(
				&signature[0],
			),
		),
		uintptr(len(signature)),
		1,
		uintptr(
			unsafe.Pointer(
				&toBeSigned[0],
			),
		),
		uintptr(
			unsafe.Pointer(
				&toBeSignedLengths[0],
			),
		),
		uintptr(
			unsafe.Pointer(
				&signer,
			),
		),
	)

	runtime.KeepAlive(manifest)
	runtime.KeepAlive(signature)
	runtime.KeepAlive(toBeSigned)
	runtime.KeepAlive(toBeSignedLengths)

	if result == 0 {
		state.Error = fmt.Sprintf(
			"CryptVerifyDetachedMessageSignature: %v",
			callErr,
		)
		return state
	}
	if signer == nil {
		state.Error = "detached signature verified but returned no signer certificate"
		return state
	}
	defer windows.CertFreeCertificateContext(
		signer,
	)

	state.SignatureValid = true

	certificateDER := unsafe.Slice(
		signer.EncodedCert,
		signer.Length,
	)
	certificateCopy := append(
		[]byte(nil),
		certificateDER...,
	)
	certificateHash := sha256.Sum256(
		certificateCopy,
	)
	state.SignerCertSHA256 = fmt.Sprintf(
		"%X",
		certificateHash[:],
	)

	certificate, err := x509.ParseCertificate(
		certificateCopy,
	)
	if err != nil {
		state.Error = fmt.Sprintf(
			"parse detached-signature signer certificate: %v",
			err,
		)
		return state
	}
	state.SignerSubject = certificate.Subject.String()

	spkiHash := sha256.Sum256(
		certificate.RawSubjectPublicKeyInfo,
	)
	state.SignerSPKISHA256 = fmt.Sprintf(
		"%X",
		spkiHash[:],
	)

	if requireTrustedCodeSigningChain {
		if err := verifyCodeSigningCertificateChain(
			signer,
		); err != nil {
			state.Error = err.Error()
			return state
		}
		state.SignerChainTrusted = true
	}

	return state
}

func verifyCodeSigningCertificateChain(
	signer *windows.CertContext,
) error {
	if signer == nil {
		return fmt.Errorf(
			"signer certificate is required",
		)
	}

	codeSigningOID := append(
		[]byte(
			"1.3.6.1.5.5.7.3.3",
		),
		0,
	)
	codeSigningOIDPointer := &codeSigningOID[0]

	chainPara := windows.CertChainPara{
		Size: uint32(
			unsafe.Sizeof(
				windows.CertChainPara{},
			),
		),
		URLRetrievalTimeout: 10_000,
	}
	chainPara.RequestedUsage.Type = windows.USAGE_MATCH_TYPE_AND
	chainPara.RequestedUsage.Usage.Length = 1
	chainPara.RequestedUsage.Usage.UsageIdentifiers = &codeSigningOIDPointer

	var chain *windows.CertChainContext
	err := windows.CertGetCertificateChain(
		0,
		signer,
		nil,
		signer.Store,
		&chainPara,
		certChainRevocationCheckChainExcludeRoot,
		0,
		&chain,
	)
	runtime.KeepAlive(codeSigningOID)
	runtime.KeepAlive(codeSigningOIDPointer)
	if err != nil {
		return fmt.Errorf(
			"build manifest signer code-signing chain: %w",
			err,
		)
	}
	if chain == nil {
		return fmt.Errorf(
			"build manifest signer code-signing chain: no chain returned",
		)
	}
	defer windows.CertFreeCertificateChain(
		chain,
	)

	policyPara := windows.CertChainPolicyPara{
		Size: uint32(
			unsafe.Sizeof(
				windows.CertChainPolicyPara{},
			),
		),
	}
	policyStatus := windows.CertChainPolicyStatus{
		Size: uint32(
			unsafe.Sizeof(
				windows.CertChainPolicyStatus{},
			),
		),
	}

	if err := windows.CertVerifyCertificateChainPolicy(
		windows.CERT_CHAIN_POLICY_BASE,
		chain,
		&policyPara,
		&policyStatus,
	); err != nil {
		return fmt.Errorf(
			"verify manifest signer certificate chain policy: %w",
			err,
		)
	}
	if policyStatus.Error != 0 {
		return fmt.Errorf(
			"verify manifest signer certificate chain policy: status=0x%08X chain_index=%d element_index=%d",
			policyStatus.Error,
			policyStatus.ChainIndex,
			policyStatus.ElementIndex,
		)
	}
	if chain.TrustStatus.ErrorStatus != 0 {
		return fmt.Errorf(
			"verify manifest signer certificate chain: trust_status=0x%08X",
			chain.TrustStatus.ErrorStatus,
		)
	}

	return nil
}

func readBoundedFile(
	path string,
	maximum int64,
) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf(
			"%s is a symbolic link; signed release inputs must be regular files",
			path,
		)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"%s is not a regular file",
			path,
		)
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf(
			"%s size=%d exceeds maximum=%d",
			path,
			info.Size(),
			maximum,
		)
	}

	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > maximum {
		return nil, fmt.Errorf(
			"%s read size=%d exceeds maximum=%d",
			path,
			len(value),
			maximum,
		)
	}
	return value, nil
}

func manifestSignatureSummary(
	state ManifestSignatureState,
) string {
	parts := []string{
		fmt.Sprintf(
			"signature_valid=%t",
			state.SignatureValid,
		),
		fmt.Sprintf(
			"signer_chain_trusted=%t",
			state.SignerChainTrusted,
		),
	}

	if state.SignerSubject != "" {
		parts = append(
			parts,
			"signer_subject="+state.SignerSubject,
		)
	}
	if state.SignerCertSHA256 != "" {
		parts = append(
			parts,
			"signer_cert_sha256="+state.SignerCertSHA256,
		)
	}
	if state.SignerSPKISHA256 != "" {
		parts = append(
			parts,
			"signer_spki_sha256="+state.SignerSPKISHA256,
		)
	}
	if state.Error != "" {
		parts = append(
			parts,
			"error="+state.Error,
		)
	}

	return strings.Join(
		parts,
		" ",
	)
}
