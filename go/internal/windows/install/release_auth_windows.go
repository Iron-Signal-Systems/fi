// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintrustReleaseAuthDLL = windows.NewLazySystemDLL(
		"wintrust.dll",
	)
	procWTHelperGetProvCertFromChain = wintrustReleaseAuthDLL.NewProc(
		"WTHelperGetProvCertFromChain",
	)
	procWTHelperGetProvSignerFromChain = wintrustReleaseAuthDLL.NewProc(
		"WTHelperGetProvSignerFromChain",
	)
	procWTHelperProvDataFromStateData = wintrustReleaseAuthDLL.NewProc(
		"WTHelperProvDataFromStateData",
	)
)

// cryptProviderCertHead describes only the leading fields of
// CRYPT_PROVIDER_CERT that FI needs. The Windows structure continues after
// Cert; those later fields are intentionally opaque here.
type cryptProviderCertHead struct {
	Size uint32
	Cert *windows.CertContext
}

type AuthenticodeState struct {
	Error               string
	Path                string
	SignerCertSHA256    string
	SignerIdentityError string
	SignerSPKISHA256    string
	SignerSubject       string
	Trusted             bool
}

func verifyAuthenticode(
	path string,
) AuthenticodeState {
	state := AuthenticodeState{
		Path: path,
	}

	pathPointer, err := windows.UTF16PtrFromString(
		path,
	)
	if err != nil {
		state.Error = fmt.Sprintf(
			"encode path: %v",
			err,
		)
		return state
	}

	fileInfo := windows.WinTrustFileInfo{
		Size: uint32(
			unsafe.Sizeof(
				windows.WinTrustFileInfo{},
			),
		),
		FilePath: pathPointer,
	}

	data := windows.WinTrustData{
		Size: uint32(
			unsafe.Sizeof(
				windows.WinTrustData{},
			),
		),
		UIChoice:         windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(
			&fileInfo,
		),
		StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
			windows.WTD_DISABLE_MD2_MD4,
		UIContext: windows.WTD_UICONTEXT_INSTALL,
	}

	verifyErr := windows.WinVerifyTrustEx(
		windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2,
		&data,
	)

	var identity AuthenticodeState
	var identityErr error
	if verifyErr == nil {
		identity, identityErr = authenticodeSignerIdentity(
			data.StateData,
		)
	}

	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(
		windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2,
		&data,
	)

	runtime.KeepAlive(pathPointer)
	runtime.KeepAlive(fileInfo)

	if verifyErr != nil {
		state.Error = fmt.Sprintf(
			"WinVerifyTrustEx: %v",
			verifyErr,
		)
		return state
	}
	if closeErr != nil {
		state.Error = fmt.Sprintf(
			"WinVerifyTrustEx close: %v",
			closeErr,
		)
		return state
	}

	state.Trusted = true
	if identityErr != nil {
		state.SignerIdentityError = identityErr.Error()
		return state
	}

	state.SignerCertSHA256 = identity.SignerCertSHA256
	state.SignerSPKISHA256 = identity.SignerSPKISHA256
	state.SignerSubject = identity.SignerSubject
	return state
}

func authenticodeSignerIdentity(
	stateData windows.Handle,
) (AuthenticodeState, error) {
	if stateData == 0 {
		return AuthenticodeState{}, fmt.Errorf(
			"WinVerifyTrust returned no provider state handle",
		)
	}

	providerData, _, _ := procWTHelperProvDataFromStateData.Call(
		uintptr(stateData),
	)
	if providerData == 0 {
		return AuthenticodeState{}, fmt.Errorf(
			"WTHelperProvDataFromStateData returned no provider data",
		)
	}

	providerSigner, _, _ := procWTHelperGetProvSignerFromChain.Call(
		providerData,
		0,
		0,
		0,
	)
	if providerSigner == 0 {
		return AuthenticodeState{}, fmt.Errorf(
			"WTHelperGetProvSignerFromChain returned no primary signer",
		)
	}

	providerCertificate, _, _ := procWTHelperGetProvCertFromChain.Call(
		providerSigner,
		0,
	)
	if providerCertificate == 0 {
		return AuthenticodeState{}, fmt.Errorf(
			"WTHelperGetProvCertFromChain returned no primary signer certificate",
		)
	}

	certificateHead := (*cryptProviderCertHead)(
		unsafe.Pointer(
			providerCertificate,
		),
	)
	if certificateHead.Cert == nil {
		return AuthenticodeState{}, fmt.Errorf(
			"Authenticode provider signer certificate context is nil",
		)
	}
	if certificateHead.Cert.EncodedCert == nil ||
		certificateHead.Cert.Length == 0 {
		return AuthenticodeState{}, fmt.Errorf(
			"Authenticode provider signer certificate is empty",
		)
	}

	certificateDER := unsafe.Slice(
		certificateHead.Cert.EncodedCert,
		certificateHead.Cert.Length,
	)
	certificateCopy := append(
		[]byte(nil),
		certificateDER...,
	)

	certificate, err := x509.ParseCertificate(
		certificateCopy,
	)
	if err != nil {
		return AuthenticodeState{}, fmt.Errorf(
			"parse Authenticode signer certificate: %w",
			err,
		)
	}

	certificateHash := sha256.Sum256(
		certificateCopy,
	)
	spkiHash := sha256.Sum256(
		certificate.RawSubjectPublicKeyInfo,
	)

	return AuthenticodeState{
		SignerCertSHA256: fmt.Sprintf(
			"%X",
			certificateHash[:],
		),
		SignerSPKISHA256: fmt.Sprintf(
			"%X",
			spkiHash[:],
		),
		SignerSubject: certificate.Subject.String(),
	}, nil
}
