// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package certstore

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"syscall"
	"unsafe"
)

const (
	certNcryptKeySpec             = uint32(0xffffffff)
	certStoreReadOnlyFlag         = uint32(0x00008000)
	certSystemStoreLocalMachine   = uint32(0x00020000)
	cryptAcquireCompareKeyFlag    = uint32(0x00000004)
	cryptAcquireOnlyNcryptKeyFlag = uint32(0x00040000)
	cryptAcquireSilentFlag        = uint32(0x00000040)
	cryptENotFound                = syscall.Errno(0x80092004)
	ncryptPadPKCS1Flag            = uintptr(0x00000002)
	ncryptPadPSSFlag              = uintptr(0x00000008)
	storeProviderSystemW          = uintptr(10)
)

const (
	StoreCA   = "CA"
	StoreMy   = "MY"
	StoreRoot = "ROOT"
)

var (
	crypt32DLL = syscall.NewLazyDLL("crypt32.dll")
	ncryptDLL  = syscall.NewLazyDLL("ncrypt.dll")

	certCloseStoreProc                    = crypt32DLL.NewProc("CertCloseStore")
	certFreeCertificateContextProc        = crypt32DLL.NewProc("CertFreeCertificateContext")
	certOpenStoreProc                     = crypt32DLL.NewProc("CertOpenStore")
	cryptAcquireCertificatePrivateKeyProc = crypt32DLL.NewProc("CryptAcquireCertificatePrivateKey")
	ncryptFreeObjectProc                  = ncryptDLL.NewProc("NCryptFreeObject")
	ncryptSignHashProc                    = ncryptDLL.NewProc("NCryptSignHash")
)

// SigningIdentity is one FI source identity whose private key remains inside
// the Windows CNG key provider. Signer is suitable for both crypto/tls client
// authentication and FI batch signing.
type SigningIdentity struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	signer      *cngRSASigner
}

type bcryptPKCS1PaddingInfo struct {
	AlgID *uint16
}

type bcryptPSSPaddingInfo struct {
	AlgID      *uint16
	SaltLength uint32
}

type cngRSASigner struct {
	certificate *x509.Certificate
	closed      bool
	handle      uintptr
	mustFree    bool
	mutex       sync.Mutex
}

// Close releases the acquired CNG key handle when Windows transferred handle
// ownership to FI. It is safe to call Close more than once.
func (identity *SigningIdentity) Close() error {
	if identity == nil || identity.signer == nil {
		return nil
	}

	return identity.signer.Close()
}

// LoadLocalMachineCertificate loads one exact certificate by SHA-256 from an
// allowed LocalMachine certificate store. No CurrentUser fallback is permitted.
func LoadLocalMachineCertificate(
	storeName string,
	certificateSHA256 string,
) (*x509.Certificate, error) {
	normalized, err := normalizeCertificateSHA256(certificateSHA256)
	if err != nil {
		return nil, err
	}

	store, err := openLocalMachineStore(storeName)
	if err != nil {
		return nil, err
	}
	defer closeCertificateStore(store)

	certificate, context, err := findCertificate(store, normalized)
	if err != nil {
		return nil, err
	}
	defer freeCertificateContext(context)

	return certificate, nil
}

// LoadLocalMachineSigningIdentity loads one exact RSA certificate from
// LocalMachine\MY and acquires its private key through CNG. Legacy CSP keys are
// rejected: FI does not export or copy the private key into Go memory.
func LoadLocalMachineSigningIdentity(
	certificateSHA256 string,
) (*SigningIdentity, error) {
	normalized, err := normalizeCertificateSHA256(certificateSHA256)
	if err != nil {
		return nil, err
	}

	store, err := openLocalMachineStore(StoreMy)
	if err != nil {
		return nil, err
	}
	defer closeCertificateStore(store)

	certificate, context, err := findCertificate(store, normalized)
	if err != nil {
		return nil, err
	}
	defer freeCertificateContext(context)
	if _, ok := certificate.PublicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New(
			"FI Windows signing certificate must use an RSA public key",
		)
	}

	signer, err := acquireCNGSigner(context, certificate)
	if err != nil {
		return nil, err
	}

	return &SigningIdentity{
		Certificate: certificate,
		Signer:      signer,
		signer:      signer,
	}, nil
}

// TLSCertificate returns the in-memory public certificate plus the CNG-backed
// crypto.Signer. The private key itself never leaves the Windows key provider.
func (identity *SigningIdentity) TLSCertificate() (tls.Certificate, error) {
	if identity == nil ||
		identity.Certificate == nil ||
		identity.Signer == nil {
		return tls.Certificate{}, errors.New(
			"Windows signing identity is incomplete",
		)
	}

	return tls.Certificate{
		Certificate: [][]byte{
			append([]byte(nil), identity.Certificate.Raw...),
		},
		PrivateKey: identity.Signer,
		Leaf:       identity.Certificate,
	}, nil
}

func acquireCNGSigner(
	context uintptr,
	certificate *x509.Certificate,
) (*cngRSASigner, error) {
	var keyHandle uintptr
	var keySpec uint32
	var callerFree uint32
	flags := uintptr(
		cryptAcquireCompareKeyFlag |
			cryptAcquireOnlyNcryptKeyFlag |
			cryptAcquireSilentFlag,
	)

	result, _, callErr := cryptAcquireCertificatePrivateKeyProc.Call(
		context,
		flags,
		0,
		uintptr(unsafe.Pointer(&keyHandle)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&callerFree)),
	)
	if result == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return nil, fmt.Errorf(
				"acquire FI Windows certificate private key: %w",
				callErr,
			)
		}

		return nil, errors.New(
			"acquire FI Windows certificate private key failed",
		)
	}

	if keyHandle == 0 || keySpec != certNcryptKeySpec {
		if keyHandle != 0 && callerFree != 0 {
			_, _, _ = ncryptFreeObjectProc.Call(keyHandle)
		}

		return nil, errors.New(
			"FI Windows certificate private key must be backed by CNG",
		)
	}

	return &cngRSASigner{
		certificate: certificate,
		handle:      keyHandle,
		mustFree:    callerFree != 0,
	}, nil
}

func closeCertificateStore(store uintptr) {
	if store != 0 {
		_, _, _ = certCloseStoreProc.Call(store, 0)
	}
}

func freeCertificateContext(context uintptr) {
	if context != 0 {
		_, _, _ = certFreeCertificateContextProc.Call(context)
	}
}

func (signer *cngRSASigner) Close() error {
	signer.mutex.Lock()
	defer signer.mutex.Unlock()

	if signer.closed {
		return nil
	}
	signer.closed = true

	if !signer.mustFree || signer.handle == 0 {
		signer.handle = 0
		return nil
	}

	status, _, _ := ncryptFreeObjectProc.Call(signer.handle)
	signer.handle = 0
	if status != 0 {
		return fmt.Errorf(
			"free FI Windows CNG key handle: status=0x%08x",
			uint32(status),
		)
	}

	return nil
}

func (signer *cngRSASigner) Public() crypto.PublicKey {
	if signer == nil || signer.certificate == nil {
		return nil
	}

	return signer.certificate.PublicKey
}

func (signer *cngRSASigner) Sign(
	_ io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) ([]byte, error) {
	signer.mutex.Lock()
	defer signer.mutex.Unlock()

	if signer.closed || signer.handle == 0 {
		return nil, errors.New("FI Windows CNG signer is closed")
	}
	if opts == nil {
		return nil, errors.New("FI Windows CNG signer options are required")
	}

	hash := opts.HashFunc()
	if !supportedHash(hash) {
		return nil, fmt.Errorf(
			"FI Windows CNG signer does not support hash %v",
			hash,
		)
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf(
			"FI Windows CNG signer digest length %d does not match %s size %d",
			len(digest),
			hash.String(),
			hash.Size(),
		)
	}

	algorithm, err := syscall.UTF16PtrFromString(
		hashAlgorithmName(hash),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"construct FI Windows CNG hash algorithm name: %w",
			err,
		)
	}

	var paddingInfo unsafe.Pointer
	var flags uintptr
	var pkcs1 bcryptPKCS1PaddingInfo
	var pss bcryptPSSPaddingInfo

	if pssOptions, ok := opts.(*rsa.PSSOptions); ok {
		saltLength, err := pssSaltLength(hash, pssOptions)
		if err != nil {
			return nil, err
		}

		pss = bcryptPSSPaddingInfo{
			AlgID:      algorithm,
			SaltLength: uint32(saltLength),
		}
		paddingInfo = unsafe.Pointer(&pss)
		flags = ncryptPadPSSFlag
	} else {
		pkcs1 = bcryptPKCS1PaddingInfo{AlgID: algorithm}
		paddingInfo = unsafe.Pointer(&pkcs1)
		flags = ncryptPadPKCS1Flag
	}

	var required uint32
	status, _, _ := ncryptSignHashProc.Call(
		signer.handle,
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&required)),
		flags,
	)
	if status != 0 {
		return nil, fmt.Errorf(
			"size FI Windows CNG signature: status=0x%08x",
			uint32(status),
		)
	}
	if required == 0 {
		return nil, errors.New("FI Windows CNG signature size is zero")
	}

	signature := make([]byte, int(required))
	var written uint32
	status, _, _ = ncryptSignHashProc.Call(
		signer.handle,
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&signature[0])),
		uintptr(len(signature)),
		uintptr(unsafe.Pointer(&written)),
		flags,
	)
	if status != 0 {
		return nil, fmt.Errorf(
			"create FI Windows CNG signature: status=0x%08x",
			uint32(status),
		)
	}
	if written == 0 || written > uint32(len(signature)) {
		return nil, errors.New(
			"FI Windows CNG signature returned an invalid byte count",
		)
	}

	return signature[:written], nil
}

func findCertificate(
	store uintptr,
	wantSHA256 string,
) (*x509.Certificate, uintptr, error) {
	var previous *syscall.CertContext

	for {
		context, err := syscall.CertEnumCertificatesInStore(
			syscall.Handle(store),
			previous,
		)
		if err != nil {
			if errors.Is(err, cryptENotFound) {
				return nil, 0, fmt.Errorf(
					"FI Windows certificate SHA-256 %s was not found",
					wantSHA256,
				)
			}

			return nil, 0, fmt.Errorf(
				"enumerate FI Windows certificate store: %w",
				err,
			)
		}
		if context == nil {
			return nil, 0, fmt.Errorf(
				"FI Windows certificate SHA-256 %s was not found",
				wantSHA256,
			)
		}
		previous = context

		if context.EncodedCert == nil || context.Length == 0 {
			continue
		}

		raw := append(
			[]byte(nil),
			unsafe.Slice(context.EncodedCert, int(context.Length))...,
		)
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}

		digest := sha256.Sum256(certificate.Raw)
		if hex.EncodeToString(digest[:]) == wantSHA256 {
			return certificate, uintptr(unsafe.Pointer(context)), nil
		}
	}
}

func hashAlgorithmName(hash crypto.Hash) string {
	switch hash {
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	case crypto.SHA512:
		return "SHA512"
	default:
		return ""
	}
}

func openLocalMachineStore(storeName string) (uintptr, error) {
	switch storeName {
	case StoreCA, StoreMy, StoreRoot:
	default:
		return 0, fmt.Errorf(
			"unsupported FI Windows certificate store %q",
			storeName,
		)
	}

	name, err := syscall.UTF16PtrFromString(storeName)
	if err != nil {
		return 0, fmt.Errorf(
			"construct FI Windows certificate store name: %w",
			err,
		)
	}

	store, _, callErr := certOpenStoreProc.Call(
		storeProviderSystemW,
		0,
		0,
		uintptr(certSystemStoreLocalMachine|certStoreReadOnlyFlag),
		uintptr(unsafe.Pointer(name)),
	)
	if store == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, fmt.Errorf(
				"open LocalMachine\\%s certificate store: %w",
				storeName,
				callErr,
			)
		}

		return 0, fmt.Errorf(
			"open LocalMachine\\%s certificate store failed",
			storeName,
		)
	}

	return store, nil
}

func pssSaltLength(
	hash crypto.Hash,
	options *rsa.PSSOptions,
) (int, error) {
	switch options.SaltLength {
	case rsa.PSSSaltLengthEqualsHash:
		return hash.Size(), nil
	case rsa.PSSSaltLengthAuto:
		return 0, errors.New(
			"FI Windows CNG signer requires an explicit RSA-PSS salt length",
		)
	default:
		if options.SaltLength <= 0 {
			return 0, fmt.Errorf(
				"unsupported FI Windows CNG PSS salt length %d",
				options.SaltLength,
			)
		}
		return options.SaltLength, nil
	}
}

func supportedHash(hash crypto.Hash) bool {
	switch hash {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}
