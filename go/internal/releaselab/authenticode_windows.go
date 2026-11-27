// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package releaselab

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	calgSHA256                    = 0x0000800C
	provRSAAES                    = 24
	signerCertPolicyChainNoRoot   = 0x00000008
	signerCertStoreChoice         = 0x00000002
	signerNoAttr                  = 0x00000000
	signerPrivateKeyContainer     = 0x00000002
	signerSubjectFile             = 0x00000001
	temporaryContainerRandomBytes = 16
)

const enhancedRSAAESProvider = "Microsoft Enhanced RSA and AES Cryptographic Provider"

var (
	advapi32AuthenticodeDLL = windows.NewLazySystemDLL(
		"advapi32.dll",
	)
	procCryptDestroyKey = advapi32AuthenticodeDLL.NewProc(
		"CryptDestroyKey",
	)
	procCryptImportKey = advapi32AuthenticodeDLL.NewProc(
		"CryptImportKey",
	)

	mssign32DLL = windows.NewLazySystemDLL(
		"mssign32.dll",
	)
	procSignerFreeSignerContext = mssign32DLL.NewProc(
		"SignerFreeSignerContext",
	)
	procSignerSignEx2 = mssign32DLL.NewProc(
		"SignerSignEx2",
	)
)

type signerCert struct {
	CbSize       uint32
	CertChoice   uint32
	CertInfo     uintptr
	WindowHandle windows.Handle
}

type signerCertStoreInfo struct {
	CbSize      uint32
	SigningCert *windows.CertContext
	CertPolicy  uint32
	CertStore   windows.Handle
}

type signerContext struct {
	CbSize uint32
	CbBlob uint32
	PbBlob *byte
}

type signerFileInfo struct {
	CbSize   uint32
	FileName *uint16
	File     windows.Handle
}

type signerProviderInfo struct {
	CbSize       uint32
	ProviderName *uint16
	ProviderType uint32
	KeySpec      uint32
	PvkChoice    uint32
	PvkInfo      uintptr
}

type signerSignatureInfo struct {
	CbSize          uint32
	HashAlgorithm   uint32
	AttrChoice      uint32
	AttrInfo        uintptr
	Authenticated   uintptr
	Unauthenticated uintptr
}

type signerSubjectInfo struct {
	CbSize        uint32
	Index         *uint32
	SubjectChoice uint32
	SubjectInfo   uintptr
}

// SignAuthenticodeFile applies a development Authenticode signature to filePath
// with the existing release-signer certificate/private key in keysDirectory.
//
// The RSA key is imported into a randomly named current-user CSP key container
// only for the duration of the signing operation. The container is deleted
// before this function returns.
func SignAuthenticodeFile(
	keysDirectory string,
	filePath string,
) error {
	fileInfo, err := os.Lstat(
		filePath,
	)
	if err != nil {
		return fmt.Errorf(
			"stat file to sign %s: %w",
			filePath,
			err,
		)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 ||
		!fileInfo.Mode().IsRegular() {
		return fmt.Errorf(
			"file to sign must be a regular non-symlink file: %s",
			filePath,
		)
	}

	certificatePath := filepathJoin(
		keysDirectory,
		ReleaseSignerCertFileName,
	)
	privateKeyPath := filepathJoin(
		keysDirectory,
		ReleaseSignerKeyFileName,
	)
	rootCertificatePath := filepathJoin(
		keysDirectory,
		CodeSigningRootCertFileName,
	)

	certificateValue, err := os.ReadFile(
		certificatePath,
	)
	if err != nil {
		return fmt.Errorf(
			"read release signer certificate: %w",
			err,
		)
	}
	certificate, err := x509.ParseCertificate(
		certificateValue,
	)
	if err != nil {
		return fmt.Errorf(
			"parse release signer certificate: %w",
			err,
		)
	}
	if !certificatePermitsCodeSigning(
		certificate,
	) {
		return fmt.Errorf(
			"release signer certificate does not permit Code Signing EKU",
		)
	}

	privateKey, err := loadPrivateKey(
		privateKeyPath,
	)
	if err != nil {
		return err
	}
	if err := requireCertificateMatchesPrivateKey(
		certificate,
		privateKey,
	); err != nil {
		return err
	}

	keyBlob, err := rsaPrivateKeyBlob(
		privateKey,
	)
	if err != nil {
		return fmt.Errorf(
			"encode release signer CryptoAPI PRIVATEKEYBLOB: %w",
			err,
		)
	}

	containerName, err := temporaryKeyContainerName()
	if err != nil {
		return err
	}
	containerPointer, err := windows.UTF16PtrFromString(
		containerName,
	)
	if err != nil {
		return fmt.Errorf(
			"encode temporary key-container name: %w",
			err,
		)
	}
	providerPointer, err := windows.UTF16PtrFromString(
		enhancedRSAAESProvider,
	)
	if err != nil {
		return fmt.Errorf(
			"encode CryptoAPI provider name: %w",
			err,
		)
	}

	var provider windows.Handle
	if err := windows.CryptAcquireContext(
		&provider,
		containerPointer,
		providerPointer,
		provRSAAES,
		windows.CRYPT_NEWKEYSET,
	); err != nil {
		return fmt.Errorf(
			"create temporary release-signing CSP key container %q: %w",
			containerName,
			err,
		)
	}

	containerCreated := true
	defer func() {
		if provider != 0 {
			_ = windows.CryptReleaseContext(
				provider,
				0,
			)
		}
		if containerCreated {
			deleteTemporaryKeyContainer(
				containerPointer,
				providerPointer,
			)
		}
	}()

	importedKey, err := cryptImportPrivateKey(
		provider,
		keyBlob,
	)
	if err != nil {
		return err
	}
	defer cryptDestroyKey(
		importedKey,
	)

	signingCertContext, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|
			windows.PKCS_7_ASN_ENCODING,
		&certificateValue[0],
		uint32(len(certificateValue)),
	)
	if err != nil {
		return fmt.Errorf(
			"create release signer certificate context: %w",
			err,
		)
	}
	defer windows.CertFreeCertificateContext(
		signingCertContext,
	)

	rootValue, err := os.ReadFile(
		rootCertificatePath,
	)
	if err != nil {
		return fmt.Errorf(
			"read code-signing root certificate: %w",
			err,
		)
	}
	rootContext, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|
			windows.PKCS_7_ASN_ENCODING,
		&rootValue[0],
		uint32(len(rootValue)),
	)
	if err != nil {
		return fmt.Errorf(
			"create code-signing root certificate context: %w",
			err,
		)
	}
	defer windows.CertFreeCertificateContext(
		rootContext,
	)

	additionalStore, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_MEMORY,
		windows.X509_ASN_ENCODING|
			windows.PKCS_7_ASN_ENCODING,
		0,
		0,
		0,
	)
	if err != nil {
		return fmt.Errorf(
			"open temporary in-memory certificate store: %w",
			err,
		)
	}
	defer windows.CertCloseStore(
		additionalStore,
		0,
	)

	if err := windows.CertAddCertificateContextToStore(
		additionalStore,
		rootContext,
		windows.CERT_STORE_ADD_REPLACE_EXISTING,
		nil,
	); err != nil {
		return fmt.Errorf(
			"add code-signing root to temporary certificate store: %w",
			err,
		)
	}

	fileNamePointer, err := windows.UTF16PtrFromString(
		filePath,
	)
	if err != nil {
		return fmt.Errorf(
			"encode file path for Authenticode signing: %w",
			err,
		)
	}

	file := signerFileInfo{
		CbSize: uint32(
			unsafe.Sizeof(
				signerFileInfo{},
			),
		),
		FileName: fileNamePointer,
	}
	index := uint32(0)
	subject := signerSubjectInfo{
		CbSize: uint32(
			unsafe.Sizeof(
				signerSubjectInfo{},
			),
		),
		Index:         &index,
		SubjectChoice: signerSubjectFile,
		SubjectInfo: uintptr(
			unsafe.Pointer(
				&file,
			),
		),
	}

	certStoreInfo := signerCertStoreInfo{
		CbSize: uint32(
			unsafe.Sizeof(
				signerCertStoreInfo{},
			),
		),
		SigningCert: signingCertContext,
		CertPolicy:  signerCertPolicyChainNoRoot,
		CertStore:   additionalStore,
	}
	signerCertificate := signerCert{
		CbSize: uint32(
			unsafe.Sizeof(
				signerCert{},
			),
		),
		CertChoice: signerCertStoreChoice,
		CertInfo: uintptr(
			unsafe.Pointer(
				&certStoreInfo,
			),
		),
	}

	signature := signerSignatureInfo{
		CbSize: uint32(
			unsafe.Sizeof(
				signerSignatureInfo{},
			),
		),
		HashAlgorithm: calgSHA256,
		AttrChoice:    signerNoAttr,
	}

	providerInfo := signerProviderInfo{
		CbSize: uint32(
			unsafe.Sizeof(
				signerProviderInfo{},
			),
		),
		ProviderName: providerPointer,
		ProviderType: provRSAAES,
		KeySpec:      windows.AT_SIGNATURE,
		PvkChoice:    signerPrivateKeyContainer,
		PvkInfo: uintptr(
			unsafe.Pointer(
				containerPointer,
			),
		),
	}

	var context *signerContext
	result, _, _ := procSignerSignEx2.Call(
		0,
		uintptr(
			unsafe.Pointer(
				&subject,
			),
		),
		uintptr(
			unsafe.Pointer(
				&signerCertificate,
			),
		),
		uintptr(
			unsafe.Pointer(
				&signature,
			),
		),
		uintptr(
			unsafe.Pointer(
				&providerInfo,
			),
		),
		0,
		0,
		0,
		0,
		0,
		uintptr(
			unsafe.Pointer(
				&context,
			),
		),
		0,
		0,
	)

	runtime.KeepAlive(
		keyBlob,
	)
	runtime.KeepAlive(
		certificateValue,
	)
	runtime.KeepAlive(
		rootValue,
	)
	runtime.KeepAlive(
		containerPointer,
	)
	runtime.KeepAlive(
		providerPointer,
	)
	runtime.KeepAlive(
		fileNamePointer,
	)

	if context != nil {
		procSignerFreeSignerContext.Call(
			uintptr(
				unsafe.Pointer(
					context,
				),
			),
		)
	}

	if uint32(result) != 0 {
		return fmt.Errorf(
			"SignerSignEx2 %s: HRESULT=0x%08X",
			filePath,
			uint32(result),
		)
	}

	return nil
}

func certificatePermitsCodeSigning(
	certificate *x509.Certificate,
) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

func requireCertificateMatchesPrivateKey(
	certificate *x509.Certificate,
	privateKey *rsa.PrivateKey,
) error {
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf(
			"release signer certificate public key is %T; RSA is required",
			certificate.PublicKey,
		)
	}
	if publicKey.N.Cmp(
		privateKey.N,
	) != 0 ||
		publicKey.E != privateKey.E {
		return fmt.Errorf(
			"release signer certificate does not match release signer private key",
		)
	}
	return nil
}

func temporaryKeyContainerName() (string, error) {
	random := make(
		[]byte,
		temporaryContainerRandomBytes,
	)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf(
			"generate temporary CSP key-container name: %w",
			err,
		)
	}
	return "FI-Release-Lab-" + strings.ToUpper(
		hex.EncodeToString(
			random,
		),
	), nil
}

func cryptImportPrivateKey(
	provider windows.Handle,
	encoded []byte,
) (windows.Handle, error) {
	if len(encoded) == 0 {
		return 0, fmt.Errorf(
			"CryptoAPI PRIVATEKEYBLOB is empty",
		)
	}

	var key windows.Handle
	result, _, callErr := procCryptImportKey.Call(
		uintptr(provider),
		uintptr(
			unsafe.Pointer(
				&encoded[0],
			),
		),
		uintptr(len(encoded)),
		0,
		0,
		uintptr(
			unsafe.Pointer(
				&key,
			),
		),
	)
	if result == 0 {
		return 0, fmt.Errorf(
			"CryptImportKey release signer PRIVATEKEYBLOB: %v",
			callErr,
		)
	}
	return key, nil
}

func cryptDestroyKey(
	key windows.Handle,
) {
	if key == 0 {
		return
	}
	procCryptDestroyKey.Call(
		uintptr(key),
	)
}

func deleteTemporaryKeyContainer(
	container *uint16,
	provider *uint16,
) {
	var ignored windows.Handle
	_ = windows.CryptAcquireContext(
		&ignored,
		container,
		provider,
		provRSAAES,
		windows.CRYPT_DELETEKEYSET,
	)
}

func filepathJoin(
	root string,
	name string,
) string {
	if strings.HasSuffix(
		root,
		`\`,
	) || strings.HasSuffix(
		root,
		`/`,
	) {
		return root + name
	}
	return root + string(os.PathSeparator) + name
}
