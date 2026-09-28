// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package releaselab

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32ReleaseLabDLL = windows.NewLazySystemDLL(
		"crypt32.dll",
	)
	procCertAddCRLContextToStore = crypt32ReleaseLabDLL.NewProc(
		"CertAddCRLContextToStore",
	)
	procCertCreateCRLContext = crypt32ReleaseLabDLL.NewProc(
		"CertCreateCRLContext",
	)
	procCertDeleteCRLFromStore = crypt32ReleaseLabDLL.NewProc(
		"CertDeleteCRLFromStore",
	)
	procCertEnumCRLsInStore = crypt32ReleaseLabDLL.NewProc(
		"CertEnumCRLsInStore",
	)
	procCertFreeCRLContext = crypt32ReleaseLabDLL.NewProc(
		"CertFreeCRLContext",
	)
)

type crlContext struct {
	EncodingType uint32
	EncodedCRL   *byte
	Length       uint32
	CRLInfo      unsafe.Pointer
	Store        windows.Handle
}

type DevelopmentCodeSigningTrustState struct {
	CRLSHA256             string
	RootCertificateSHA256 string
}

// TrustDevelopmentCodeSigningMaterial explicitly installs the development-only
// code-signing root into LocalMachine\ROOT and its CRL into LocalMachine\CA.
// It is never called implicitly.
func TrustDevelopmentCodeSigningMaterial(
	certificatePath string,
	crlPath string,
) (DevelopmentCodeSigningTrustState, error) {
	certificateValue, err := os.ReadFile(
		certificatePath,
	)
	if err != nil {
		return DevelopmentCodeSigningTrustState{}, fmt.Errorf(
			"read development code-signing root: %w",
			err,
		)
	}
	if len(certificateValue) == 0 {
		return DevelopmentCodeSigningTrustState{}, fmt.Errorf(
			"development code-signing root is empty",
		)
	}

	certificate, err := x509.ParseCertificate(
		certificateValue,
	)
	if err != nil {
		return DevelopmentCodeSigningTrustState{}, fmt.Errorf(
			"parse development code-signing root: %w",
			err,
		)
	}
	if !certificate.IsCA {
		return DevelopmentCodeSigningTrustState{}, fmt.Errorf(
			"development code-signing root is not a CA certificate",
		)
	}

	crlValue, err := os.ReadFile(
		crlPath,
	)
	if err != nil {
		return DevelopmentCodeSigningTrustState{}, fmt.Errorf(
			"read development code-signing CRL: %w",
			err,
		)
	}
	if len(crlValue) == 0 {
		return DevelopmentCodeSigningTrustState{}, fmt.Errorf(
			"development code-signing CRL is empty",
		)
	}
	if _, err := x509.ParseRevocationList(
		crlValue,
	); err != nil {
		return DevelopmentCodeSigningTrustState{}, fmt.Errorf(
			"parse development code-signing CRL: %w",
			err,
		)
	}

	if err := addCertificateToMachineStore(
		"ROOT",
		certificateValue,
	); err != nil {
		return DevelopmentCodeSigningTrustState{}, err
	}

	if err := addCRLToMachineStore(
		"CA",
		crlValue,
	); err != nil {
		return DevelopmentCodeSigningTrustState{}, err
	}

	certificateHash := sha256.Sum256(
		certificate.Raw,
	)
	crlHash := sha256.Sum256(
		crlValue,
	)

	return DevelopmentCodeSigningTrustState{
		CRLSHA256: strings.ToUpper(
			fmt.Sprintf(
				"%X",
				crlHash[:],
			),
		),
		RootCertificateSHA256: strings.ToUpper(
			fmt.Sprintf(
				"%X",
				certificateHash[:],
			),
		),
	}, nil
}

// UntrustDevelopmentCodeSigningMaterial removes the exact development CRL from
// LocalMachine\CA and the exact development root certificate from
// LocalMachine\ROOT.
func UntrustDevelopmentCodeSigningMaterial(
	certificateSHA256 string,
	crlSHA256 string,
) error {
	expectedCertificate, err := normalizeSHA256(
		certificateSHA256,
		"certificate",
	)
	if err != nil {
		return err
	}
	expectedCRL, err := normalizeSHA256(
		crlSHA256,
		"CRL",
	)
	if err != nil {
		return err
	}

	if err := deleteCRLFromMachineStore(
		"CA",
		expectedCRL,
	); err != nil {
		return err
	}

	if err := deleteCertificateFromMachineStore(
		"ROOT",
		expectedCertificate,
	); err != nil {
		return err
	}

	return nil
}

func addCertificateToMachineStore(
	storeName string,
	encoded []byte,
) error {
	store, err := openMachineStore(
		storeName,
	)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(
		store,
		0,
	)

	context, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|
			windows.PKCS_7_ASN_ENCODING,
		&encoded[0],
		uint32(len(encoded)),
	)
	if err != nil {
		return fmt.Errorf(
			"create certificate context for LocalMachine\\%s: %w",
			storeName,
			err,
		)
	}
	defer windows.CertFreeCertificateContext(
		context,
	)

	if err := windows.CertAddCertificateContextToStore(
		store,
		context,
		windows.CERT_STORE_ADD_REPLACE_EXISTING,
		nil,
	); err != nil {
		return fmt.Errorf(
			"add certificate to LocalMachine\\%s: %w",
			storeName,
			err,
		)
	}

	return nil
}

func addCRLToMachineStore(
	storeName string,
	encoded []byte,
) error {
	store, err := openMachineStore(
		storeName,
	)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(
		store,
		0,
	)

	context, err := createCRLContext(
		encoded,
	)
	if err != nil {
		return err
	}
	defer freeCRLContext(
		context,
	)

	result, _, callErr := procCertAddCRLContextToStore.Call(
		uintptr(store),
		uintptr(
			unsafe.Pointer(
				context,
			),
		),
		uintptr(windows.CERT_STORE_ADD_REPLACE_EXISTING),
		0,
	)
	if result == 0 {
		return fmt.Errorf(
			"add CRL to LocalMachine\\%s: %v",
			storeName,
			callErr,
		)
	}

	return nil
}

func createCRLContext(
	encoded []byte,
) (*crlContext, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf(
			"CRL bytes are empty",
		)
	}

	result, _, callErr := procCertCreateCRLContext.Call(
		uintptr(
			windows.X509_ASN_ENCODING|
				windows.PKCS_7_ASN_ENCODING,
		),
		uintptr(
			unsafe.Pointer(
				&encoded[0],
			),
		),
		uintptr(len(encoded)),
	)
	if result == 0 {
		return nil, fmt.Errorf(
			"create CRL context: %v",
			callErr,
		)
	}

	return (*crlContext)(
		unsafe.Pointer(
			result,
		),
	), nil
}

func deleteCertificateFromMachineStore(
	storeName string,
	expectedSHA256 string,
) error {
	store, err := openMachineStore(
		storeName,
	)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(
		store,
		0,
	)

	var previous *windows.CertContext
	for {
		context, enumErr := windows.CertEnumCertificatesInStore(
			store,
			previous,
		)
		previous = nil
		if enumErr != nil || context == nil {
			break
		}

		value := unsafe.Slice(
			context.EncodedCert,
			context.Length,
		)
		hash := sha256.Sum256(
			value,
		)
		observed := strings.ToUpper(
			fmt.Sprintf(
				"%X",
				hash[:],
			),
		)

		if observed == expectedSHA256 {
			duplicate := windows.CertDuplicateCertificateContext(
				context,
			)
			windows.CertFreeCertificateContext(
				context,
			)
			if duplicate == nil {
				return fmt.Errorf(
					"duplicate matching certificate context failed",
				)
			}
			if err := windows.CertDeleteCertificateFromStore(
				duplicate,
			); err != nil {
				return fmt.Errorf(
					"remove certificate SHA256=%s from LocalMachine\\%s: %w",
					expectedSHA256,
					storeName,
					err,
				)
			}
			return nil
		}

		previous = context
	}

	return fmt.Errorf(
		"certificate SHA256=%s was not found in LocalMachine\\%s",
		expectedSHA256,
		storeName,
	)
}

func deleteCRLFromMachineStore(
	storeName string,
	expectedSHA256 string,
) error {
	store, err := openMachineStore(
		storeName,
	)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(
		store,
		0,
	)

	var previous *crlContext
	for {
		context, enumErr := enumCRLsInStore(
			store,
			previous,
		)
		previous = nil
		if enumErr != nil || context == nil {
			break
		}

		value := unsafe.Slice(
			context.EncodedCRL,
			context.Length,
		)
		hash := sha256.Sum256(
			value,
		)
		observed := strings.ToUpper(
			fmt.Sprintf(
				"%X",
				hash[:],
			),
		)

		if observed == expectedSHA256 {
			if err := deleteCRLFromStore(
				context,
			); err != nil {
				return fmt.Errorf(
					"remove CRL SHA256=%s from LocalMachine\\%s: %w",
					expectedSHA256,
					storeName,
					err,
				)
			}
			return nil
		}

		previous = context
	}

	return fmt.Errorf(
		"CRL SHA256=%s was not found in LocalMachine\\%s",
		expectedSHA256,
		storeName,
	)
}

func deleteCRLFromStore(
	context *crlContext,
) error {
	result, _, callErr := procCertDeleteCRLFromStore.Call(
		uintptr(
			unsafe.Pointer(
				context,
			),
		),
	)
	if result == 0 {
		return callErr
	}
	return nil
}

func enumCRLsInStore(
	store windows.Handle,
	previous *crlContext,
) (*crlContext, error) {
	result, _, callErr := procCertEnumCRLsInStore.Call(
		uintptr(store),
		uintptr(
			unsafe.Pointer(
				previous,
			),
		),
	)
	if result == 0 {
		// Enumeration termination and a real failure both return nil. The caller
		// only needs a fail-closed "not found" outcome, so preserve a non-zero
		// native error when one is available.
		if callErr != windows.ERROR_SUCCESS {
			return nil, callErr
		}
		return nil, nil
	}

	return (*crlContext)(
		unsafe.Pointer(
			result,
		),
	), nil
}

func freeCRLContext(
	context *crlContext,
) {
	if context == nil {
		return
	}
	procCertFreeCRLContext.Call(
		uintptr(
			unsafe.Pointer(
				context,
			),
		),
	)
}

func normalizeSHA256(
	value string,
	kind string,
) (string, error) {
	normalized := strings.ToUpper(
		strings.TrimSpace(
			value,
		),
	)
	if len(normalized) != 64 {
		return "", fmt.Errorf(
			"%s SHA-256 must contain 64 hexadecimal characters",
			kind,
		)
	}
	for _, character := range normalized {
		if !strings.ContainsRune(
			"0123456789ABCDEF",
			character,
		) {
			return "", fmt.Errorf(
				"%s SHA-256 contains a non-hexadecimal character",
				kind,
			)
		}
	}
	return normalized, nil
}

func openMachineStore(
	storeName string,
) (windows.Handle, error) {
	storeNamePointer, err := windows.UTF16PtrFromString(
		storeName,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"encode %s store name: %w",
			storeName,
			err,
		)
	}

	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|
			windows.CERT_STORE_OPEN_EXISTING_FLAG,
		uintptr(
			unsafe.Pointer(
				storeNamePointer,
			),
		),
	)
	if err != nil {
		return 0, fmt.Errorf(
			"open LocalMachine\\%s store: %w",
			storeName,
			err,
		)
	}

	return store, nil
}
