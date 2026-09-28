// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	certKeyProvInfoPropertyID = uint32(2)

	fiPKICNGProviderName = "Microsoft Software Key Storage Provider"

	ncryptMachineKeyFlag = uint32(0x00000020)
	ncryptSilentFlag     = uint32(0x00000040)
)

var (
	certDeleteCertificateFromStorePKIProc = crypt32PKIDLL.NewProc(
		"CertDeleteCertificateFromStore",
	)

	certFreeCertificateContextPKIProc = crypt32PKIDLL.NewProc(
		"CertFreeCertificateContext",
	)

	certGetCertificateContextPropertyPKIProc = crypt32PKIDLL.NewProc(
		"CertGetCertificateContextProperty",
	)

	ncryptPKIDLL = windows.NewLazySystemDLL(
		"ncrypt.dll",
	)

	ncryptDeleteKeyPKIProc = ncryptPKIDLL.NewProc(
		"NCryptDeleteKey",
	)

	ncryptFreeObjectPKIProc = ncryptPKIDLL.NewProc(
		"NCryptFreeObject",
	)

	ncryptOpenKeyPKIProc = ncryptPKIDLL.NewProc(
		"NCryptOpenKey",
	)

	ncryptOpenStorageProviderPKIProc = ncryptPKIDLL.NewProc(
		"NCryptOpenStorageProvider",
	)
)

type cngKeyLocator struct {
	KeyName      string
	KeySpec      uint32
	MachineKey   bool
	ProviderName string
}

type cryptKeyProvInfoPKI struct {
	ContainerName      *uint16
	ProviderName       *uint16
	ProviderType       uint32
	Flags              uint32
	ProviderParamCount uint32
	ProviderParams     uintptr
	KeySpec            uint32
}

func rollbackOwnedPKIEnrollment(
	mutation pkiEnrollmentMutation,
) error {
	if err := validateOwnedPKIRollbackMutation(
		mutation,
	); err != nil {
		return err
	}

	store, err := openLocalMachinePKIMutationStore()
	if err != nil {
		return err
	}
	defer closeLocalMachinePKIStore(
		store,
	)

	context, found, err :=
		findLocalMachinePKICertificateContextBySHA256(
			store,
			mutation.Certificate.CertificateSHA256,
		)
	if err != nil {
		return err
	}

	if !found {
		return nil
	}

	locator, err := cngKeyLocatorFromCertificateContext(
		context,
	)
	if err != nil {
		freeLocalMachinePKICertificateContext(
			context,
		)
		return err
	}

	if err := validateCNGKeyLocator(
		locator,
	); err != nil {
		freeLocalMachinePKICertificateContext(
			context,
		)
		return err
	}

	// Delete the private key first. This certificate is transaction-owned
	// and has not yet become an authoritative FI runtime identity.
	if err := deleteCNGKey(
		locator,
	); err != nil {
		freeLocalMachinePKICertificateContext(
			context,
		)
		return fmt.Errorf(
			"delete transaction-owned CNG key for certificate SHA256=%s: %w",
			mutation.Certificate.CertificateSHA256,
			err,
		)
	}

	// CertDeleteCertificateFromStore always releases the supplied context,
	// including when deletion itself fails. Do not free context again.
	result, _, callErr :=
		certDeleteCertificateFromStorePKIProc.Call(
			uintptr(
				unsafe.Pointer(
					context,
				),
			),
		)

	if result == 0 {
		if callErr != nil &&
			callErr != syscall.Errno(0) {
			return fmt.Errorf(
				"transaction-owned private key was deleted but certificate SHA256=%s could not be removed from LocalMachine\\MY: %w",
				mutation.Certificate.CertificateSHA256,
				callErr,
			)
		}

		return fmt.Errorf(
			"transaction-owned private key was deleted but certificate SHA256=%s could not be removed from LocalMachine\\MY",
			mutation.Certificate.CertificateSHA256,
		)
	}

	return nil
}

func cngKeyLocatorFromCertificateContext(
	context *syscall.CertContext,
) (cngKeyLocator, error) {
	if context == nil {
		return cngKeyLocator{}, errors.New(
			"certificate context is required",
		)
	}

	var required uint32

	result, _, callErr :=
		certGetCertificateContextPropertyPKIProc.Call(
			uintptr(
				unsafe.Pointer(
					context,
				),
			),
			uintptr(certKeyProvInfoPropertyID),
			0,
			uintptr(
				unsafe.Pointer(
					&required,
				),
			),
		)

	if result == 0 {
		if callErr != nil &&
			callErr != syscall.Errno(0) {
			return cngKeyLocator{}, fmt.Errorf(
				"size CERT_KEY_PROV_INFO: %w",
				callErr,
			)
		}

		return cngKeyLocator{}, errors.New(
			"size CERT_KEY_PROV_INFO failed",
		)
	}

	if required <
		uint32(
			unsafe.Sizeof(
				cryptKeyProvInfoPKI{},
			),
		) {
		return cngKeyLocator{}, fmt.Errorf(
			"CERT_KEY_PROV_INFO size=%d is smaller than expected structure size=%d",
			required,
			unsafe.Sizeof(
				cryptKeyProvInfoPKI{},
			),
		)
	}

	wordSize := uintptr(
		unsafe.Sizeof(
			uintptr(0),
		),
	)

	wordCount := (uintptr(required) + wordSize - 1) / wordSize

	buffer := make(
		[]uintptr,
		int(wordCount),
	)

	size := required

	result, _, callErr =
		certGetCertificateContextPropertyPKIProc.Call(
			uintptr(
				unsafe.Pointer(
					context,
				),
			),
			uintptr(certKeyProvInfoPropertyID),
			uintptr(
				unsafe.Pointer(
					&buffer[0],
				),
			),
			uintptr(
				unsafe.Pointer(
					&size,
				),
			),
		)

	if result == 0 {
		if callErr != nil &&
			callErr != syscall.Errno(0) {
			return cngKeyLocator{}, fmt.Errorf(
				"read CERT_KEY_PROV_INFO: %w",
				callErr,
			)
		}

		return cngKeyLocator{}, errors.New(
			"read CERT_KEY_PROV_INFO failed",
		)
	}

	information := (*cryptKeyProvInfoPKI)(
		unsafe.Pointer(
			&buffer[0],
		),
	)

	if information.ProviderType != 0 {
		return cngKeyLocator{}, fmt.Errorf(
			"certificate private key uses legacy provider type=%d; FI requires CNG",
			information.ProviderType,
		)
	}

	if information.ContainerName == nil {
		return cngKeyLocator{}, errors.New(
			"CNG key container name is unavailable",
		)
	}

	if information.ProviderName == nil {
		return cngKeyLocator{}, errors.New(
			"CNG key provider name is unavailable",
		)
	}

	locator := cngKeyLocator{
		KeyName: windows.UTF16PtrToString(
			information.ContainerName,
		),
		KeySpec: information.KeySpec,
		MachineKey: information.Flags&
			ncryptMachineKeyFlag != 0,
		ProviderName: windows.UTF16PtrToString(
			information.ProviderName,
		),
	}

	runtime.KeepAlive(buffer)

	return locator, nil
}

func deleteCNGKey(
	locator cngKeyLocator,
) error {
	if err := validateCNGKeyLocator(
		locator,
	); err != nil {
		return err
	}

	providerPointer, err :=
		syscall.UTF16PtrFromString(
			locator.ProviderName,
		)
	if err != nil {
		return fmt.Errorf(
			"encode CNG provider name: %w",
			err,
		)
	}

	keyPointer, err :=
		syscall.UTF16PtrFromString(
			locator.KeyName,
		)
	if err != nil {
		return fmt.Errorf(
			"encode CNG key name: %w",
			err,
		)
	}

	var provider uintptr

	status, _, _ :=
		ncryptOpenStorageProviderPKIProc.Call(
			uintptr(
				unsafe.Pointer(
					&provider,
				),
			),
			uintptr(
				unsafe.Pointer(
					providerPointer,
				),
			),
			0,
		)

	runtime.KeepAlive(providerPointer)

	if status != 0 {
		return fmt.Errorf(
			"NCryptOpenStorageProvider(%s): status=0x%08X",
			locator.ProviderName,
			uint32(status),
		)
	}

	defer ncryptFreeObjectPKIProc.Call(
		provider,
	)

	var key uintptr

	openFlags := ncryptSilentFlag
	if locator.MachineKey {
		openFlags |= ncryptMachineKeyFlag
	}

	status, _, _ = ncryptOpenKeyPKIProc.Call(
		provider,
		uintptr(
			unsafe.Pointer(
				&key,
			),
		),
		uintptr(
			unsafe.Pointer(
				keyPointer,
			),
		),
		uintptr(locator.KeySpec),
		uintptr(openFlags),
	)

	runtime.KeepAlive(keyPointer)

	if status != 0 {
		return fmt.Errorf(
			"NCryptOpenKey(%s): status=0x%08X",
			locator.KeyName,
			uint32(status),
		)
	}

	status, _, _ = ncryptDeleteKeyPKIProc.Call(
		key,
		uintptr(ncryptSilentFlag),
	)

	if status != 0 {
		_, _, _ = ncryptFreeObjectPKIProc.Call(
			key,
		)

		return fmt.Errorf(
			"NCryptDeleteKey(%s): status=0x%08X",
			locator.KeyName,
			uint32(status),
		)
	}

	// Successful NCryptDeleteKey also releases the key handle.
	key = 0

	return nil
}

func findLocalMachinePKICertificateContextBySHA256(
	store uintptr,
	wantSHA256 string,
) (*syscall.CertContext, bool, error) {
	normalized := strings.ToLower(
		strings.TrimSpace(
			wantSHA256,
		),
	)

	decoded, err := hex.DecodeString(
		normalized,
	)
	if err != nil ||
		len(decoded) != sha256.Size {
		return nil, false, fmt.Errorf(
			"certificate SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	var previous *syscall.CertContext

	for {
		context, err :=
			syscall.CertEnumCertificatesInStore(
				syscall.Handle(store),
				previous,
			)
		if err != nil {
			if errors.Is(
				err,
				syscall.Errno(0x80092004),
			) {
				return nil, false, nil
			}

			return nil, false, fmt.Errorf(
				"enumerate LocalMachine\\MY certificates: %w",
				err,
			)
		}

		if context == nil {
			return nil, false, nil
		}

		previous = context

		if context.EncodedCert == nil ||
			context.Length == 0 {
			continue
		}

		raw := append(
			[]byte(nil),
			unsafe.Slice(
				context.EncodedCert,
				int(context.Length),
			)...,
		)

		certificate, err := x509.ParseCertificate(
			raw,
		)
		if err != nil {
			continue
		}

		digest := sha256.Sum256(
			certificate.Raw,
		)

		if hex.EncodeToString(
			digest[:],
		) == normalized {
			return context, true, nil
		}
	}
}

func freeLocalMachinePKICertificateContext(
	context *syscall.CertContext,
) {
	if context == nil {
		return
	}

	_, _, _ =
		certFreeCertificateContextPKIProc.Call(
			uintptr(
				unsafe.Pointer(
					context,
				),
			),
		)
}

func openLocalMachinePKIMutationStore() (
	uintptr,
	error,
) {
	name, err := syscall.UTF16PtrFromString(
		"MY",
	)
	if err != nil {
		return 0, fmt.Errorf(
			"encode LocalMachine MY certificate store name: %w",
			err,
		)
	}

	store, _, callErr :=
		certOpenStorePKIProc.Call(
			certStorePKISystemW,
			0,
			0,
			uintptr(
				certStorePKILocalMachine,
			),
			uintptr(
				unsafe.Pointer(
					name,
				),
			),
		)

	runtime.KeepAlive(name)

	if store == 0 {
		if callErr != nil &&
			callErr != syscall.Errno(0) {
			return 0, fmt.Errorf(
				"open writable LocalMachine\\MY certificate store: %w",
				callErr,
			)
		}

		return 0, errors.New(
			"open writable LocalMachine\\MY certificate store failed",
		)
	}

	return store, nil
}

func validateCNGKeyLocator(
	locator cngKeyLocator,
) error {
	if strings.TrimSpace(
		locator.ProviderName,
	) != fiPKICNGProviderName {
		return fmt.Errorf(
			"CNG provider expected=%q observed=%q",
			fiPKICNGProviderName,
			locator.ProviderName,
		)
	}

	if strings.TrimSpace(
		locator.KeyName,
	) == "" {
		return errors.New(
			"CNG key name is required",
		)
	}

	if !locator.MachineKey {
		return errors.New(
			"refusing to delete a non-machine CNG key",
		)
	}

	switch locator.KeySpec {
	case 0, 1, 2:
	default:
		return fmt.Errorf(
			"unsupported CNG legacy key spec=%d",
			locator.KeySpec,
		)
	}

	return nil
}

func validateOwnedPKIRollbackMutation(
	mutation pkiEnrollmentMutation,
) error {
	if !mutation.Owned {
		return errors.New(
			"refusing to roll back a certificate not owned by this enrollment transaction",
		)
	}

	value := strings.TrimSpace(
		mutation.Certificate.CertificateSHA256,
	)

	decoded, err := hex.DecodeString(
		value,
	)
	if err != nil ||
		len(decoded) != sha256.Size {
		return errors.New(
			"transaction-owned certificate SHA-256 is invalid",
		)
	}

	return nil
}
