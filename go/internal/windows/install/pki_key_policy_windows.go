// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const ncryptExportPolicyPropertyName = "Export Policy"

var ncryptGetPropertyPKIProc = ncryptPKIDLL.NewProc(
	"NCryptGetProperty",
)

func verifyLocalMachineCNGPrivateKeyContract(
	certificateSHA256 string,
) error {
	store, err := openLocalMachinePKIStore()
	if err != nil {
		return err
	}
	defer closeLocalMachinePKIStore(
		store,
	)

	context, found, err :=
		findLocalMachinePKICertificateContextBySHA256(
			store,
			certificateSHA256,
		)
	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf(
			"certificate SHA256=%s disappeared from LocalMachine\\MY during private-key verification",
			certificateSHA256,
		)
	}

	defer freeLocalMachinePKICertificateContext(
		context,
	)

	locator, err := cngKeyLocatorFromCertificateContext(
		context,
	)
	if err != nil {
		return fmt.Errorf(
			"read CNG private-key locator for certificate SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	if err := validateCNGKeyLocator(
		locator,
	); err != nil {
		return fmt.Errorf(
			"validate CNG private-key locator for certificate SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	exportPolicy, err := readCNGExportPolicy(
		locator,
	)
	if err != nil {
		return fmt.Errorf(
			"read CNG export policy for certificate SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	if exportPolicy != 0 {
		return fmt.Errorf(
			"CNG private key for certificate SHA256=%s is exportable or archive-exportable: export_policy=0x%08X",
			certificateSHA256,
			exportPolicy,
		)
	}

	return nil
}

func readCNGExportPolicy(
	locator cngKeyLocator,
) (uint32, error) {
	if err := validateCNGKeyLocator(
		locator,
	); err != nil {
		return 0, err
	}

	providerPointer, err := syscall.UTF16PtrFromString(
		locator.ProviderName,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"encode CNG provider name: %w",
			err,
		)
	}

	keyPointer, err := syscall.UTF16PtrFromString(
		locator.KeyName,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"encode CNG key name: %w",
			err,
		)
	}

	propertyPointer, err := syscall.UTF16PtrFromString(
		ncryptExportPolicyPropertyName,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"encode CNG export-policy property name: %w",
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
		return 0, fmt.Errorf(
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
		return 0, fmt.Errorf(
			"NCryptOpenKey(%s): status=0x%08X",
			locator.KeyName,
			uint32(status),
		)
	}

	defer ncryptFreeObjectPKIProc.Call(
		key,
	)

	var (
		exportPolicy uint32
		written      uint32
	)

	status, _, _ = ncryptGetPropertyPKIProc.Call(
		key,
		uintptr(
			unsafe.Pointer(
				propertyPointer,
			),
		),
		uintptr(
			unsafe.Pointer(
				&exportPolicy,
			),
		),
		uintptr(
			unsafe.Sizeof(
				exportPolicy,
			),
		),
		uintptr(
			unsafe.Pointer(
				&written,
			),
		),
		0,
	)

	runtime.KeepAlive(propertyPointer)

	if status != 0 {
		return 0, fmt.Errorf(
			"NCryptGetProperty(%s): status=0x%08X",
			ncryptExportPolicyPropertyName,
			uint32(status),
		)
	}

	if written != uint32(
		unsafe.Sizeof(
			exportPolicy,
		),
	) {
		return 0, errors.New(
			"CNG export-policy property returned an unexpected size",
		)
	}

	return exportPolicy, nil
}
