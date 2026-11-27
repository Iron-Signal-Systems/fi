// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ncryptNoMoreItemsStatus = uint32(0x8009002A)
)

var (
	ncryptEnumKeysPKIProc = ncryptPKIDLL.NewProc(
		"NCryptEnumKeys",
	)

	ncryptFreeBufferPKIProc = ncryptPKIDLL.NewProc(
		"NCryptFreeBuffer",
	)
)

type machineCNGKeyState struct {
	Algorithm    string
	Flags        uint32
	KeyName      string
	KeySpec      uint32
	MachineKey   bool
	ProviderName string
}

type ncryptKeyNamePKI struct {
	Name          *uint16
	Algorithm     *uint16
	LegacyKeySpec uint32
	Flags         uint32
}

func findAddedMachineCNGKeyForLocator(
	locator cngKeyLocator,
	added []machineCNGKeyState,
) (
	machineCNGKeyState,
	bool,
	error,
) {
	if err := validateCNGKeyLocator(
		locator,
	); err != nil {
		return machineCNGKeyState{}, false, err
	}

	var (
		found machineCNGKeyState
		count int
	)

	for _, state := range added {
		if state.ProviderName != locator.ProviderName {
			continue
		}

		if state.KeyName != locator.KeyName {
			continue
		}

		if !state.MachineKey {
			continue
		}

		count++
		found = state
	}

	switch count {
	case 0:
		return machineCNGKeyState{}, false, nil

	case 1:
		if !strings.EqualFold(
			found.Algorithm,
			"RSA",
		) {
			return machineCNGKeyState{}, false, fmt.Errorf(
				"new CNG key %q algorithm=%q expected RSA",
				found.KeyName,
				found.Algorithm,
			)
		}

		return found, true, nil

	default:
		return machineCNGKeyState{}, false, fmt.Errorf(
			"new CNG key inventory contains %d entries for provider=%q key=%q",
			count,
			locator.ProviderName,
			locator.KeyName,
		)
	}
}

func localMachineCNGKeyLocatorForCertificateSHA256(
	certificateSHA256 string,
) (
	cngKeyLocator,
	error,
) {
	store, err := openLocalMachinePKIStore()
	if err != nil {
		return cngKeyLocator{}, err
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
		return cngKeyLocator{}, err
	}

	if !found {
		return cngKeyLocator{}, fmt.Errorf(
			"certificate SHA256=%s disappeared from LocalMachine\\MY while establishing CNG key ownership",
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
		return cngKeyLocator{}, fmt.Errorf(
			"read CNG key locator for certificate SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	if err := validateCNGKeyLocator(
		locator,
	); err != nil {
		return cngKeyLocator{}, fmt.Errorf(
			"validate CNG key locator for certificate SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	return locator, nil
}

func machineCNGKeyStateDifference(
	before []machineCNGKeyState,
	after []machineCNGKeyState,
) []machineCNGKeyState {
	type keyIdentity struct {
		KeyName      string
		ProviderName string
	}

	existing := make(
		map[keyIdentity]struct{},
		len(before),
	)

	for _, state := range before {
		existing[keyIdentity{
			KeyName:      state.KeyName,
			ProviderName: state.ProviderName,
		}] = struct{}{}
	}

	added := make(
		[]machineCNGKeyState,
		0,
	)

	for _, state := range after {
		identity := keyIdentity{
			KeyName:      state.KeyName,
			ProviderName: state.ProviderName,
		}

		if _, found := existing[identity]; found {
			continue
		}

		added = append(
			added,
			state,
		)
	}

	sortMachineCNGKeyStates(
		added,
	)

	return added
}

func snapshotFIMachineCNGKeys() (
	[]machineCNGKeyState,
	error,
) {
	providerPointer, err := syscall.UTF16PtrFromString(
		fiPKICNGProviderName,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode FI CNG provider name: %w",
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

	runtime.KeepAlive(
		providerPointer,
	)

	if status != 0 {
		return nil, fmt.Errorf(
			"NCryptOpenStorageProvider(%s): status=0x%08X",
			fiPKICNGProviderName,
			uint32(status),
		)
	}

	defer ncryptFreeObjectPKIProc.Call(
		provider,
	)

	var enumerationState uintptr

	defer func() {
		if enumerationState != 0 {
			_, _, _ =
				ncryptFreeBufferPKIProc.Call(
					enumerationState,
				)
		}
	}()

	result := make(
		[]machineCNGKeyState,
		0,
	)

	for {
		var keyName *ncryptKeyNamePKI

		status, _, _ =
			ncryptEnumKeysPKIProc.Call(
				provider,
				0,
				uintptr(
					unsafe.Pointer(
						&keyName,
					),
				),
				uintptr(
					unsafe.Pointer(
						&enumerationState,
					),
				),
				uintptr(
					ncryptMachineKeyFlag,
				),
			)

		if uint32(status) ==
			ncryptNoMoreItemsStatus {
			break
		}

		if status != 0 {
			if keyName != nil {
				_, _, _ =
					ncryptFreeBufferPKIProc.Call(
						uintptr(
							unsafe.Pointer(
								keyName,
							),
						),
					)
			}

			return nil, fmt.Errorf(
				"NCryptEnumKeys(%s): status=0x%08X",
				fiPKICNGProviderName,
				uint32(status),
			)
		}

		if keyName == nil {
			return nil, errors.New(
				"NCryptEnumKeys returned success with no key information",
			)
		}

		state := machineCNGKeyState{
			Flags:        keyName.Flags,
			KeySpec:      keyName.LegacyKeySpec,
			MachineKey:   true,
			ProviderName: fiPKICNGProviderName,
		}

		if keyName.Name != nil {
			state.KeyName =
				windows.UTF16PtrToString(
					keyName.Name,
				)
		}

		if keyName.Algorithm != nil {
			state.Algorithm =
				windows.UTF16PtrToString(
					keyName.Algorithm,
				)
		}

		freeStatus, _, _ :=
			ncryptFreeBufferPKIProc.Call(
				uintptr(
					unsafe.Pointer(
						keyName,
					),
				),
			)

		keyName = nil

		if freeStatus != 0 {
			return nil, fmt.Errorf(
				"NCryptFreeBuffer(key information): status=0x%08X",
				uint32(freeStatus),
			)
		}

		if strings.TrimSpace(
			state.KeyName,
		) == "" {
			return nil, errors.New(
				"NCryptEnumKeys returned a machine key with no name",
			)
		}

		if strings.TrimSpace(
			state.Algorithm,
		) == "" {
			return nil, fmt.Errorf(
				"NCryptEnumKeys returned no algorithm for machine key %q",
				state.KeyName,
			)
		}

		result = append(
			result,
			state,
		)
	}

	sortMachineCNGKeyStates(
		result,
	)

	return result, nil
}

func sortMachineCNGKeyStates(
	states []machineCNGKeyState,
) {
	sort.Slice(
		states,
		func(
			left int,
			right int,
		) bool {
			if states[left].ProviderName !=
				states[right].ProviderName {
				return states[left].ProviderName <
					states[right].ProviderName
			}

			if states[left].KeyName !=
				states[right].KeyName {
				return states[left].KeyName <
					states[right].KeyName
			}

			if states[left].Algorithm !=
				states[right].Algorithm {
				return states[left].Algorithm <
					states[right].Algorithm
			}

			if states[left].KeySpec !=
				states[right].KeySpec {
				return states[left].KeySpec <
					states[right].KeySpec
			}

			return states[left].Flags <
				states[right].Flags
		},
	)
}
