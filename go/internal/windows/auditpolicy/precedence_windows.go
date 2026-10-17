// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package auditpolicy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	legacyAuditPrecedenceKey   = `SYSTEM\CurrentControlSet\Control\Lsa`
	legacyAuditPrecedenceValue = "SCENoApplyLegacyAuditPolicy"
)

var (
	setRegistryValue    = advapi32.NewProc("RegSetValueExW")
	deleteRegistryValue = advapi32.NewProc("RegDeleteValueW")
)

type Precedence struct {
	Present bool
	Value   uint32
}

func openPrecedenceKey() (syscall.Handle, error) {
	subkey, err := syscall.UTF16PtrFromString(legacyAuditPrecedenceKey)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subkey, 0, syscall.KEY_QUERY_VALUE|syscall.KEY_SET_VALUE, &key)
	if err != nil {
		return 0, fmt.Errorf("open legacy audit precedence key: %w", err)
	}
	return key, nil
}

func readPrecedence(key syscall.Handle) (Precedence, error) {
	name, err := syscall.UTF16PtrFromString(legacyAuditPrecedenceValue)
	if err != nil {
		return Precedence{}, err
	}
	var data [4]byte
	dataLength := uint32(len(data))
	var valueType uint32
	err = syscall.RegQueryValueEx(key, name, nil, &valueType, &data[0], &dataLength)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return Precedence{}, nil
	}
	if err != nil {
		return Precedence{}, fmt.Errorf("query audit precedence: %w", err)
	}
	if valueType != syscall.REG_DWORD || dataLength != 4 {
		return Precedence{}, fmt.Errorf("audit precedence has unexpected registry type=%d size=%d", valueType, dataLength)
	}
	return Precedence{Present: true, Value: binary.LittleEndian.Uint32(data[:])}, nil
}

func writePrecedence(key syscall.Handle, value Precedence) error {
	name, err := syscall.UTF16PtrFromString(legacyAuditPrecedenceValue)
	if err != nil {
		return err
	}
	if !value.Present {
		ok, _, callErr := deleteRegistryValue.Call(uintptr(key), uintptr(unsafe.Pointer(name)))
		if ok != 0 {
			return fmt.Errorf("RegDeleteValueW: status=%d (last error: %v)", ok, callErr)
		}
		return nil
	}
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value.Value)
	status, _, callErr := setRegistryValue.Call(uintptr(key), uintptr(unsafe.Pointer(name)), 0, syscall.REG_DWORD, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	if status != 0 {
		return fmt.Errorf("RegSetValueExW: status=%d (last error: %v)", status, callErr)
	}
	return nil
}

// QueryPrecedence reads the currently configured advanced-audit precedence
// DWORD; later effective policy verification must detect GPO overrides.
func QueryPrecedence() (Precedence, error) {
	key, err := openPrecedenceKey()
	if err != nil {
		return Precedence{}, err
	}
	defer syscall.RegCloseKey(key)
	return readPrecedence(key)
}

// ApplyPrecedence is a separate transaction step so Approval 2 can restore the
// exact previous DWORD or absence if any subsequent local mutation fails.
func ApplyPrecedence() (func() error, error) {
	before, err := QueryPrecedence()
	if err != nil {
		return nil, err
	}
	if before.Present && before.Value == 1 {
		return func() error { return nil }, nil
	}

	rollback := func() error {
		key, err := openPrecedenceKey()
		if err != nil {
			return err
		}
		defer syscall.RegCloseKey(key)
		current, err := readPrecedence(key)
		if err != nil {
			return err
		}
		if !current.Present || current.Value != 1 {
			return fmt.Errorf("audit precedence changed externally (present=%t value=%d); refusing to overwrite drift", current.Present, current.Value)
		}
		return writePrecedence(key, before)
	}

	key, err := openPrecedenceKey()
	if err != nil {
		return nil, err
	}
	current, err := readPrecedence(key)
	if err != nil {
		syscall.RegCloseKey(key)
		return nil, err
	}
	if current != before {
		syscall.RegCloseKey(key)
		return nil, fmt.Errorf("audit precedence drifted before mutation")
	}
	writeErr := writePrecedence(key, Precedence{Present: true, Value: 1})
	closeErr := syscall.RegCloseKey(key)
	if err := errors.Join(writeErr, closeErr); err != nil {
		return nil, errors.Join(err, rollback())
	}
	observed, err := QueryPrecedence()
	if err != nil {
		return nil, errors.Join(err, rollback())
	}
	if !observed.Present || observed.Value != 1 {
		return nil, errors.Join(fmt.Errorf("audit precedence did not converge: %+v", observed), rollback())
	}
	return rollback, nil
}
