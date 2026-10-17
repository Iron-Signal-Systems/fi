// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ldapsecure

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ldapAuthNegotiate      = uintptr(0x0486)
	ldapOptEncrypt         = uintptr(0x96)
	ldapOptProtocolVersion = uintptr(0x11)
	ldapOptSign            = uintptr(0x95)
	ldapPort               = uintptr(389)
	ldapScopeBase          = uintptr(0)
	ldapSuccess            = uintptr(0)
	ldapVersion3           = uint32(3)
)

type ldapBerval struct {
	Length uint32
	Value  *byte
}

var (
	wldap32DLL = windows.NewLazySystemDLL(
		"wldap32.dll",
	)

	ldapBindSWProc = wldap32DLL.NewProc(
		"ldap_bind_sW",
	)

	ldapCountEntriesProc = wldap32DLL.NewProc(
		"ldap_count_entries",
	)

	ldapErr2StringWProc = wldap32DLL.NewProc(
		"ldap_err2stringW",
	)

	ldapFirstEntryProc = wldap32DLL.NewProc(
		"ldap_first_entry",
	)

	ldapGetValuesLenWProc = wldap32DLL.NewProc(
		"ldap_get_values_lenW",
	)

	ldapInitWProc = wldap32DLL.NewProc(
		"ldap_initW",
	)

	ldapMsgFreeProc = wldap32DLL.NewProc(
		"ldap_msgfree",
	)

	ldapSearchSWProc = wldap32DLL.NewProc(
		"ldap_search_sW",
	)

	ldapSetOptionWProc = wldap32DLL.NewProc(
		"ldap_set_optionW",
	)

	ldapUnbindSProc = wldap32DLL.NewProc(
		"ldap_unbind_s",
	)

	ldapValueFreeLenProc = wldap32DLL.NewProc(
		"ldap_value_free_len",
	)
)

func Close(
	handle uintptr,
) error {
	if handle == 0 {
		return nil
	}

	status, _, _ :=
		ldapUnbindSProc.Call(
			handle,
		)

	if status != ldapSuccess {
		return fmt.Errorf(
			"unbind signed/sealed LDAP session: %s",
			ldapErrorText(
				status,
			),
		)
	}

	return nil
}

func Open(
	host string,
) (uintptr, error) {
	host = strings.TrimSpace(
		host,
	)

	if host == "" {
		return 0, errors.New(
			"LDAP host is required",
		)
	}

	hostPointer, err :=
		windows.UTF16PtrFromString(
			host,
		)
	if err != nil {
		return 0, fmt.Errorf(
			"encode LDAP host %q: %w",
			host,
			err,
		)
	}

	handle, _, callErr :=
		ldapInitWProc.Call(
			uintptr(
				unsafe.Pointer(
					hostPointer,
				),
			),
			ldapPort,
		)

	if handle == 0 {
		return 0, fmt.Errorf(
			"ldap_initW %s: %v",
			host,
			callErr,
		)
	}

	closeOnError := true

	defer func() {
		if closeOnError {
			_ = Close(
				handle,
			)
		}
	}()

	version := ldapVersion3

	if status, _, _ :=
		ldapSetOptionWProc.Call(
			handle,
			ldapOptProtocolVersion,
			uintptr(
				unsafe.Pointer(
					&version,
				),
			),
		); status != ldapSuccess {
		return 0, fmt.Errorf(
			"set LDAP protocol version: %s",
			ldapErrorText(
				status,
			),
		)
	}

	on := uint32(1)

	if status, _, _ :=
		ldapSetOptionWProc.Call(
			handle,
			ldapOptSign,
			uintptr(
				unsafe.Pointer(
					&on,
				),
			),
		); status != ldapSuccess {
		return 0, fmt.Errorf(
			"enable LDAP signing: %s",
			ldapErrorText(
				status,
			),
		)
	}

	if status, _, _ :=
		ldapSetOptionWProc.Call(
			handle,
			ldapOptEncrypt,
			uintptr(
				unsafe.Pointer(
					&on,
				),
			),
		); status != ldapSuccess {
		return 0, fmt.Errorf(
			"enable LDAP sealing: %s",
			ldapErrorText(
				status,
			),
		)
	}

	if status, _, _ :=
		ldapBindSWProc.Call(
			handle,
			0,
			0,
			ldapAuthNegotiate,
		); status != ldapSuccess {
		return 0, fmt.Errorf(
			"bind LDAP using current Windows credentials: %s",
			ldapErrorText(
				status,
			),
		)
	}

	closeOnError = false

	return handle, nil
}

func ReadBaseBinary(
	handle uintptr,
	baseDN string,
	filter string,
	attribute string,
	maxBytes int,
) ([]byte, error) {
	baseDN = strings.TrimSpace(
		baseDN,
	)

	filter = strings.TrimSpace(
		filter,
	)

	attribute = strings.TrimSpace(
		attribute,
	)

	switch {
	case baseDN == "":
		return nil, errors.New(
			"LDAP base distinguished name is required",
		)

	case filter == "":
		return nil, errors.New(
			"LDAP filter is required",
		)

	case attribute == "":
		return nil, errors.New(
			"LDAP binary attribute is required",
		)

	case maxBytes <= 0:
		return nil, errors.New(
			"LDAP binary value maximum size must be positive",
		)

	case handle == 0:
		return nil, errors.New(
			"signed/sealed LDAP session is unavailable",
		)
	}

	basePointer, err :=
		windows.UTF16PtrFromString(
			baseDN,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode LDAP search base %q: %w",
			baseDN,
			err,
		)
	}

	filterPointer, err :=
		windows.UTF16PtrFromString(
			filter,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode LDAP search filter %q: %w",
			filter,
			err,
		)
	}

	attributeStorage, err :=
		windows.UTF16FromString(
			attribute,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode LDAP attribute %q: %w",
			attribute,
			err,
		)
	}

	attributePointers := []uintptr{
		uintptr(
			unsafe.Pointer(
				&attributeStorage[0],
			),
		),
		0,
	}

	var result uintptr

	status, _, _ :=
		ldapSearchSWProc.Call(
			handle,
			uintptr(
				unsafe.Pointer(
					basePointer,
				),
			),
			ldapScopeBase,
			uintptr(
				unsafe.Pointer(
					filterPointer,
				),
			),
			uintptr(
				unsafe.Pointer(
					&attributePointers[0],
				),
			),
			0,
			uintptr(
				unsafe.Pointer(
					&result,
				),
			),
		)

	runtime.KeepAlive(
		basePointer,
	)

	runtime.KeepAlive(
		filterPointer,
	)

	runtime.KeepAlive(
		attributeStorage,
	)

	runtime.KeepAlive(
		attributePointers,
	)

	if result != 0 {
		defer ldapMsgFreeProc.Call(
			result,
		)
	}

	if status != ldapSuccess {
		return nil, fmt.Errorf(
			"LDAP base search failed: base=%q filter=%q: %s",
			baseDN,
			filter,
			ldapErrorText(
				status,
			),
		)
	}

	count, _, _ :=
		ldapCountEntriesProc.Call(
			handle,
			result,
		)

	switch uint32(count) {
	case 1:
	default:
		return nil, fmt.Errorf(
			"LDAP base search returned %d entries; expected exactly one: base=%q filter=%q",
			uint32(count),
			baseDN,
			filter,
		)
	}

	entry, _, _ :=
		ldapFirstEntryProc.Call(
			handle,
			result,
		)

	if entry == 0 {
		return nil, fmt.Errorf(
			"LDAP base search entry is unavailable: base=%q filter=%q",
			baseDN,
			filter,
		)
	}

	attributePointer, err :=
		windows.UTF16PtrFromString(
			attribute,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"encode LDAP binary attribute %q: %w",
			attribute,
			err,
		)
	}

	values, _, _ :=
		ldapGetValuesLenWProc.Call(
			handle,
			entry,
			uintptr(
				unsafe.Pointer(
					attributePointer,
				),
			),
		)

	if values == 0 {
		return nil, fmt.Errorf(
			"LDAP binary attribute %s is missing",
			attribute,
		)
	}

	defer ldapValueFreeLenProc.Call(
		values,
	)

	first :=
		*(*uintptr)(
			unsafe.Pointer(
				values,
			),
		)

	if first == 0 {
		return nil, fmt.Errorf(
			"LDAP binary attribute %s has no value",
			attribute,
		)
	}

	value :=
		(*ldapBerval)(
			unsafe.Pointer(
				first,
			),
		)

	if value.Value == nil {
		return nil, fmt.Errorf(
			"LDAP binary attribute %s has a nil value",
			attribute,
		)
	}

	if value.Length == 0 {
		return nil, fmt.Errorf(
			"LDAP binary attribute %s is empty",
			attribute,
		)
	}

	if uint64(
		value.Length,
	) > uint64(
		maxBytes,
	) {
		return nil, fmt.Errorf(
			"LDAP binary attribute %s size=%d exceeds FI limit=%d bytes",
			attribute,
			value.Length,
			maxBytes,
		)
	}

	source := unsafe.Slice(
		value.Value,
		int(
			value.Length,
		),
	)

	resultValue := make(
		[]byte,
		len(
			source,
		),
	)

	copy(
		resultValue,
		source,
	)

	return resultValue, nil
}

func ldapErrorText(
	status uintptr,
) string {
	message, _, _ :=
		ldapErr2StringWProc.Call(
			status,
		)

	if message == 0 {
		return fmt.Sprintf(
			"LDAP error %d",
			uint32(
				status,
			),
		)
	}

	return fmt.Sprintf(
		"%s (%d)",
		windows.UTF16PtrToString(
			(*uint16)(
				unsafe.Pointer(
					message,
				),
			),
		),
		uint32(
			status,
		),
	)
}

var _ = syscall.Errno(0)
