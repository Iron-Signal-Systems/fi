// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const computerNameDNSDomain = uintptr(2)

var (
	kernel32DLL = windows.NewLazySystemDLL(
		"kernel32.dll",
	)

	getComputerNameExWProc = kernel32DLL.NewProc(
		"GetComputerNameExW",
	)
)

func computerDNSDomain() (
	string,
	error,
) {
	var buffer [256]uint16

	size :=
		uint32(
			len(
				buffer,
			),
		)

	result, _, callErr :=
		getComputerNameExWProc.Call(
			computerNameDNSDomain,
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
		return "", fmt.Errorf(
			"GetComputerNameExW(ComputerNameDnsDomain): %v",
			callErr,
		)
	}

	if size == 0 {
		return "", errors.New(
			"GetComputerNameExW returned an empty DNS domain",
		)
	}

	if size >
		uint32(
			len(
				buffer,
			),
		) {
		return "", fmt.Errorf(
			"GetComputerNameExW returned invalid DNS domain size=%d",
			size,
		)
	}

	value :=
		strings.TrimSpace(
			windows.UTF16ToString(
				buffer[:size],
			),
		)

	if value == "" {
		return "", errors.New(
			"Windows DNS domain name is empty",
		)
	}

	return value, nil
}
