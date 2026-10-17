// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package domaincontroller

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dsDirectoryServiceRequired = uint32(0x00000010)
	dsWritableRequired         = uint32(0x00001000)
	dsIsDNSName                = uint32(0x00020000)
	dsReturnDNSName            = uint32(0x40000000)
)

type Info struct {
	ClientSite       string
	DCSite           string
	DomainController string
	ForestDNS        string
}

type domainControllerInfoW struct {
	DomainControllerName        *uint16
	DomainControllerAddress     *uint16
	DomainControllerAddressType uint32
	DomainGUID                  windows.GUID
	DomainName                  *uint16
	DNSForestName               *uint16
	Flags                       uint32
	DCSiteName                  *uint16
	ClientSiteName              *uint16
}

var (
	netapi32DLL = windows.NewLazySystemDLL(
		"netapi32.dll",
	)

	dsGetDcNameWProc = netapi32DLL.NewProc(
		"DsGetDcNameW",
	)
)

func Discover(
	domainDNS string,
) (Info, error) {
	return discover(
		domainDNS,
		false,
	)
}

func DiscoverWritable(
	domainDNS string,
) (Info, error) {
	return discover(
		domainDNS,
		true,
	)
}

func discover(
	domainDNS string,
	writable bool,
) (Info, error) {
	domainDNS = strings.TrimSpace(
		domainDNS,
	)

	if domainDNS == "" {
		return Info{}, fmt.Errorf(
			"domain DNS name is required",
		)
	}

	domain, err :=
		windows.UTF16PtrFromString(
			domainDNS,
		)
	if err != nil {
		return Info{}, fmt.Errorf(
			"encode domain DNS name %q: %w",
			domainDNS,
			err,
		)
	}

	var infoPointer *domainControllerInfoW

	status, _, _ :=
		dsGetDcNameWProc.Call(
			0,
			uintptr(
				unsafe.Pointer(
					domain,
				),
			),
			0,
			0,
			uintptr(
				discoveryFlags(
					writable,
				),
			),
			uintptr(
				unsafe.Pointer(
					&infoPointer,
				),
			),
		)

	runtime.KeepAlive(
		domain,
	)

	if status != 0 {
		kind := "domain controller"

		if writable {
			kind = "writable domain controller"
		}

		return Info{}, fmt.Errorf(
			"locate %s for %s: Win32=%d",
			kind,
			domainDNS,
			uint32(
				status,
			),
		)
	}

	if infoPointer == nil {
		return Info{}, fmt.Errorf(
			"locate domain controller for %s returned no information",
			domainDNS,
		)
	}

	defer windows.NetApiBufferFree(
		(*byte)(
			unsafe.Pointer(
				infoPointer,
			),
		),
	)

	controller :=
		strings.TrimPrefix(
			utf16String(
				infoPointer.DomainControllerName,
			),
			`\\`,
		)

	controller = strings.TrimSpace(
		controller,
	)

	if controller == "" {
		return Info{}, fmt.Errorf(
			"domain controller name is empty",
		)
	}

	return Info{
		ClientSite: utf16String(
			infoPointer.ClientSiteName,
		),
		DCSite: utf16String(
			infoPointer.DCSiteName,
		),
		DomainController: controller,
		ForestDNS: utf16String(
			infoPointer.DNSForestName,
		),
	}, nil
}

func discoveryFlags(
	writable bool,
) uint32 {
	flags :=
		dsDirectoryServiceRequired |
			dsIsDNSName |
			dsReturnDNSName

	if writable {
		flags |= dsWritableRequired
	}

	return flags
}

func utf16String(
	value *uint16,
) string {
	if value == nil {
		return ""
	}

	return windows.UTF16PtrToString(
		value,
	)
}
