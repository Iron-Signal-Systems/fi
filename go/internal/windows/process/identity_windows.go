// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package process

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	tokenQuery = 0x0008

	tokenUser          = 1
	tokenGroups        = 2
	tokenPrivileges    = 3
	tokenType          = 8
	tokenElevationType = 18
	tokenElevation     = 20

	computerNameNetBIOS   = 0
	computerNameDNSHost   = 1
	computerNameDNSDomain = 2
	computerNameDNSFQDN   = 3

	seGroupMandatory        = 0x00000001
	seGroupEnabledByDefault = 0x00000002
	seGroupEnabled          = 0x00000004
	seGroupOwner            = 0x00000008
	seGroupUseForDenyOnly   = 0x00000010
	seGroupIntegrity        = 0x00000020
	seGroupIntegrityEnabled = 0x00000040
	seGroupResource         = 0x20000000
	seGroupLogonID          = 0xC0000000

	sePrivilegeEnabledByDefault = 0x00000001
	sePrivilegeEnabled          = 0x00000002
	sePrivilegeRemoved          = 0x00000004
	sePrivilegeUsedForAccess    = 0x80000000
)

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procOpenProcessToken       = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation    = advapi32.NewProc("GetTokenInformation")
	procConvertSidToStringSIDW = advapi32.NewProc("ConvertSidToStringSidW")
	procLookupAccountSidW      = advapi32.NewProc("LookupAccountSidW")
	procLookupPrivilegeNameW   = advapi32.NewProc("LookupPrivilegeNameW")
	procGetComputerNameExW     = kernel32.NewProc("GetComputerNameExW")
	procLocalFree              = kernel32.NewProc("LocalFree")
	procLstrlenW               = kernel32.NewProc("lstrlenW")
)

type sidAndAttributes struct {
	SID        uintptr
	Attributes uint32
}

type tokenGroupsLayout struct {
	Count uint32
	First sidAndAttributes
}

type luidAndAttributes struct {
	LowPart    uint32
	HighPart   int32
	Attributes uint32
}

type tokenPrivilegesLayout struct {
	Count uint32
	First luidAndAttributes
}

// CurrentIdentity records the Windows identity and access-token facts for the
// current FI process. It reads the process token, not a possibly impersonating
// thread token.
func CurrentIdentity() (records.ProcessIdentityObservation, error) {
	computer, err := currentComputerIdentity()
	if err != nil {
		return records.ProcessIdentityObservation{}, err
	}

	processHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return records.ProcessIdentityObservation{}, fmt.Errorf("GetCurrentProcess: %w", err)
	}

	var token syscall.Handle
	result, _, callErr := procOpenProcessToken.Call(
		uintptr(processHandle),
		uintptr(tokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if result == 0 {
		return records.ProcessIdentityObservation{}, windowsCallError("OpenProcessToken", callErr)
	}
	defer syscall.CloseHandle(token)

	user, err := queryTokenUser(token)
	if err != nil {
		return records.ProcessIdentityObservation{}, err
	}
	groups, err := queryTokenGroups(token)
	if err != nil {
		return records.ProcessIdentityObservation{}, err
	}
	privileges, err := queryTokenPrivileges(token)
	if err != nil {
		return records.ProcessIdentityObservation{}, err
	}
	typeRaw, err := queryTokenUint32(token, tokenType)
	if err != nil {
		return records.ProcessIdentityObservation{}, err
	}
	elevationTypeRaw, err := queryTokenUint32(token, tokenElevationType)
	if err != nil {
		return records.ProcessIdentityObservation{}, err
	}
	elevatedRaw, err := queryTokenUint32(token, tokenElevation)
	if err != nil {
		return records.ProcessIdentityObservation{}, err
	}

	observation := records.ProcessIdentityObservation{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		CollectionMethod: records.ProcessIdentityCollectionMethod,
		Computer:         computer,
		Token: records.ProcessTokenObservation{
			User:              user,
			TokenTypeRaw:      strconv.FormatUint(uint64(typeRaw), 10),
			TokenTypeName:     tokenTypeName(typeRaw),
			ElevationTypeRaw:  strconv.FormatUint(uint64(elevationTypeRaw), 10),
			ElevationTypeName: elevationTypeName(elevationTypeRaw),
			Elevated:          elevatedRaw != 0,
			Groups:            groups,
			Privileges:        privileges,
		},
	}
	if err := records.ValidateProcessIdentityObservation(observation); err != nil {
		return records.ProcessIdentityObservation{}, fmt.Errorf("ValidateProcessIdentityObservation: %w", err)
	}
	return observation, nil
}

func currentComputerIdentity() (records.ComputerIdentity, error) {
	netbios, err := computerName(computerNameNetBIOS)
	if err != nil {
		return records.ComputerIdentity{}, err
	}
	dnsHost, _ := computerName(computerNameDNSHost)
	dnsDomain, _ := computerName(computerNameDNSDomain)
	dnsFQDN, _ := computerName(computerNameDNSFQDN)
	return records.ComputerIdentity{
		NetBIOSName: netbios,
		DNSHostName: dnsHost,
		DNSDomain:   dnsDomain,
		DNSFQDN:     dnsFQDN,
	}, nil
}

func computerName(nameType uint32) (string, error) {
	buffer := make([]uint16, 1024)
	size := uint32(len(buffer))
	result, _, callErr := procGetComputerNameExW.Call(
		uintptr(nameType),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if result == 0 {
		return "", windowsCallError("GetComputerNameExW", callErr)
	}
	if size > uint32(len(buffer)) {
		return "", fmt.Errorf("GetComputerNameExW returned invalid size %d", size)
	}
	return syscall.UTF16ToString(buffer[:size]), nil
}

func queryTokenUser(token syscall.Handle) (records.TokenPrincipalObservation, error) {
	data, err := tokenInformation(token, tokenUser)
	if err != nil {
		return records.TokenPrincipalObservation{}, fmt.Errorf("TokenUser: %w", err)
	}
	if len(data) < int(unsafe.Sizeof(sidAndAttributes{})) {
		return records.TokenPrincipalObservation{}, fmt.Errorf("TokenUser: short buffer")
	}
	entry := *(*sidAndAttributes)(unsafe.Pointer(&data[0]))
	if entry.SID == 0 {
		return records.TokenPrincipalObservation{}, fmt.Errorf("TokenUser: null SID")
	}
	principal, err := principalFromSID(entry.SID)
	runtime.KeepAlive(data)
	return principal, err
}

func queryTokenGroups(token syscall.Handle) ([]records.TokenGroupObservation, error) {
	data, err := tokenInformation(token, tokenGroups)
	if err != nil {
		return nil, fmt.Errorf("TokenGroups: %w", err)
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("TokenGroups: short buffer")
	}
	count := binary.LittleEndian.Uint32(data[:4])
	offset := int(unsafe.Offsetof(tokenGroupsLayout{}.First))
	entrySize := int(unsafe.Sizeof(sidAndAttributes{}))
	if offset > len(data) || uint64(count) > uint64((len(data)-offset)/entrySize) {
		return nil, fmt.Errorf("TokenGroups: invalid count %d", count)
	}

	groups := make([]records.TokenGroupObservation, 0, count)
	for index := uint32(0); index < count; index++ {
		position := offset + int(index)*entrySize
		entry := *(*sidAndAttributes)(unsafe.Pointer(&data[position]))
		if entry.SID == 0 {
			return nil, fmt.Errorf("TokenGroups[%d]: null SID", index)
		}
		principal, err := principalFromSID(entry.SID)
		if err != nil {
			return nil, fmt.Errorf("TokenGroups[%d]: %w", index, err)
		}
		attributes := entry.Attributes
		groups = append(groups, records.TokenGroupObservation{
			Index:            strconv.FormatUint(uint64(index), 10),
			Principal:        principal,
			AttributesRaw:    strconv.FormatUint(uint64(attributes), 10),
			Mandatory:        attributes&seGroupMandatory != 0,
			EnabledByDefault: attributes&seGroupEnabledByDefault != 0,
			Enabled:          attributes&seGroupEnabled != 0,
			Owner:            attributes&seGroupOwner != 0,
			DenyOnly:         attributes&seGroupUseForDenyOnly != 0,
			Integrity:        attributes&seGroupIntegrity != 0,
			IntegrityEnabled: attributes&seGroupIntegrityEnabled != 0,
			LogonID:          attributes&seGroupLogonID == seGroupLogonID,
			Resource:         attributes&seGroupResource != 0,
		})
	}
	runtime.KeepAlive(data)
	return groups, nil
}

func queryTokenPrivileges(token syscall.Handle) ([]records.TokenPrivilegeObservation, error) {
	data, err := tokenInformation(token, tokenPrivileges)
	if err != nil {
		return nil, fmt.Errorf("TokenPrivileges: %w", err)
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("TokenPrivileges: short buffer")
	}
	count := binary.LittleEndian.Uint32(data[:4])
	offset := int(unsafe.Offsetof(tokenPrivilegesLayout{}.First))
	entrySize := int(unsafe.Sizeof(luidAndAttributes{}))
	if offset > len(data) || uint64(count) > uint64((len(data)-offset)/entrySize) {
		return nil, fmt.Errorf("TokenPrivileges: invalid count %d", count)
	}

	privileges := make([]records.TokenPrivilegeObservation, 0, count)
	for index := uint32(0); index < count; index++ {
		position := offset + int(index)*entrySize
		entry := *(*luidAndAttributes)(unsafe.Pointer(&data[position]))
		name := privilegeName(entry.LowPart, entry.HighPart)
		attributes := entry.Attributes
		privileges = append(privileges, records.TokenPrivilegeObservation{
			Index:            strconv.FormatUint(uint64(index), 10),
			LUIDLow:          strconv.FormatUint(uint64(entry.LowPart), 10),
			LUIDHigh:         strconv.FormatInt(int64(entry.HighPart), 10),
			Name:             name,
			AttributesRaw:    strconv.FormatUint(uint64(attributes), 10),
			EnabledByDefault: attributes&sePrivilegeEnabledByDefault != 0,
			Enabled:          attributes&sePrivilegeEnabled != 0,
			Removed:          attributes&sePrivilegeRemoved != 0,
			UsedForAccess:    attributes&sePrivilegeUsedForAccess != 0,
		})
	}
	return privileges, nil
}

func queryTokenUint32(token syscall.Handle, informationClass uint32) (uint32, error) {
	data, err := tokenInformation(token, informationClass)
	if err != nil {
		return 0, fmt.Errorf("token information class %d: %w", informationClass, err)
	}
	if len(data) < 4 {
		return 0, fmt.Errorf("token information class %d: short buffer", informationClass)
	}
	return binary.LittleEndian.Uint32(data[:4]), nil
}

func tokenInformation(token syscall.Handle, informationClass uint32) ([]byte, error) {
	var required uint32
	result, _, callErr := procGetTokenInformation.Call(
		uintptr(token),
		uintptr(informationClass),
		0,
		0,
		uintptr(unsafe.Pointer(&required)),
	)
	if result != 0 && required == 0 {
		return []byte{}, nil
	}
	if required == 0 {
		return nil, windowsCallError("GetTokenInformation(size)", callErr)
	}

	data := make([]byte, required)
	result, _, callErr = procGetTokenInformation.Call(
		uintptr(token),
		uintptr(informationClass),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(required),
		uintptr(unsafe.Pointer(&required)),
	)
	if result == 0 {
		return nil, windowsCallError("GetTokenInformation", callErr)
	}
	if required > uint32(len(data)) {
		return nil, fmt.Errorf("GetTokenInformation returned invalid size %d", required)
	}
	return data[:required], nil
}

func principalFromSID(sid uintptr) (records.TokenPrincipalObservation, error) {
	sidText, err := sidString(sid)
	if err != nil {
		return records.TokenPrincipalObservation{}, err
	}
	principal := records.TokenPrincipalObservation{SID: sidText}

	account, domain, nameUse, ok := accountName(sid)
	if !ok {
		return principal, nil
	}
	principal.AccountName = account
	principal.DomainName = domain
	principal.NameUseRaw = strconv.FormatUint(uint64(nameUse), 10)
	principal.NameUseName = sidNameUseName(nameUse)
	return principal, nil
}

func sidString(sid uintptr) (string, error) {
	var text *uint16
	result, _, callErr := procConvertSidToStringSIDW.Call(
		sid,
		uintptr(unsafe.Pointer(&text)),
	)
	if result == 0 {
		return "", windowsCallError("ConvertSidToStringSidW", callErr)
	}
	if text == nil {
		return "", fmt.Errorf("ConvertSidToStringSidW returned null string")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(text)))
	length, _, _ := procLstrlenW.Call(uintptr(unsafe.Pointer(text)))
	return syscall.UTF16ToString(unsafe.Slice(text, int(length))), nil
}

func accountName(sid uintptr) (string, string, uint32, bool) {
	var accountLength uint32
	var domainLength uint32
	var nameUse uint32
	procLookupAccountSidW.Call(
		0,
		sid,
		0,
		uintptr(unsafe.Pointer(&accountLength)),
		0,
		uintptr(unsafe.Pointer(&domainLength)),
		uintptr(unsafe.Pointer(&nameUse)),
	)
	if accountLength == 0 {
		return "", "", 0, false
	}

	accountBuffer := make([]uint16, accountLength)
	domainBuffer := make([]uint16, domainLength)
	var domainPointer uintptr
	if len(domainBuffer) > 0 {
		domainPointer = uintptr(unsafe.Pointer(&domainBuffer[0]))
	}
	result, _, _ := procLookupAccountSidW.Call(
		0,
		sid,
		uintptr(unsafe.Pointer(&accountBuffer[0])),
		uintptr(unsafe.Pointer(&accountLength)),
		domainPointer,
		uintptr(unsafe.Pointer(&domainLength)),
		uintptr(unsafe.Pointer(&nameUse)),
	)
	if result == 0 {
		return "", "", 0, false
	}
	return syscall.UTF16ToString(accountBuffer), syscall.UTF16ToString(domainBuffer), nameUse, true
}

func privilegeName(low uint32, high int32) string {
	luid := struct {
		LowPart  uint32
		HighPart int32
	}{low, high}
	var size uint32
	procLookupPrivilegeNameW.Call(
		0,
		uintptr(unsafe.Pointer(&luid)),
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if size == 0 {
		return ""
	}
	buffer := make([]uint16, size+1)
	bufferSize := uint32(len(buffer))
	result, _, _ := procLookupPrivilegeNameW.Call(
		0,
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
	)
	if result == 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer)
}

func tokenTypeName(value uint32) string {
	switch value {
	case 1:
		return "Primary"
	case 2:
		return "Impersonation"
	default:
		return "NotKnown"
	}
}

func elevationTypeName(value uint32) string {
	switch value {
	case 1:
		return "Default"
	case 2:
		return "Full"
	case 3:
		return "Limited"
	default:
		return "NotKnown"
	}
}

func sidNameUseName(value uint32) string {
	switch value {
	case 1:
		return "User"
	case 2:
		return "Group"
	case 3:
		return "Domain"
	case 4:
		return "Alias"
	case 5:
		return "WellKnownGroup"
	case 6:
		return "DeletedAccount"
	case 7:
		return "Invalid"
	case 8:
		return "Unknown"
	case 9:
		return "Computer"
	case 10:
		return "Label"
	case 11:
		return "LogonSession"
	default:
		return "NotKnown"
	}
}
