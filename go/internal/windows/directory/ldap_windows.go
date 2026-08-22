// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows && (amd64 || arm64)

package directory

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	ldapPort                  = 389
	ldapVersion3              = 3
	ldapOptProtocolVersion    = 0x11
	ldapAuthNegotiate         = 0x0486
	ldapScopeBase             = 0
	ldapScopeSubtree          = 2
	ldapSuccess               = 0
	maxDirectoryPrincipalSIDs = 512
	maxLDAPStringUnits        = 1 << 20
)

var (
	wldap32                = syscall.NewLazyDLL("wldap32.dll")
	procLDAPInitW          = wldap32.NewProc("ldap_initW")
	procLDAPSetOptionW     = wldap32.NewProc("ldap_set_optionW")
	procLDAPBindSW         = wldap32.NewProc("ldap_bind_sW")
	procLDAPUnbind         = wldap32.NewProc("ldap_unbind")
	procLDAPSearchSW       = wldap32.NewProc("ldap_search_sW")
	procLDAPFirstEntry     = wldap32.NewProc("ldap_first_entry")
	procLDAPNextEntry      = wldap32.NewProc("ldap_next_entry")
	procLDAPGetValuesW     = wldap32.NewProc("ldap_get_valuesW")
	procLDAPCountValuesW   = wldap32.NewProc("ldap_count_valuesW")
	procLDAPValueFreeW     = wldap32.NewProc("ldap_value_freeW")
	procLDAPGetValuesLenW  = wldap32.NewProc("ldap_get_values_lenW")
	procLDAPCountValuesLen = wldap32.NewProc("ldap_count_values_len")
	procLDAPValueFreeLen   = wldap32.NewProc("ldap_value_free_len")
	procLDAPMsgFree        = wldap32.NewProc("ldap_msgfree")
	procLDAPErr2StringW    = wldap32.NewProc("ldap_err2stringW")
	procLdapGetLastError   = wldap32.NewProc("LdapGetLastError")
)

type berval struct {
	Len uint32
	Val *byte
}

// CollectCurrentDomainPrincipals resolves the supplied SIDs against the Active
// Directory domain named by domainDNSName using the current Windows process
// token for LDAP authentication. It performs read-only LDAP searches and does
// not calculate effective access.
func CollectCurrentDomainPrincipals(ctx context.Context, domainDNSName string, sids []string) (records.DirectoryPrincipalSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}
	if domainDNSName == "" {
		return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("domain DNS name is required")
	}

	requested := sortedUnique(sids)
	if len(requested) == 0 {
		return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("at least one SID is required")
	}
	if len(requested) > maxDirectoryPrincipalSIDs {
		return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("SID lookup count %d exceeds limit %d", len(requested), maxDirectoryPrincipalSIDs)
	}

	binarySIDs := make(map[string][]byte, len(requested))
	for _, sid := range requested {
		raw, err := sidStringToBytes(sid)
		if err != nil {
			return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("SID %q: %w", sid, err)
		}
		binarySIDs[sid] = raw
	}

	host, err := syscall.UTF16PtrFromString(domainDNSName)
	if err != nil {
		return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("domain DNS name: %w", err)
	}
	ld, _, _ := procLDAPInitW.Call(uintptr(unsafe.Pointer(host)), ldapPort)
	runtime.KeepAlive(host)
	if ld == 0 {
		code, _, _ := procLdapGetLastError.Call()
		return records.DirectoryPrincipalSnapshot{}, ldapError("ldap_initW", code)
	}
	defer procLDAPUnbind.Call(ld)

	version := uint32(ldapVersion3)
	code, _, _ := procLDAPSetOptionW.Call(ld, ldapOptProtocolVersion, uintptr(unsafe.Pointer(&version)))
	if code != ldapSuccess {
		return records.DirectoryPrincipalSnapshot{}, ldapError("ldap_set_optionW(LDAPv3)", code)
	}

	code, _, _ = procLDAPBindSW.Call(ld, 0, 0, ldapAuthNegotiate)
	if code != ldapSuccess {
		return records.DirectoryPrincipalSnapshot{}, ldapError("ldap_bind_sW(Negotiate)", code)
	}

	serverDNSName, namingContext, err := readRootDSE(ld)
	if err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}

	principals, err := searchPrincipals(ld, namingContext, requested, binarySIDs)
	if err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}

	found := make(map[string]struct{}, len(principals))
	for _, principal := range principals {
		found[principal.SID] = struct{}{}
	}
	notFound := make([]string, 0)
	for _, sid := range requested {
		if _, ok := found[sid]; !ok {
			notFound = append(notFound, sid)
		}
	}

	snapshot := records.DirectoryPrincipalSnapshot{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		CollectionMethod: records.DirectoryPrincipalCollectionMethod,
		DomainDNSName:    domainDNSName,
		ServerDNSName:    serverDNSName,
		NamingContext:    namingContext,
		RequestedSIDs:    requested,
		Principals:       principals,
		NotFoundSIDs:     notFound,
	}
	if err := records.ValidateDirectoryPrincipalSnapshot(snapshot); err != nil {
		return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("validate directory snapshot: %w", err)
	}
	return snapshot, nil
}

func readRootDSE(ld uintptr) (string, string, error) {
	result, err := ldapSearch(ld, "", ldapScopeBase, "(objectClass=*)", []string{"dnsHostName", "defaultNamingContext"})
	if err != nil {
		return "", "", fmt.Errorf("rootDSE search: %w", err)
	}
	defer procLDAPMsgFree.Call(result)

	entry, _, _ := procLDAPFirstEntry.Call(ld, result)
	if entry == 0 {
		return "", "", fmt.Errorf("rootDSE search returned no entry")
	}
	server, err := firstLDAPStringValue(ld, entry, "dnsHostName")
	if err != nil {
		return "", "", fmt.Errorf("rootDSE dnsHostName: %w", err)
	}
	base, err := firstLDAPStringValue(ld, entry, "defaultNamingContext")
	if err != nil {
		return "", "", fmt.Errorf("rootDSE defaultNamingContext: %w", err)
	}
	if server == "" || base == "" {
		return "", "", fmt.Errorf("rootDSE omitted required directory context")
	}
	return server, base, nil
}

func searchPrincipals(ld uintptr, namingContext string, requested []string, binarySIDs map[string][]byte) ([]records.DirectoryPrincipalObservation, error) {
	var filter strings.Builder
	if len(requested) > 1 {
		filter.WriteString("(|")
	}
	for _, sid := range requested {
		filter.WriteString("(objectSid=")
		filter.WriteString(ldapSIDFilterValue(binarySIDs[sid]))
		filter.WriteByte(')')
	}
	if len(requested) > 1 {
		filter.WriteByte(')')
	}

	attrs := []string{
		"objectSid",
		"objectGUID",
		"distinguishedName",
		"sAMAccountName",
		"userPrincipalName",
		"objectClass",
		"userAccountControl",
		"primaryGroupID",
	}
	result, err := ldapSearch(ld, namingContext, ldapScopeSubtree, filter.String(), attrs)
	if err != nil {
		return nil, fmt.Errorf("principal search: %w", err)
	}
	defer procLDAPMsgFree.Call(result)

	principals := make([]records.DirectoryPrincipalObservation, 0, len(requested))
	for entry, _, _ := procLDAPFirstEntry.Call(ld, result); entry != 0; {
		principal, err := readPrincipal(ld, entry)
		if err != nil {
			return nil, err
		}
		principals = append(principals, principal)
		next, _, _ := procLDAPNextEntry.Call(ld, entry)
		entry = next
	}
	sort.Slice(principals, func(i, j int) bool { return principals[i].SID < principals[j].SID })
	return principals, nil
}

func readPrincipal(ld, entry uintptr) (records.DirectoryPrincipalObservation, error) {
	sidValues, err := ldapBinaryValues(ld, entry, "objectSid")
	if err != nil || len(sidValues) != 1 {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal objectSid: expected one value")
	}
	sid, err := sidBytesToString(sidValues[0])
	if err != nil {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal objectSid: %w", err)
	}

	guidValues, err := ldapBinaryValues(ld, entry, "objectGUID")
	if err != nil || len(guidValues) != 1 || len(guidValues[0]) != 16 {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal objectGUID: expected one 16-byte value")
	}

	dn, err := firstLDAPStringValue(ld, entry, "distinguishedName")
	if err != nil || dn == "" {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal distinguishedName missing")
	}
	sam, err := firstLDAPStringValue(ld, entry, "sAMAccountName")
	if err != nil {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal sAMAccountName: %w", err)
	}
	upn, err := firstLDAPStringValue(ld, entry, "userPrincipalName")
	if err != nil {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal userPrincipalName: %w", err)
	}
	classes, err := ldapStringValues(ld, entry, "objectClass")
	if err != nil || len(classes) == 0 {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal objectClass missing")
	}
	uac, err := firstLDAPStringValue(ld, entry, "userAccountControl")
	if err != nil {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal userAccountControl: %w", err)
	}
	primaryGroupID, err := firstLDAPStringValue(ld, entry, "primaryGroupID")
	if err != nil {
		return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal primaryGroupID: %w", err)
	}
	principal := records.DirectoryPrincipalObservation{
		SID:                    sid,
		SIDRawBase64URL:        base64.RawURLEncoding.EncodeToString(sidValues[0]),
		ObjectGUID:             formatWindowsGUID(guidValues[0]),
		ObjectGUIDRawBase64URL: base64.RawURLEncoding.EncodeToString(guidValues[0]),
		DistinguishedName:      dn,
		SAMAccountName:         sam,
		UserPrincipalName:      upn,
		ObjectClasses:          classes,
		UserAccountControlRaw:  uac,
		PrimaryGroupIDRaw:      primaryGroupID,
	}
	if uac != "" {
		value, err := strconv.ParseUint(uac, 10, 32)
		if err != nil {
			return records.DirectoryPrincipalObservation{}, fmt.Errorf("directory principal userAccountControl %q: %w", uac, err)
		}
		disabled := value&0x00000002 != 0
		principal.AccountDisabled = &disabled
	}
	return principal, nil
}

func ldapSearch(ld uintptr, base string, scope uintptr, filter string, attrs []string) (uintptr, error) {
	basePtr, err := syscall.UTF16PtrFromString(base)
	if err != nil {
		return 0, err
	}
	filterPtr, err := syscall.UTF16PtrFromString(filter)
	if err != nil {
		return 0, err
	}
	attrPointers := make([]*uint16, len(attrs)+1)
	for i, attr := range attrs {
		ptr, err := syscall.UTF16PtrFromString(attr)
		if err != nil {
			return 0, err
		}
		attrPointers[i] = ptr
	}

	var result uintptr
	code, _, _ := procLDAPSearchSW.Call(
		ld,
		uintptr(unsafe.Pointer(basePtr)),
		scope,
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(unsafe.Pointer(&attrPointers[0])),
		0,
		uintptr(unsafe.Pointer(&result)),
	)
	runtime.KeepAlive(basePtr)
	runtime.KeepAlive(filterPtr)
	runtime.KeepAlive(attrPointers)
	if code != ldapSuccess {
		return 0, ldapError("ldap_search_sW", code)
	}
	if result == 0 {
		return 0, fmt.Errorf("ldap_search_sW returned no result message")
	}
	return result, nil
}

func firstLDAPStringValue(ld, entry uintptr, attr string) (string, error) {
	values, err := ldapStringValues(ld, entry, attr)
	if err != nil || len(values) == 0 {
		return "", err
	}
	return values[0], nil
}

func ldapStringValues(ld, entry uintptr, attr string) ([]string, error) {
	attrPtr, err := syscall.UTF16PtrFromString(attr)
	if err != nil {
		return nil, err
	}
	values, _, _ := procLDAPGetValuesW.Call(ld, entry, uintptr(unsafe.Pointer(attrPtr)))
	runtime.KeepAlive(attrPtr)
	if values == 0 {
		return []string{}, nil
	}
	defer procLDAPValueFreeW.Call(values)

	count, _, _ := procLDAPCountValuesW.Call(values)
	if count > 1<<20 {
		return nil, fmt.Errorf("LDAP attribute %s returned unreasonable value count %d", attr, count)
	}
	pointers := unsafe.Slice((**uint16)(unsafe.Pointer(values)), int(count))
	result := make([]string, 0, len(pointers))
	for _, ptr := range pointers {
		if ptr == nil {
			continue
		}
		value, err := utf16PointerString(ptr)
		if err != nil {
			return nil, fmt.Errorf("LDAP attribute %s: %w", attr, err)
		}
		result = append(result, value)
	}
	return result, nil
}

func ldapBinaryValues(ld, entry uintptr, attr string) ([][]byte, error) {
	attrPtr, err := syscall.UTF16PtrFromString(attr)
	if err != nil {
		return nil, err
	}
	values, _, _ := procLDAPGetValuesLenW.Call(ld, entry, uintptr(unsafe.Pointer(attrPtr)))
	runtime.KeepAlive(attrPtr)
	if values == 0 {
		return [][]byte{}, nil
	}
	defer procLDAPValueFreeLen.Call(values)

	count, _, _ := procLDAPCountValuesLen.Call(values)
	if count > 1<<20 {
		return nil, fmt.Errorf("LDAP binary attribute %s returned unreasonable value count %d", attr, count)
	}
	pointers := unsafe.Slice((**berval)(unsafe.Pointer(values)), int(count))
	result := make([][]byte, 0, len(pointers))
	for _, value := range pointers {
		if value == nil {
			continue
		}
		if value.Len > 16<<20 {
			return nil, fmt.Errorf("LDAP binary attribute %s value too large: %d", attr, value.Len)
		}
		if value.Len > 0 && value.Val == nil {
			return nil, fmt.Errorf("LDAP binary attribute %s returned nil data", attr)
		}
		raw := make([]byte, int(value.Len))
		if value.Len > 0 {
			copy(raw, unsafe.Slice(value.Val, int(value.Len)))
		}
		result = append(result, raw)
	}
	return result, nil
}

func utf16PointerString(ptr *uint16) (string, error) {
	if ptr == nil {
		return "", nil
	}
	units := unsafe.Slice(ptr, maxLDAPStringUnits)
	for i, unit := range units {
		if unit == 0 {
			return syscall.UTF16ToString(units[:i]), nil
		}
	}
	return "", fmt.Errorf("unterminated UTF-16 string exceeds %d code units", maxLDAPStringUnits)
}

func ldapError(operation string, code uintptr) error {
	textPtr, _, _ := procLDAPErr2StringW.Call(code)
	text := ""
	if textPtr != 0 {
		if parsed, err := utf16PointerString((*uint16)(unsafe.Pointer(textPtr))); err == nil {
			text = parsed
		}
	}
	if text == "" {
		return fmt.Errorf("%s: LDAP error %d", operation, code)
	}
	return fmt.Errorf("%s: LDAP error %d: %s", operation, code, text)
}

func formatWindowsGUID(raw []byte) string {
	return fmt.Sprintf(
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	)
}
