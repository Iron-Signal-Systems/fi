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
	ldapSSLPort            = 636
	ldapVersion3           = 3
	ldapOptProtocolVersion = 0x11
	ldapAuthNegotiate      = 0x0486
	ldapScopeBase          = 0
	ldapScopeSubtree       = 2
	ldapSuccess            = 0

	dsDirectoryServiceRequired = 0x00000010
	dsIsDNSName                = 0x00020000
	dsReturnDNSName            = 0x40000000
	maxDirectorySeedSIDs       = 16384
	maxDirectoryPrincipals     = 65536
	maxDirectoryMemberships    = 262144
	directorySIDSearchBatch    = 64
	maxLDAPStringUnits         = 1 << 20
)

var (
	wldap32                = syscall.NewLazyDLL("wldap32.dll")
	netapi32               = syscall.NewLazyDLL("netapi32.dll")
	procLDAPSSLInitW       = wldap32.NewProc("ldap_sslinitW")
	procLDAPConnect        = wldap32.NewProc("ldap_connect")
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
	procDsGetDcNameW       = netapi32.NewProc("DsGetDcNameW")
	procNetApiBufferFree   = netapi32.NewProc("NetApiBufferFree")
)

type berval struct {
	Len uint32
	Val *byte
}

type domainControllerInfoW struct {
	DomainControllerName        *uint16
	DomainControllerAddress     *uint16
	DomainControllerAddressType uint32
	DomainGUID                  [16]byte
	DomainName                  *uint16
	DNSForestName               *uint16
	Flags                       uint32
	DCSiteName                  *uint16
	ClientSiteName              *uint16
}

// CollectCurrentDomainPrincipals resolves the supplied seed SIDs against the
// Active Directory domain named by domainDNSName using the current Windows
// process token for LDAP authentication.
//
// FI records principal attributes returned by AD and direct group relationships
// established by a group's member attribute. primaryGroupID is preserved only
// as PrimaryGroupIDRaw on the principal. The collector does not construct a
// primary-group SID or emit a derived primary-group membership edge. That
// relationship belongs to later backend derivation.
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
	if len(requested) > maxDirectorySeedSIDs {
		return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("SID seed count %d exceeds limit %d", len(requested), maxDirectorySeedSIDs)
	}

	ld, err := openLDAP(domainDNSName)
	if err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}
	defer procLDAPUnbind.Call(ld)

	serverDNSName, namingContext, err := readRootDSE(ld)
	if err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}

	seedPrincipals, err := searchPrincipalSIDs(ld, namingContext, requested)
	if err != nil {
		return records.DirectoryPrincipalSnapshot{}, err
	}

	principalBySID := make(map[string]records.DirectoryPrincipalObservation, len(seedPrincipals))
	queue := make([]string, 0, len(seedPrincipals))
	for _, principal := range seedPrincipals {
		newPrincipal, err := addDirectoryPrincipal(principalBySID, principal)
		if err != nil {
			return records.DirectoryPrincipalSnapshot{}, err
		}
		if newPrincipal {
			queue = append(queue, principal.SID)
		}
	}

	foundRequested := make(map[string]struct{}, len(seedPrincipals))
	for _, principal := range seedPrincipals {
		foundRequested[principal.SID] = struct{}{}
	}
	notFound := make([]string, 0)
	for _, sid := range requested {
		if _, ok := foundRequested[sid]; !ok {
			notFound = append(notFound, sid)
		}
	}

	membershipByKey := make(map[string]records.DirectoryMembershipObservation)
	processed := make(map[string]struct{})

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return records.DirectoryPrincipalSnapshot{}, err
		}

		sid := queue[0]
		queue = queue[1:]
		if _, ok := processed[sid]; ok {
			continue
		}
		principal, ok := principalBySID[sid]
		if !ok {
			return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("directory membership queue referenced unknown SID %s", sid)
		}
		processed[sid] = struct{}{}

		directGroups, err := searchDirectGroupsForMember(ld, namingContext, principal.DistinguishedName)
		if err != nil {
			return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("direct groups for %s: %w", principal.SID, err)
		}
		for _, group := range directGroups {
			newPrincipal, err := addDirectoryPrincipal(principalBySID, group)
			if err != nil {
				return records.DirectoryPrincipalSnapshot{}, err
			}
			if newPrincipal {
				if len(principalBySID) > maxDirectoryPrincipals {
					return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("directory principal count exceeds limit %d", maxDirectoryPrincipals)
				}
				queue = append(queue, group.SID)
			}

			membership := records.DirectoryMembershipObservation{
				MemberSID: principal.SID,
				GroupSID:  group.SID,
				Source:    records.DirectoryMembershipSourceGroupMember,
			}
			if err := addDirectoryMembership(membershipByKey, membership); err != nil {
				return records.DirectoryPrincipalSnapshot{}, err
			}
		}
	}

	principals := make([]records.DirectoryPrincipalObservation, 0, len(principalBySID))
	for _, principal := range principalBySID {
		principals = append(principals, principal)
	}
	memberships := make([]records.DirectoryMembershipObservation, 0, len(membershipByKey))
	for _, membership := range membershipByKey {
		memberships = append(memberships, membership)
	}

	snapshot := records.DirectoryPrincipalSnapshot{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		CollectionMethod: records.DirectoryPrincipalCollectionMethod,
		DomainDNSName:    domainDNSName,
		ServerDNSName:    serverDNSName,
		NamingContext:    namingContext,
		RequestedSIDs:    requested,
		Principals:       principals,
		Memberships:      memberships,
		NotFoundSIDs:     notFound,
	}
	records.SortDirectoryPrincipalSnapshot(&snapshot)
	if err := records.ValidateDirectoryPrincipalSnapshot(snapshot); err != nil {
		return records.DirectoryPrincipalSnapshot{}, fmt.Errorf("validate directory snapshot: %w", err)
	}
	return snapshot, nil
}

func openLDAP(domainDNSName string) (uintptr, error) {
	dcDNSName, err := discoverDomainController(domainDNSName)
	if err != nil {
		return 0, err
	}

	host, err := syscall.UTF16PtrFromString(dcDNSName)
	if err != nil {
		return 0, fmt.Errorf("domain controller DNS name: %w", err)
	}

	// FI requires LDAPS for directory collection. Use the discovered DC FQDN
	// instead of the AD domain name so Schannel validates the certificate against
	// the actual domain controller identity present in the certificate.
	ld, _, _ := procLDAPSSLInitW.Call(
		uintptr(unsafe.Pointer(host)),
		ldapSSLPort,
		1,
	)
	runtime.KeepAlive(host)
	if ld == 0 {
		code, _, _ := procLdapGetLastError.Call()
		return 0, ldapError("ldap_sslinitW(LDAPS)", code)
	}

	version := uint32(ldapVersion3)
	code, _, _ := procLDAPSetOptionW.Call(ld, ldapOptProtocolVersion, uintptr(unsafe.Pointer(&version)))
	if code != ldapSuccess {
		procLDAPUnbind.Call(ld)
		return 0, ldapError("ldap_set_optionW(LDAPv3)", code)
	}

	// Connect explicitly so TLS/certificate failures are reported separately
	// from authentication failures.
	code, _, _ = procLDAPConnect.Call(ld, 0)
	if code != ldapSuccess {
		procLDAPUnbind.Call(ld)
		return 0, ldapError("ldap_connect(LDAPS "+dcDNSName+")", code)
	}

	code, _, _ = procLDAPBindSW.Call(ld, 0, 0, ldapAuthNegotiate)
	if code != ldapSuccess {
		procLDAPUnbind.Call(ld)
		return 0, ldapError("ldap_bind_sW(Negotiate over LDAPS)", code)
	}
	return ld, nil
}

func discoverDomainController(domainDNSName string) (string, error) {
	domain, err := syscall.UTF16PtrFromString(domainDNSName)
	if err != nil {
		return "", fmt.Errorf("domain DNS name: %w", err)
	}

	var infoPointer *domainControllerInfoW
	flags := uintptr(dsDirectoryServiceRequired | dsIsDNSName | dsReturnDNSName)
	status, _, _ := procDsGetDcNameW.Call(
		0,
		uintptr(unsafe.Pointer(domain)),
		0,
		0,
		flags,
		uintptr(unsafe.Pointer(&infoPointer)),
	)
	runtime.KeepAlive(domain)
	if status != 0 {
		return "", fmt.Errorf("DsGetDcNameW(%s): Windows error %d", domainDNSName, status)
	}
	if infoPointer == nil {
		return "", fmt.Errorf("DsGetDcNameW(%s): returned no domain controller", domainDNSName)
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(infoPointer)))

	info := infoPointer
	name, err := utf16PointerString(info.DomainControllerName)
	if err != nil {
		return "", fmt.Errorf("DsGetDcNameW(%s) domain controller name: %w", domainDNSName, err)
	}

	// DOMAIN_CONTROLLER_INFO returns the name with a leading UNC prefix.
	name = strings.TrimPrefix(name, `\\`)
	if name == "" {
		return "", fmt.Errorf("DsGetDcNameW(%s): returned empty domain controller DNS name", domainDNSName)
	}
	return name, nil
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

func searchPrincipalSIDs(ld uintptr, namingContext string, sids []string) ([]records.DirectoryPrincipalObservation, error) {
	requested := sortedUnique(sids)
	if len(requested) == 0 {
		return []records.DirectoryPrincipalObservation{}, nil
	}

	principalBySID := make(map[string]records.DirectoryPrincipalObservation, len(requested))
	for start := 0; start < len(requested); start += directorySIDSearchBatch {
		end := start + directorySIDSearchBatch
		if end > len(requested) {
			end = len(requested)
		}
		batch := requested[start:end]
		binarySIDs := make(map[string][]byte, len(batch))
		for _, sid := range batch {
			raw, err := sidStringToBytes(sid)
			if err != nil {
				return nil, fmt.Errorf("SID %q: %w", sid, err)
			}
			binarySIDs[sid] = raw
		}

		principals, err := searchPrincipals(ld, namingContext, batch, binarySIDs)
		if err != nil {
			return nil, err
		}
		for _, principal := range principals {
			if _, expected := binarySIDs[principal.SID]; !expected {
				return nil, fmt.Errorf("principal search returned unrequested SID %s", principal.SID)
			}
			if _, duplicate := principalBySID[principal.SID]; duplicate {
				return nil, fmt.Errorf("principal search returned duplicate SID %s", principal.SID)
			}
			principalBySID[principal.SID] = principal
		}
	}

	principals := make([]records.DirectoryPrincipalObservation, 0, len(principalBySID))
	for _, principal := range principalBySID {
		principals = append(principals, principal)
	}
	sort.Slice(principals, func(i, j int) bool { return principals[i].SID < principals[j].SID })
	return principals, nil
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

	result, err := ldapSearch(ld, namingContext, ldapScopeSubtree, filter.String(), principalLDAPAttributes())
	if err != nil {
		return nil, fmt.Errorf("principal search: %w", err)
	}
	defer procLDAPMsgFree.Call(result)

	return readPrincipalSearchResults(ld, result)
}

// searchDirectGroupsForMember returns only groups in the current naming context
// whose member attribute directly contains memberDN. This deliberately avoids
// transitive LDAP matching rules; PostgreSQL owns nested membership traversal.
func searchDirectGroupsForMember(ld uintptr, namingContext, memberDN string) ([]records.DirectoryPrincipalObservation, error) {
	if memberDN == "" {
		return nil, fmt.Errorf("member distinguished name is required")
	}
	filter := "(&(objectClass=group)(member=" + ldapFilterEscapeValue(memberDN) + "))"
	result, err := ldapSearch(ld, namingContext, ldapScopeSubtree, filter, principalLDAPAttributes())
	if err != nil {
		return nil, fmt.Errorf("group member search: %w", err)
	}
	defer procLDAPMsgFree.Call(result)

	groups, err := readPrincipalSearchResults(ld, result)
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if !containsFold(group.ObjectClasses, "group") {
			return nil, fmt.Errorf("member search returned non-group SID %s", group.SID)
		}
	}
	return groups, nil
}

func principalLDAPAttributes() []string {
	return []string{
		"objectSid",
		"objectGUID",
		"distinguishedName",
		"sAMAccountName",
		"userPrincipalName",
		"objectClass",
		"userAccountControl",
		"primaryGroupID",
	}
}

func readPrincipalSearchResults(ld, result uintptr) ([]records.DirectoryPrincipalObservation, error) {
	principals := []records.DirectoryPrincipalObservation{}
	seen := map[string]struct{}{}
	for entry, _, _ := procLDAPFirstEntry.Call(ld, result); entry != 0; {
		principal, err := readPrincipal(ld, entry)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[principal.SID]; duplicate {
			return nil, fmt.Errorf("LDAP result contained duplicate SID %s", principal.SID)
		}
		seen[principal.SID] = struct{}{}
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

func addDirectoryPrincipal(principals map[string]records.DirectoryPrincipalObservation, principal records.DirectoryPrincipalObservation) (bool, error) {
	if principal.SID == "" {
		return false, fmt.Errorf("directory principal SID is empty")
	}
	if existing, ok := principals[principal.SID]; ok {
		if existing.ObjectGUID != principal.ObjectGUID || existing.DistinguishedName != principal.DistinguishedName {
			return false, fmt.Errorf("directory SID %s resolved to conflicting objects", principal.SID)
		}
		return false, nil
	}
	principals[principal.SID] = principal
	return true, nil
}

func addDirectoryMembership(memberships map[string]records.DirectoryMembershipObservation, membership records.DirectoryMembershipObservation) error {
	if len(memberships) >= maxDirectoryMemberships {
		return fmt.Errorf("directory membership count exceeds limit %d", maxDirectoryMemberships)
	}
	key := membership.MemberSID + "\x00" + membership.GroupSID + "\x00" + string(membership.Source)
	memberships[key] = membership
	return nil
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

// ldapFilterEscapeValue applies RFC 4515 escaping to a filter assertion value.
// The distinguished-name text itself is not reinterpreted; only bytes that have
// special meaning in an LDAP filter are escaped.
func ldapFilterEscapeValue(value string) string {
	var builder strings.Builder
	for _, b := range []byte(value) {
		switch b {
		case 0x00, '(', ')', '*', '\\':
			builder.WriteByte('\\')
			const hex = "0123456789abcdef"
			builder.WriteByte(hex[b>>4])
			builder.WriteByte(hex[b&0x0f])
		default:
			builder.WriteByte(b)
		}
	}
	return builder.String()
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

// ldapPointerFromProcReturn converts a pointer-valued wldap32 return exposed
// through syscall.LazyProc.Call's uintptr return slot.
//
// The returned memory is owned by Windows/LDAP, not by the Go heap. Callers
// consume it only while the corresponding LDAP allocation remains valid and
// release it through the matching LDAP free routine. Keep this unavoidable FFI
// conversion centralized instead of retaining native pointers as uintptr values
// throughout the collector.
func ldapPointerFromProcReturn(value uintptr) unsafe.Pointer {
	if value == 0 {
		return nil
	}
	return *(*unsafe.Pointer)(unsafe.Pointer(&value))
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
	pointers := unsafe.Slice((**uint16)(ldapPointerFromProcReturn(values)), int(count))
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
	pointers := unsafe.Slice((**berval)(ldapPointerFromProcReturn(values)), int(count))
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
		if parsed, err := utf16PointerString((*uint16)(ldapPointerFromProcReturn(textPtr))); err == nil {
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
