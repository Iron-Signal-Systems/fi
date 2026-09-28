// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

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
	dsDirectoryServiceRequired = uint32(0x00000010)
	dsWritableRequired         = uint32(0x00001000)
	dsIsDNSName                = uint32(0x00020000)
	dsReturnDNSName            = uint32(0x40000000)

	ldapAuthNegotiate      = uintptr(0x0486)
	ldapOptEncrypt         = uintptr(0x96)
	ldapOptProtocolVersion = uintptr(0x11)
	ldapOptSign            = uintptr(0x95)
	ldapPort               = uintptr(389)
	ldapScopeBase          = uintptr(0)
	ldapScopeOneLevel      = uintptr(1)
	ldapScopeSubtree       = uintptr(2)
	ldapSuccess            = uintptr(0)
	ldapVersion3           = uint32(3)
)

type ActiveDirectoryGMSAState struct {
	DNSHostName                 string
	DistinguishedName           string
	GroupMSAMembershipBytes     uint32
	ManagedPasswordIntervalDays string
	PasswordRetrievalTrustees   []GMSAMembershipTrustee
	Role                        string
	SAMAccountName              string
	ServicePrincipalNames       []string
	SupportedEncryptionTypes    string
	UserAccountControl          string
}

type ActiveDirectoryState struct {
	ClientSite                 string
	ComputerDN                 string
	ComputerObjectKnown        bool
	ComputerSID                string
	ConfigurationNamingContext string
	DCSite                     string
	DefaultNamingContext       string
	DomainController           string
	ForestDNS                  string
	GMSADiscoveryKnown         bool
	GMSAs                      []ActiveDirectoryGMSAState
	KDSRootKeyCount            uint32
	KDSRootKeyKnown            bool
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

type ldapBerval struct {
	Length uint32
	Value  *byte
}

type ldapSession struct {
	handle uintptr
}

type ldapSearchCardinalityError struct {
	Base   string
	Count  uint32
	Filter string
}

func (err *ldapSearchCardinalityError) Error() string {
	if err == nil {
		return "LDAP search cardinality error"
	}
	if err.Count == 0 {
		return fmt.Sprintf(
			"LDAP search returned no entries: base=%q filter=%q",
			err.Base,
			err.Filter,
		)
	}
	return fmt.Sprintf(
		"LDAP search returned %d entries; expected exactly one: base=%q filter=%q",
		err.Count,
		err.Base,
		err.Filter,
	)
}

func ldapSearchReturnedNoEntries(err error) bool {
	var cardinalityError *ldapSearchCardinalityError
	return errors.As(
		err,
		&cardinalityError,
	) && cardinalityError.Count == 0
}

var (
	wldap32DLL = syscall.NewLazyDLL("wldap32.dll")

	dsGetDcNameWProc      = netapi32ManagedServiceDLL.NewProc("DsGetDcNameW")
	ldapBindSWProc        = wldap32DLL.NewProc("ldap_bind_sW")
	ldapCountEntriesProc  = wldap32DLL.NewProc("ldap_count_entries")
	ldapErr2StringWProc   = wldap32DLL.NewProc("ldap_err2stringW")
	ldapFirstEntryProc    = wldap32DLL.NewProc("ldap_first_entry")
	ldapGetDNWProc        = wldap32DLL.NewProc("ldap_get_dnW")
	ldapGetValuesLenWProc = wldap32DLL.NewProc("ldap_get_values_lenW")
	ldapGetValuesWProc    = wldap32DLL.NewProc("ldap_get_valuesW")
	ldapInitWProc         = wldap32DLL.NewProc("ldap_initW")
	ldapMemFreeWProc      = wldap32DLL.NewProc("ldap_memfreeW")
	ldapMsgFreeProc       = wldap32DLL.NewProc("ldap_msgfree")
	ldapSearchSWProc      = wldap32DLL.NewProc("ldap_search_sW")
	ldapSetOptionWProc    = wldap32DLL.NewProc("ldap_set_optionW")
	ldapUnbindSProc       = wldap32DLL.NewProc("ldap_unbind_s")
	ldapValueFreeLenProc  = wldap32DLL.NewProc("ldap_value_free_len")
	ldapValueFreeWProc    = wldap32DLL.NewProc("ldap_value_freeW")
)

func discoverActiveDirectory(report *Report) {
	if report.Join.Status != "domain" {
		report.addCheck(
			checkFail,
			"Active Directory discovery",
			"host is not domain joined",
		)
		return
	}

	domainDNS := strings.TrimSpace(report.Host.DomainDNS)
	if domainDNS == "" || domainDNS == notKnown {
		report.addCheck(
			checkFail,
			"Active Directory discovery",
			"DNS domain name is unavailable",
		)
		return
	}

	dc, err := discoverWritableDomainController(domainDNS)
	if err != nil {
		report.addCheck(
			checkFail,
			"Active Directory domain controller",
			err.Error(),
		)
		return
	}

	report.AD.DomainController = dc.DomainController
	report.AD.ForestDNS = dc.ForestDNS
	report.AD.DCSite = dc.DCSite
	report.AD.ClientSite = dc.ClientSite

	session, err := openLDAPSession(dc.DomainController)
	if err != nil {
		report.addCheck(
			checkFail,
			"Active Directory LDAP bind",
			err.Error(),
		)
		return
	}
	defer session.close()

	rootDSE, err := session.rootDSE()
	if err != nil {
		report.addCheck(
			checkFail,
			"Active Directory RootDSE",
			err.Error(),
		)
		return
	}

	report.AD.DefaultNamingContext = rootDSE["defaultNamingContext"]
	report.AD.ConfigurationNamingContext = rootDSE["configurationNamingContext"]

	report.addCheck(
		checkPass,
		"Active Directory LDAP bind",
		fmt.Sprintf(
			"dc=%s domain_nc=%s configuration_nc=%s",
			report.AD.DomainController,
			report.AD.DefaultNamingContext,
			report.AD.ConfigurationNamingContext,
		),
	)

	computerSAM := strings.TrimSpace(report.Host.Computer)
	if computerSAM != "" && !strings.HasSuffix(computerSAM, "$") {
		computerSAM += "$"
	}

	computerDN, computerSID, err := session.findComputerObject(
		report.AD.DefaultNamingContext,
		computerSAM,
	)
	if err != nil {
		report.addCheck(
			checkFail,
			"Active Directory computer object",
			err.Error(),
		)
	} else {
		report.AD.ComputerDN = computerDN
		report.AD.ComputerObjectKnown = true
		report.AD.ComputerSID = computerSID
		report.addCheck(
			checkPass,
			"Active Directory computer object",
			fmt.Sprintf(
				"sam=%s dn=%s sid=%s",
				computerSAM,
				computerDN,
				computerSID,
			),
		)
	}

	kdsBase := fmt.Sprintf(
		"CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,%s",
		report.AD.ConfigurationNamingContext,
	)
	kdsCount, err := session.countSearch(
		kdsBase,
		uint32(ldapScopeOneLevel),
		"(objectClass=msKds-ProvRootKey)",
	)
	if err != nil {
		report.addCheck(
			checkFail,
			"KDS root key discovery",
			err.Error(),
		)
	} else {
		report.AD.KDSRootKeyCount = kdsCount
		report.AD.KDSRootKeyKnown = true
		if kdsCount == 0 {
			report.addCheck(
				checkInfo,
				"KDS root key discovery",
				"no msKds-ProvRootKey objects were found; authoritative absence can be planned as CREATE after Approval 1",
			)
		} else {
			report.addCheck(
				checkPass,
				"KDS root key discovery",
				fmt.Sprintf(
					"root_key_objects=%d",
					kdsCount,
				),
			)
		}
	}

	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		report.addCheck(
			checkFail,
			"AD FI gMSA naming",
			err.Error(),
		)
		return
	}

	seen := make(map[string]struct{})
	gmsaDiscoveryKnown := true

	for _, item := range desiredFIIdentityList(identities) {
		sam := item.SAMAccountName

		key := strings.ToLower(sam)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		state, err := session.findGMSA(
			report.AD.DefaultNamingContext,
			item.Role,
			sam,
		)
		if err != nil {
			if ldapSearchReturnedNoEntries(err) {
				report.addCheck(
					checkInfo,
					"AD "+item.Role+" gMSA object",
					fmt.Sprintf(
						"sam=%s is not present; creation may be planned only after authoritative AD discovery completes",
						sam,
					),
				)
				continue
			}

			gmsaDiscoveryKnown = false
			report.addCheck(
				checkFail,
				"AD "+item.Role+" gMSA object",
				err.Error(),
			)
			continue
		}

		report.AD.GMSAs = append(
			report.AD.GMSAs,
			state,
		)

		expectedDNS := strings.TrimSuffix(sam, "$") + "." + domainDNS
		if !strings.EqualFold(state.DNSHostName, expectedDNS) {
			report.addCheck(
				checkFail,
				"AD "+item.Role+" gMSA DNS name",
				fmt.Sprintf(
					"sam=%s expected=%s observed=%s",
					sam,
					expectedDNS,
					state.DNSHostName,
				),
			)
		} else {
			report.addCheck(
				checkPass,
				"AD "+item.Role+" gMSA DNS name",
				fmt.Sprintf(
					"sam=%s dns=%s",
					sam,
					state.DNSHostName,
				),
			)
		}

		if state.GroupMSAMembershipBytes == 0 {
			report.addCheck(
				checkFail,
				"AD "+item.Role+" gMSA password-retrieval descriptor",
				fmt.Sprintf(
					"sam=%s msDS-GroupMSAMembership is missing or empty",
					sam,
				),
			)
			continue
		}

		report.addCheck(
			checkPass,
			"AD "+item.Role+" gMSA password-retrieval descriptor",
			fmt.Sprintf(
				"sam=%s bytes=%d trustees=%d",
				sam,
				state.GroupMSAMembershipBytes,
				len(state.PasswordRetrievalTrustees),
			),
		)

		if report.AD.ComputerSID == "" {
			report.addCheck(
				checkFail,
				"AD "+item.Role+" gMSA password-retrieval authorization",
				"local computer SID is unavailable",
			)
			continue
		}

		if exactSingleGMSATrustee(
			state.PasswordRetrievalTrustees,
			report.AD.ComputerSID,
		) {
			report.addCheck(
				checkPass,
				"AD "+item.Role+" gMSA password-retrieval authorization",
				fmt.Sprintf(
					"only %s is authorized by msDS-GroupMSAMembership",
					report.AD.ComputerSID,
				),
			)
		} else {
			report.addCheck(
				checkFail,
				"AD "+item.Role+" gMSA password-retrieval authorization",
				fmt.Sprintf(
					"expected exactly one READ_PROPERTY Allow trustee %s; observed=%s",
					report.AD.ComputerSID,
					formatGMSATrustees(state.PasswordRetrievalTrustees),
				),
			)
		}
	}

	report.AD.GMSADiscoveryKnown = gmsaDiscoveryKnown
}

type discoveredDomainController struct {
	ClientSite       string
	DCSite           string
	DomainController string
	ForestDNS        string
}

func discoverWritableDomainController(
	domainDNS string,
) (discoveredDomainController, error) {
	domain, err := syscall.UTF16PtrFromString(domainDNS)
	if err != nil {
		return discoveredDomainController{}, fmt.Errorf(
			"encode domain DNS name %q: %w",
			domainDNS,
			err,
		)
	}

	var infoPointer uintptr

	status, _, _ := dsGetDcNameWProc.Call(
		0,
		uintptr(unsafe.Pointer(domain)),
		0,
		0,
		uintptr(
			dsDirectoryServiceRequired|
				dsWritableRequired|
				dsIsDNSName|
				dsReturnDNSName,
		),
		uintptr(unsafe.Pointer(&infoPointer)),
	)
	if status != 0 {
		return discoveredDomainController{}, fmt.Errorf(
			"locate writable domain controller for %s: Win32=%d",
			domainDNS,
			uint32(status),
		)
	}
	if infoPointer == 0 {
		return discoveredDomainController{}, fmt.Errorf(
			"locate writable domain controller for %s returned no information",
			domainDNS,
		)
	}
	defer windows.NetApiBufferFree(
		(*byte)(unsafe.Pointer(infoPointer)),
	)

	info := (*domainControllerInfoW)(
		unsafe.Pointer(infoPointer),
	)

	controller := strings.TrimPrefix(
		windows.UTF16PtrToString(info.DomainControllerName),
		`\\`,
	)
	if controller == "" {
		return discoveredDomainController{}, fmt.Errorf(
			"writable domain controller name is empty",
		)
	}

	return discoveredDomainController{
		ClientSite:       windows.UTF16PtrToString(info.ClientSiteName),
		DCSite:           windows.UTF16PtrToString(info.DCSiteName),
		DomainController: controller,
		ForestDNS:        windows.UTF16PtrToString(info.DNSForestName),
	}, nil
}

func openLDAPSession(host string) (*ldapSession, error) {
	hostPointer, err := syscall.UTF16PtrFromString(host)
	if err != nil {
		return nil, fmt.Errorf(
			"encode LDAP host %q: %w",
			host,
			err,
		)
	}

	handle, _, callErr := ldapInitWProc.Call(
		uintptr(unsafe.Pointer(hostPointer)),
		ldapPort,
	)
	if handle == 0 {
		return nil, fmt.Errorf(
			"ldap_initW %s: %v",
			host,
			callErr,
		)
	}

	session := &ldapSession{handle: handle}

	version := ldapVersion3
	if status, _, _ := ldapSetOptionWProc.Call(
		handle,
		ldapOptProtocolVersion,
		uintptr(unsafe.Pointer(&version)),
	); status != ldapSuccess {
		session.close()
		return nil, fmt.Errorf(
			"set LDAP protocol version: %s",
			ldapErrorText(status),
		)
	}

	on := uint32(1)
	if status, _, _ := ldapSetOptionWProc.Call(
		handle,
		ldapOptSign,
		uintptr(unsafe.Pointer(&on)),
	); status != ldapSuccess {
		session.close()
		return nil, fmt.Errorf(
			"enable LDAP signing: %s",
			ldapErrorText(status),
		)
	}
	if status, _, _ := ldapSetOptionWProc.Call(
		handle,
		ldapOptEncrypt,
		uintptr(unsafe.Pointer(&on)),
	); status != ldapSuccess {
		session.close()
		return nil, fmt.Errorf(
			"enable LDAP sealing: %s",
			ldapErrorText(status),
		)
	}

	if status, _, _ := ldapBindSWProc.Call(
		handle,
		0,
		0,
		ldapAuthNegotiate,
	); status != ldapSuccess {
		session.close()
		return nil, fmt.Errorf(
			"bind LDAP using current Windows credentials: %s",
			ldapErrorText(status),
		)
	}

	return session, nil
}

func (session *ldapSession) close() {
	if session == nil || session.handle == 0 {
		return
	}
	ldapUnbindSProc.Call(session.handle)
	session.handle = 0
}

func (session *ldapSession) rootDSE() (map[string]string, error) {
	attributes := []string{
		"defaultNamingContext",
		"configurationNamingContext",
	}
	entry, result, err := session.searchSingleEntry(
		"",
		uint32(ldapScopeBase),
		"(objectClass=*)",
		attributes,
	)
	if result != 0 {
		defer ldapMsgFreeProc.Call(result)
	}
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)
	for _, attribute := range attributes {
		value, err := session.getStringValue(
			entry,
			attribute,
		)
		if err != nil {
			return nil, err
		}
		values[attribute] = value
	}

	if strings.TrimSpace(values["defaultNamingContext"]) == "" ||
		strings.TrimSpace(values["configurationNamingContext"]) == "" {
		return nil, fmt.Errorf(
			"RootDSE did not return required naming contexts",
		)
	}

	return values, nil
}

func (session *ldapSession) countSearch(
	base string,
	scope uint32,
	filter string,
) (uint32, error) {
	result, err := session.search(
		base,
		scope,
		filter,
		nil,
	)
	if result != 0 {
		defer ldapMsgFreeProc.Call(result)
	}
	if err != nil {
		return 0, err
	}

	count, _, _ := ldapCountEntriesProc.Call(
		session.handle,
		result,
	)
	return uint32(count), nil
}

func (session *ldapSession) findComputerObject(
	base string,
	sam string,
) (string, string, error) {
	entry, result, err := session.searchSingleEntry(
		base,
		uint32(ldapScopeSubtree),
		fmt.Sprintf(
			"(&(objectClass=computer)(sAMAccountName=%s))",
			escapeLDAPFilterValue(sam),
		),
		[]string{"objectSid"},
	)
	if result != 0 {
		defer ldapMsgFreeProc.Call(result)
	}
	if err != nil {
		return "", "", err
	}

	dn, err := session.entryDN(entry)
	if err != nil {
		return "", "", err
	}

	objectSID, err := session.getBinaryValue(
		entry,
		"objectSid",
	)
	if err != nil {
		return "", "", err
	}

	sid, err := sidStringFromBinary(objectSID)
	if err != nil {
		return "", "", fmt.Errorf(
			"decode computer objectSid for %s: %w",
			sam,
			err,
		)
	}

	return dn, sid, nil
}

func (session *ldapSession) findGMSA(
	base string,
	role string,
	sam string,
) (ActiveDirectoryGMSAState, error) {
	attributes := []string{
		"dNSHostName",
		"msDS-ManagedPasswordInterval",
		"msDS-GroupMSAMembership",
		"msDS-SupportedEncryptionTypes",
		"sAMAccountName",
		"servicePrincipalName",
		"userAccountControl",
	}

	entry, result, err := session.searchSingleEntry(
		base,
		uint32(ldapScopeSubtree),
		fmt.Sprintf(
			"(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=%s))",
			escapeLDAPFilterValue(sam),
		),
		attributes,
	)
	if result != 0 {
		defer ldapMsgFreeProc.Call(result)
	}
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}

	dn, err := session.entryDN(entry)
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}

	state := ActiveDirectoryGMSAState{
		DistinguishedName: dn,
		Role:              role,
	}

	state.SAMAccountName, err = session.getStringValue(
		entry,
		"sAMAccountName",
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}
	state.DNSHostName, err = session.getStringValue(
		entry,
		"dNSHostName",
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}
	state.ManagedPasswordIntervalDays, err = session.getStringValue(
		entry,
		"msDS-ManagedPasswordInterval",
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}
	state.SupportedEncryptionTypes, err = session.getStringValue(
		entry,
		"msDS-SupportedEncryptionTypes",
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}
	state.UserAccountControl, err = session.getStringValue(
		entry,
		"userAccountControl",
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}
	state.ServicePrincipalNames, err = session.getOptionalStringValues(
		entry,
		"servicePrincipalName",
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}

	membershipDescriptor, err := session.getBinaryValue(
		entry,
		"msDS-GroupMSAMembership",
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, err
	}

	state.GroupMSAMembershipBytes = uint32(
		len(membershipDescriptor),
	)
	state.PasswordRetrievalTrustees, err = decodeGMSAMembershipDescriptor(
		membershipDescriptor,
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, fmt.Errorf(
			"decode %s msDS-GroupMSAMembership: %w",
			sam,
			err,
		)
	}

	return state, nil
}

func (session *ldapSession) searchSingleEntry(
	base string,
	scope uint32,
	filter string,
	attributes []string,
) (uintptr, uintptr, error) {
	result, err := session.search(
		base,
		scope,
		filter,
		attributes,
	)
	if err != nil {
		return 0, result, err
	}

	count, _, _ := ldapCountEntriesProc.Call(
		session.handle,
		result,
	)
	switch uint32(count) {
	case 0:
		return 0, result, &ldapSearchCardinalityError{
			Base:   base,
			Count:  0,
			Filter: filter,
		}
	case 1:
	default:
		return 0, result, &ldapSearchCardinalityError{
			Base:   base,
			Count:  uint32(count),
			Filter: filter,
		}
	}

	entry, _, _ := ldapFirstEntryProc.Call(
		session.handle,
		result,
	)
	if entry == 0 {
		return 0, result, fmt.Errorf(
			"LDAP search entry is unavailable: base=%q filter=%q",
			base,
			filter,
		)
	}

	return entry, result, nil
}

func (session *ldapSession) search(
	base string,
	scope uint32,
	filter string,
	attributes []string,
) (uintptr, error) {
	basePointer, err := syscall.UTF16PtrFromString(base)
	if err != nil {
		return 0, fmt.Errorf(
			"encode LDAP search base %q: %w",
			base,
			err,
		)
	}
	filterPointer, err := syscall.UTF16PtrFromString(filter)
	if err != nil {
		return 0, fmt.Errorf(
			"encode LDAP search filter %q: %w",
			filter,
			err,
		)
	}

	attributePointers, attributeStorage, err := ldapAttributeArray(
		attributes,
	)
	if err != nil {
		return 0, err
	}

	var attributePointer uintptr
	if len(attributePointers) != 0 {
		attributePointer = uintptr(
			unsafe.Pointer(&attributePointers[0]),
		)
	}

	var result uintptr

	status, _, _ := ldapSearchSWProc.Call(
		session.handle,
		uintptr(unsafe.Pointer(basePointer)),
		uintptr(scope),
		uintptr(unsafe.Pointer(filterPointer)),
		attributePointer,
		0,
		uintptr(unsafe.Pointer(&result)),
	)

	// LazyProc.Call receives uintptr values, so keep all Go-backed buffers
	// alive until the native WinLDAP call has returned. In particular, the
	// attribute pointer array itself must remain alive; keeping only the UTF-16
	// strings alive is not sufficient.
	runtime.KeepAlive(basePointer)
	runtime.KeepAlive(filterPointer)
	runtime.KeepAlive(attributePointers)
	runtime.KeepAlive(attributeStorage)

	if status != ldapSuccess {
		if result != 0 {
			ldapMsgFreeProc.Call(result)
		}
		return 0, fmt.Errorf(
			"LDAP search failed: base=%q filter=%q: %s",
			base,
			filter,
			ldapErrorText(status),
		)
	}

	return result, nil
}

func ldapAttributeArray(
	attributes []string,
) ([]uintptr, [][]uint16, error) {
	if len(attributes) == 0 {
		return nil, nil, nil
	}

	encoded := make([][]uint16, len(attributes))
	pointers := make([]uintptr, len(attributes)+1)

	for index, attribute := range attributes {
		value, err := syscall.UTF16FromString(attribute)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"encode LDAP attribute %q: %w",
				attribute,
				err,
			)
		}
		encoded[index] = value
		pointers[index] = uintptr(
			unsafe.Pointer(&encoded[index][0]),
		)
	}

	return pointers, encoded, nil
}

func (session *ldapSession) entryDN(
	entry uintptr,
) (string, error) {
	value, _, _ := ldapGetDNWProc.Call(
		session.handle,
		entry,
	)
	if value == 0 {
		return "", fmt.Errorf(
			"LDAP entry has no distinguished name",
		)
	}
	defer ldapMemFreeWProc.Call(value)

	return windows.UTF16PtrToString(
		(*uint16)(unsafe.Pointer(value)),
	), nil
}

func (session *ldapSession) getStringValue(
	entry uintptr,
	attribute string,
) (string, error) {
	attributePointer, err := syscall.UTF16PtrFromString(
		attribute,
	)
	if err != nil {
		return "", fmt.Errorf(
			"encode LDAP attribute %q: %w",
			attribute,
			err,
		)
	}

	values, _, _ := ldapGetValuesWProc.Call(
		session.handle,
		entry,
		uintptr(unsafe.Pointer(attributePointer)),
	)
	if values == 0 {
		return "", fmt.Errorf(
			"LDAP attribute %s is missing",
			attribute,
		)
	}
	defer ldapValueFreeWProc.Call(values)

	first := *(*uintptr)(unsafe.Pointer(values))
	if first == 0 {
		return "", fmt.Errorf(
			"LDAP attribute %s has no value",
			attribute,
		)
	}

	return windows.UTF16PtrToString(
		(*uint16)(unsafe.Pointer(first)),
	), nil
}

func (session *ldapSession) getOptionalStringValues(
	entry uintptr,
	attribute string,
) ([]string, error) {
	attributePointer, err := syscall.UTF16PtrFromString(
		attribute,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode LDAP attribute %q: %w",
			attribute,
			err,
		)
	}

	values, _, _ := ldapGetValuesWProc.Call(
		session.handle,
		entry,
		uintptr(unsafe.Pointer(attributePointer)),
	)
	if values == 0 {
		return []string{}, nil
	}
	defer ldapValueFreeWProc.Call(values)

	const maximumValues = 1024
	result := make([]string, 0)
	pointerSize := unsafe.Sizeof(uintptr(0))
	for index := uintptr(0); index < maximumValues; index++ {
		current := *(*uintptr)(unsafe.Pointer(
			values + index*pointerSize,
		))
		if current == 0 {
			return result, nil
		}
		result = append(
			result,
			windows.UTF16PtrToString(
				(*uint16)(unsafe.Pointer(current)),
			),
		)
	}

	return nil, fmt.Errorf(
		"LDAP attribute %s exceeded %d values",
		attribute,
		maximumValues,
	)
}

func (session *ldapSession) getBinaryValue(
	entry uintptr,
	attribute string,
) ([]byte, error) {
	attributePointer, err := syscall.UTF16PtrFromString(
		attribute,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"encode LDAP attribute %q: %w",
			attribute,
			err,
		)
	}

	values, _, _ := ldapGetValuesLenWProc.Call(
		session.handle,
		entry,
		uintptr(unsafe.Pointer(attributePointer)),
	)
	if values == 0 {
		return nil, fmt.Errorf(
			"LDAP binary attribute %s is missing",
			attribute,
		)
	}
	defer ldapValueFreeLenProc.Call(values)

	first := *(*uintptr)(unsafe.Pointer(values))
	if first == 0 {
		return nil, fmt.Errorf(
			"LDAP binary attribute %s has no value",
			attribute,
		)
	}

	value := (*ldapBerval)(unsafe.Pointer(first))
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

	source := unsafe.Slice(
		value.Value,
		int(value.Length),
	)
	result := make([]byte, len(source))
	copy(result, source)

	return result, nil
}

func ldapErrorText(status uintptr) string {
	message, _, _ := ldapErr2StringWProc.Call(status)
	if message == 0 {
		return fmt.Sprintf(
			"LDAP error %d",
			uint32(status),
		)
	}

	return fmt.Sprintf(
		"%s (%d)",
		windows.UTF16PtrToString(
			(*uint16)(unsafe.Pointer(message)),
		),
		uint32(status),
	)
}

func escapeLDAPFilterValue(value string) string {
	var builder strings.Builder

	for _, current := range []byte(value) {
		switch current {
		case 0:
			builder.WriteString(`\00`)
		case '(':
			builder.WriteString(`\28`)
		case ')':
			builder.WriteString(`\29`)
		case '*':
			builder.WriteString(`\2a`)
		case '\\':
			builder.WriteString(`\5c`)
		default:
			builder.WriteByte(current)
		}
	}

	return builder.String()
}
