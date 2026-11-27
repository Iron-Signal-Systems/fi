// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	fiGMSAObjectClass                 = "msDS-GroupManagedServiceAccount"
	fiGMSAManagedPasswordIntervalDays = uint32(30)
	fiGMSASupportedEncryptionTypes    = uint32(28)
	fiGMSAUserAccountControl          = uint32(4096)
	fiGMSAMembershipAccessMask        = uint32(0x000F01FF)
	fiGMSAMembershipSDDLRights        = "CCDCLCSWRPWPDTLOCRSDRCWDWO"
	ldapModAdd                        = uint32(0x00)
	ldapModBinaryValues               = uint32(0x80)
	securityDescriptorRevision        = uintptr(1)
)

type GMSACreateContract struct {
	ComputerSID                 string
	DNSHostName                 string
	DistinguishedName           string
	ManagedPasswordIntervalDays uint32
	PasswordRetrievalDescriptor []byte
	Role                        string
	SAMAccountName              string
	SupportedEncryptionTypes    uint32
	UserAccountControl          uint32
}

type ldapModW struct {
	Operation uint32
	Type      *uint16
	Values    unsafe.Pointer
}

type ldapStringModStorage struct {
	attribute []uint16
	value     []uint16
	values    []*uint16
}

type ldapBinaryModStorage struct {
	attribute []uint16
	berval    ldapBerval
	value     []byte
	values    []*ldapBerval
}

var (
	convertStringSecurityDescriptorToSecurityDescriptorWProc = advapi32DLL.NewProc(
		"ConvertStringSecurityDescriptorToSecurityDescriptorW",
	)
	ldapAddSWProc     = wldap32DLL.NewProc("ldap_add_sW")
	ldapDeleteSWProc  = wldap32DLL.NewProc("ldap_delete_sW")
	localFreeGMSAProc = kernel32DLL.NewProc("LocalFree")
)

func buildDesiredGMSACreateContract(
	report Report,
	identity DesiredFIIdentity,
) (GMSACreateContract, error) {
	if !report.AD.ComputerObjectKnown {
		return GMSACreateContract{}, fmt.Errorf(
			"Active Directory computer object is not authoritatively known",
		)
	}
	if strings.TrimSpace(report.AD.ComputerSID) == "" {
		return GMSACreateContract{}, fmt.Errorf(
			"Active Directory computer SID is unavailable",
		)
	}
	if strings.TrimSpace(report.AD.DefaultNamingContext) == "" {
		return GMSACreateContract{}, fmt.Errorf(
			"Active Directory default naming context is unavailable",
		)
	}
	if strings.TrimSpace(report.Host.DomainDNS) == "" ||
		strings.EqualFold(report.Host.DomainDNS, notKnown) {
		return GMSACreateContract{}, fmt.Errorf(
			"DNS domain name is unavailable",
		)
	}
	if !report.AD.KDSRootKeyKnown {
		return GMSACreateContract{}, fmt.Errorf(
			"KDS root-key state is not authoritatively known",
		)
	}
	if report.AD.KDSRootKeyCount == 0 {
		return GMSACreateContract{}, fmt.Errorf(
			"no KDS root key is available for gMSA creation",
		)
	}

	sam := strings.TrimSpace(identity.SAMAccountName)
	if sam == "" || !strings.HasSuffix(sam, "$") {
		return GMSACreateContract{}, fmt.Errorf(
			"invalid gMSA SAM account name %q",
			sam,
		)
	}
	name := strings.TrimSuffix(sam, "$")
	if err := validateGMSARelativeName(name); err != nil {
		return GMSACreateContract{}, err
	}

	descriptor, err := buildGMSAPasswordRetrievalDescriptor(
		report.AD.ComputerSID,
	)
	if err != nil {
		return GMSACreateContract{}, err
	}

	return GMSACreateContract{
		ComputerSID: report.AD.ComputerSID,
		DNSHostName: name + "." + strings.TrimSpace(report.Host.DomainDNS),
		DistinguishedName: fmt.Sprintf(
			"CN=%s,CN=Managed Service Accounts,%s",
			name,
			strings.TrimSpace(report.AD.DefaultNamingContext),
		),
		ManagedPasswordIntervalDays: fiGMSAManagedPasswordIntervalDays,
		PasswordRetrievalDescriptor: descriptor,
		Role:                        identity.Role,
		SAMAccountName:              sam,
		SupportedEncryptionTypes:    fiGMSASupportedEncryptionTypes,
		UserAccountControl:          fiGMSAUserAccountControl,
	}, nil
}

func buildGMSAPasswordRetrievalDescriptor(
	computerSID string,
) ([]byte, error) {
	computerSID = strings.TrimSpace(computerSID)
	if computerSID == "" {
		return nil, fmt.Errorf(
			"computer SID is unavailable",
		)
	}

	sddl := fmt.Sprintf(
		"O:BAD:(A;;%s;;;%s)",
		fiGMSAMembershipSDDLRights,
		computerSID,
	)
	sddlPointer, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf(
			"encode gMSA password-retrieval SDDL: %w",
			err,
		)
	}

	var descriptor uintptr
	var descriptorLength uint32
	result, _, callErr := convertStringSecurityDescriptorToSecurityDescriptorWProc.Call(
		uintptr(unsafe.Pointer(sddlPointer)),
		securityDescriptorRevision,
		uintptr(unsafe.Pointer(&descriptor)),
		uintptr(unsafe.Pointer(&descriptorLength)),
	)
	runtime.KeepAlive(sddlPointer)
	if result == 0 {
		return nil, fmt.Errorf(
			"convert gMSA password-retrieval SDDL: %v",
			callErr,
		)
	}
	if descriptor == 0 || descriptorLength == 0 {
		if descriptor != 0 {
			localFreeGMSAProc.Call(descriptor)
		}
		return nil, fmt.Errorf(
			"converted gMSA password-retrieval descriptor is empty",
		)
	}
	defer localFreeGMSAProc.Call(descriptor)

	source := unsafe.Slice(
		(*byte)(unsafe.Pointer(descriptor)),
		int(descriptorLength),
	)
	encoded := make([]byte, len(source))
	copy(encoded, source)

	trustees, err := decodeGMSAMembershipDescriptor(encoded)
	if err != nil {
		return nil, fmt.Errorf(
			"validate generated gMSA password-retrieval descriptor: %w",
			err,
		)
	}
	if err := verifyExactFIGMSAMembershipTrustee(
		trustees,
		computerSID,
	); err != nil {
		return nil, fmt.Errorf(
			"validate generated gMSA password-retrieval authorization: %w",
			err,
		)
	}

	return encoded, nil
}

func createFIGroupManagedServiceAccount(
	session *ldapSession,
	report Report,
	identity DesiredFIIdentity,
) (ActiveDirectoryGMSAState, error) {
	state, _, err := createFIGroupManagedServiceAccountTracked(
		session,
		report,
		identity,
	)
	return state, err
}

// createFIGroupManagedServiceAccountTracked reports whether this call proved
// ownership of a newly-created object for transaction rollback purposes. Only
// LDAP_SUCCESS from ldap_add_sW establishes that ownership. If ldap_add_sW
// itself reports an error, the object is rediscovered for diagnostics, but the
// transaction never claims or deletes it because another actor could have won
// a concurrent create race.
func createFIGroupManagedServiceAccountTracked(
	session *ldapSession,
	report Report,
	identity DesiredFIIdentity,
) (
	state ActiveDirectoryGMSAState,
	createdByTransaction bool,
	err error,
) {
	if session == nil || session.handle == 0 {
		return ActiveDirectoryGMSAState{}, false, fmt.Errorf(
			"LDAP session is unavailable",
		)
	}
	if !report.AD.GMSADiscoveryKnown {
		return ActiveDirectoryGMSAState{}, false, fmt.Errorf(
			"gMSA discovery is not authoritative; refusing CREATE",
		)
	}

	contract, err := buildDesiredGMSACreateContract(
		report,
		identity,
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, false, err
	}

	// Recheck the exact object immediately before mutation. The CREATE primitive
	// never treats an existing object as success; callers must rediscover and
	// reconcile it through the normal desired-state path.
	_, err = session.findGMSA(
		report.AD.DefaultNamingContext,
		identity.Role,
		identity.SAMAccountName,
	)
	switch {
	case err == nil:
		return ActiveDirectoryGMSAState{}, false, fmt.Errorf(
			"gMSA %s already exists; refusing CREATE without authoritative reconciliation",
			identity.SAMAccountName,
		)
	case !ldapSearchReturnedNoEntries(err):
		return ActiveDirectoryGMSAState{}, false, fmt.Errorf(
			"pre-create gMSA rediscovery failed for %s: %w",
			identity.SAMAccountName,
			err,
		)
	}

	if addErr := session.addGMSA(contract); addErr != nil {
		// A failed synchronous call does not establish transaction ownership.
		// Rediscover for diagnostics, but never auto-delete an object that may
		// have been created concurrently by another administrator/process.
		observed, rediscoverErr := session.findGMSA(
			report.AD.DefaultNamingContext,
			identity.Role,
			identity.SAMAccountName,
		)
		if ldapSearchReturnedNoEntries(rediscoverErr) {
			return ActiveDirectoryGMSAState{}, false, addErr
		}
		if rediscoverErr != nil {
			return ActiveDirectoryGMSAState{}, false, fmt.Errorf(
				"%w; failed CREATE rediscovery for %s: %v",
				addErr,
				identity.SAMAccountName,
				rediscoverErr,
			)
		}
		if verifyErr := verifyGMSACreateContract(
			contract,
			observed,
		); verifyErr != nil {
			return observed, false, fmt.Errorf(
				"%w; an object now exists at %s and does not match the exact FI create contract; transaction ownership is not established: %v",
				addErr,
				contract.DistinguishedName,
				verifyErr,
			)
		}
		return observed, false, fmt.Errorf(
			"%w; an exact FI gMSA is now present, but ldap_add_sW did not return success so transaction ownership is not established and automatic rollback is refused",
			addErr,
		)
	}

	createdByTransaction = true
	created, err := session.findGMSA(
		report.AD.DefaultNamingContext,
		identity.Role,
		identity.SAMAccountName,
	)
	if err != nil {
		return ActiveDirectoryGMSAState{}, createdByTransaction, fmt.Errorf(
			"post-create gMSA rediscovery failed for %s: %w",
			identity.SAMAccountName,
			err,
		)
	}
	if err := verifyGMSACreateContract(
		contract,
		created,
	); err != nil {
		return created, createdByTransaction, fmt.Errorf(
			"post-create gMSA verification failed for %s: %w",
			identity.SAMAccountName,
			err,
		)
	}

	return created, createdByTransaction, nil
}

// deleteFIGroupManagedServiceAccountIfExact is a rollback primitive, not a
// general deletion API. It removes only an object that still matches the exact
// FI contract derived for this host. If the object has drifted or been replaced
// by something different, deletion is refused and the rollback error is surfaced
// for operator review. Absence is already the desired rollback state.
func deleteFIGroupManagedServiceAccountIfExact(
	session *ldapSession,
	report Report,
	identity DesiredFIIdentity,
) error {
	if session == nil || session.handle == 0 {
		return fmt.Errorf("LDAP session is unavailable")
	}

	contract, err := buildDesiredGMSACreateContract(
		report,
		identity,
	)
	if err != nil {
		return err
	}

	observed, err := session.findGMSA(
		report.AD.DefaultNamingContext,
		identity.Role,
		identity.SAMAccountName,
	)
	if ldapSearchReturnedNoEntries(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"rollback rediscovery failed for %s: %w",
			identity.SAMAccountName,
			err,
		)
	}
	if err := verifyGMSACreateContract(
		contract,
		observed,
	); err != nil {
		return fmt.Errorf(
			"refusing rollback delete for %s because the current object no longer matches the exact FI create contract: %w",
			identity.SAMAccountName,
			err,
		)
	}

	dnPointer, err := syscall.UTF16PtrFromString(
		contract.DistinguishedName,
	)
	if err != nil {
		return fmt.Errorf(
			"encode rollback gMSA distinguished name %q: %w",
			contract.DistinguishedName,
			err,
		)
	}

	status, _, _ := ldapDeleteSWProc.Call(
		session.handle,
		uintptr(unsafe.Pointer(dnPointer)),
	)
	runtime.KeepAlive(dnPointer)
	if status != ldapSuccess {
		return fmt.Errorf(
			"LDAP rollback delete gMSA %s at %s: %s",
			identity.SAMAccountName,
			contract.DistinguishedName,
			ldapErrorText(status),
		)
	}

	_, err = session.findGMSA(
		report.AD.DefaultNamingContext,
		identity.Role,
		identity.SAMAccountName,
	)
	if ldapSearchReturnedNoEntries(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"post-rollback absence verification failed for %s: %w",
			identity.SAMAccountName,
			err,
		)
	}
	return fmt.Errorf(
		"post-rollback verification found gMSA %s still present",
		identity.SAMAccountName,
	)
}

func (session *ldapSession) addGMSA(
	contract GMSACreateContract,
) error {
	if session == nil || session.handle == 0 {
		return fmt.Errorf("LDAP session is unavailable")
	}

	stringAttributes := []struct {
		name  string
		value string
	}{
		{name: "objectClass", value: fiGMSAObjectClass},
		{name: "cn", value: strings.TrimSuffix(contract.SAMAccountName, "$")},
		{name: "sAMAccountName", value: contract.SAMAccountName},
		{name: "dNSHostName", value: contract.DNSHostName},
		{
			name: "userAccountControl",
			value: strconv.FormatUint(
				uint64(contract.UserAccountControl),
				10,
			),
		},
		{
			name: "msDS-ManagedPasswordInterval",
			value: strconv.FormatUint(
				uint64(contract.ManagedPasswordIntervalDays),
				10,
			),
		},
		{
			name: "msDS-SupportedEncryptionTypes",
			value: strconv.FormatUint(
				uint64(contract.SupportedEncryptionTypes),
				10,
			),
		},
	}

	mods := make(
		[]ldapModW,
		0,
		len(stringAttributes)+1,
	)
	stringStorage := make(
		[]*ldapStringModStorage,
		0,
		len(stringAttributes),
	)

	for _, attribute := range stringAttributes {
		mod, storage, err := newLDAPStringAddMod(
			attribute.name,
			attribute.value,
		)
		if err != nil {
			return err
		}
		mods = append(mods, mod)
		stringStorage = append(stringStorage, storage)
	}

	binaryMod, binaryStorage, err := newLDAPBinaryAddMod(
		"msDS-GroupMSAMembership",
		contract.PasswordRetrievalDescriptor,
	)
	if err != nil {
		return err
	}
	mods = append(mods, binaryMod)

	modPointers := make([]*ldapModW, len(mods)+1)
	for index := range mods {
		modPointers[index] = &mods[index]
	}

	dnPointer, err := syscall.UTF16PtrFromString(
		contract.DistinguishedName,
	)
	if err != nil {
		return fmt.Errorf(
			"encode gMSA distinguished name %q: %w",
			contract.DistinguishedName,
			err,
		)
	}

	status, _, _ := ldapAddSWProc.Call(
		session.handle,
		uintptr(unsafe.Pointer(dnPointer)),
		uintptr(unsafe.Pointer(&modPointers[0])),
	)

	runtime.KeepAlive(dnPointer)
	runtime.KeepAlive(modPointers)
	runtime.KeepAlive(mods)
	runtime.KeepAlive(stringStorage)
	runtime.KeepAlive(binaryStorage)

	if status != ldapSuccess {
		return fmt.Errorf(
			"LDAP add gMSA %s at %s: %s",
			contract.SAMAccountName,
			contract.DistinguishedName,
			ldapErrorText(status),
		)
	}

	return nil
}

func newLDAPStringAddMod(
	attribute string,
	value string,
) (ldapModW, *ldapStringModStorage, error) {
	encodedAttribute, err := syscall.UTF16FromString(attribute)
	if err != nil {
		return ldapModW{}, nil, fmt.Errorf(
			"encode LDAP attribute %q: %w",
			attribute,
			err,
		)
	}
	encodedValue, err := syscall.UTF16FromString(value)
	if err != nil {
		return ldapModW{}, nil, fmt.Errorf(
			"encode LDAP value for %s: %w",
			attribute,
			err,
		)
	}

	storage := &ldapStringModStorage{
		attribute: encodedAttribute,
		value:     encodedValue,
	}
	storage.values = []*uint16{
		&storage.value[0],
		nil,
	}

	return ldapModW{
		Operation: ldapModAdd,
		Type:      &storage.attribute[0],
		Values:    unsafe.Pointer(&storage.values[0]),
	}, storage, nil
}

func newLDAPBinaryAddMod(
	attribute string,
	value []byte,
) (ldapModW, *ldapBinaryModStorage, error) {
	if len(value) == 0 {
		return ldapModW{}, nil, fmt.Errorf(
			"LDAP binary value for %s is empty",
			attribute,
		)
	}

	encodedAttribute, err := syscall.UTF16FromString(attribute)
	if err != nil {
		return ldapModW{}, nil, fmt.Errorf(
			"encode LDAP attribute %q: %w",
			attribute,
			err,
		)
	}

	storage := &ldapBinaryModStorage{
		attribute: encodedAttribute,
		value:     append([]byte(nil), value...),
	}
	storage.berval = ldapBerval{
		Length: uint32(len(storage.value)),
		Value:  &storage.value[0],
	}
	storage.values = []*ldapBerval{
		&storage.berval,
		nil,
	}

	return ldapModW{
		Operation: ldapModAdd | ldapModBinaryValues,
		Type:      &storage.attribute[0],
		Values:    unsafe.Pointer(&storage.values[0]),
	}, storage, nil
}

func validateGMSARelativeName(name string) error {
	if name == "" {
		return fmt.Errorf("gMSA relative name is empty")
	}
	for _, current := range name {
		switch {
		case current >= 'A' && current <= 'Z':
		case current >= 'a' && current <= 'z':
		case current >= '0' && current <= '9':
		case current == '-':
		default:
			return fmt.Errorf(
				"gMSA relative name %q contains unsupported distinguished-name character %q",
				name,
				current,
			)
		}
	}
	return nil
}

func verifyExactFIGMSAMembershipTrustee(
	trustees []GMSAMembershipTrustee,
	expectedSID string,
) error {
	if len(trustees) != 1 {
		return fmt.Errorf(
			"expected exactly one password-retrieval trustee; observed=%s",
			formatGMSATrustees(trustees),
		)
	}

	trustee := trustees[0]
	if !strings.EqualFold(
		strings.TrimSpace(trustee.SID),
		strings.TrimSpace(expectedSID),
	) {
		return fmt.Errorf(
			"expected password-retrieval SID %s; observed=%s",
			expectedSID,
			trustee.SID,
		)
	}
	if trustee.Type != "ALLOW" {
		return fmt.Errorf(
			"expected ACCESS_ALLOWED_ACE; observed=%s",
			trustee.Type,
		)
	}
	if trustee.Flags != 0 {
		return fmt.Errorf(
			"expected password-retrieval ACE flags=0x00; observed=0x%02X",
			trustee.Flags,
		)
	}
	if trustee.Mask != fiGMSAMembershipAccessMask {
		return fmt.Errorf(
			"expected password-retrieval ACE mask=0x%08X; observed=0x%08X",
			fiGMSAMembershipAccessMask,
			trustee.Mask,
		)
	}

	return nil
}

func verifyGMSACreateContract(
	contract GMSACreateContract,
	observed ActiveDirectoryGMSAState,
) error {
	if !strings.EqualFold(
		strings.TrimSpace(observed.DistinguishedName),
		strings.TrimSpace(contract.DistinguishedName),
	) {
		return fmt.Errorf(
			"distinguishedName expected=%q observed=%q",
			contract.DistinguishedName,
			observed.DistinguishedName,
		)
	}
	if !strings.EqualFold(
		strings.TrimSpace(observed.SAMAccountName),
		strings.TrimSpace(contract.SAMAccountName),
	) {
		return fmt.Errorf(
			"sAMAccountName expected=%q observed=%q",
			contract.SAMAccountName,
			observed.SAMAccountName,
		)
	}
	if !strings.EqualFold(
		strings.TrimSpace(observed.DNSHostName),
		strings.TrimSpace(contract.DNSHostName),
	) {
		return fmt.Errorf(
			"dNSHostName expected=%q observed=%q",
			contract.DNSHostName,
			observed.DNSHostName,
		)
	}

	interval, err := parseLDAPUint32(
		"msDS-ManagedPasswordInterval",
		observed.ManagedPasswordIntervalDays,
	)
	if err != nil {
		return err
	}
	if interval != contract.ManagedPasswordIntervalDays {
		return fmt.Errorf(
			"msDS-ManagedPasswordInterval expected=%d observed=%d",
			contract.ManagedPasswordIntervalDays,
			interval,
		)
	}

	uac, err := parseLDAPUint32(
		"userAccountControl",
		observed.UserAccountControl,
	)
	if err != nil {
		return err
	}
	if uac != contract.UserAccountControl {
		return fmt.Errorf(
			"userAccountControl expected=%d observed=%d",
			contract.UserAccountControl,
			uac,
		)
	}

	encryptionTypes, err := parseLDAPUint32(
		"msDS-SupportedEncryptionTypes",
		observed.SupportedEncryptionTypes,
	)
	if err != nil {
		return err
	}
	if encryptionTypes != contract.SupportedEncryptionTypes {
		return fmt.Errorf(
			"msDS-SupportedEncryptionTypes expected=%d observed=%d",
			contract.SupportedEncryptionTypes,
			encryptionTypes,
		)
	}

	if len(observed.ServicePrincipalNames) != 0 {
		return fmt.Errorf(
			"servicePrincipalName expected empty; observed=%s",
			strings.Join(observed.ServicePrincipalNames, ", "),
		)
	}

	if err := verifyExactFIGMSAMembershipTrustee(
		observed.PasswordRetrievalTrustees,
		contract.ComputerSID,
	); err != nil {
		return err
	}

	return nil
}

func parseLDAPUint32(
	attribute string,
	value string,
) (uint32, error) {
	parsed, err := strconv.ParseUint(
		strings.TrimSpace(value),
		10,
		32,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"parse %s value %q: %w",
			attribute,
			value,
			err,
		)
	}
	return uint32(parsed), nil
}
