// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	adsRightActrlDSList     = uint32(0x00000004)
	adsRightDSReadProp      = uint32(0x00000010)
	adsRightDSWriteProp     = uint32(0x00000020)
	adsRightDSListObject    = uint32(0x00000080)
	adsRightDSControlAccess = uint32(0x00000100)
	adsRightReadControl     = uint32(0x00020000)

	certificateTemplateGenericReadMask = adsRightReadControl |
		adsRightActrlDSList |
		adsRightDSReadProp |
		adsRightDSListObject

	caPropertyCAName     = uint32(0x00000006)
	caPropertyTypeString = uint32(0x00000004)

	accessAllowedACE       = byte(0x00)
	accessDeniedACE        = byte(0x01)
	accessAllowedObjectACE = byte(0x05)
	accessDeniedObjectACE  = byte(0x06)

	aceObjectTypePresent          = uint32(0x00000001)
	aceInheritedObjectTypePresent = uint32(0x00000002)

	seGroupEnabled        = uint32(0x00000004)
	seGroupUseForDenyOnly = uint32(0x00000010)

	genericAllAccess   = uint32(0x10000000)
	genericWriteAccess = uint32(0x40000000)
)

var certificateEnrollmentExtendedRightGUID = [16]byte{
	0x68, 0xC9, 0x10, 0x0E,
	0xFB, 0x78,
	0xD2, 0x11,
	0x90, 0xD4, 0x00, 0xC0, 0x4F, 0x79, 0xDC, 0x55,
}

// schemaIDGUID for the Active Directory group member attribute
// bf9679c0-0de6-11d0-a285-00aa003049e2, encoded in object-ACE byte order.
var activeDirectoryMemberAttributeGUID = [16]byte{
	0xC0, 0x79, 0x96, 0xBF,
	0xE6, 0x0D,
	0xD0, 0x11,
	0xA2, 0x85, 0x00, 0xAA, 0x00, 0x30, 0x49, 0xE2,
}

// CLSID_CCertRequest is the client-side Certificate Services request COM
// class provided by certcli.dll. The prerequisite engine uses only the
// read-only request interface so source servers do not require CA admin tools.
var certificateAuthorityRequestCLSID = windows.GUID{
	Data1: 0x98aff3f0,
	Data2: 0x5524,
	Data3: 0x11d0,
	Data4: [8]byte{
		0x88, 0x12, 0x00, 0xa0,
		0xc9, 0x03, 0xb8, 0x3c,
	},
}

var ldapNextEntryPrerequisiteProc = wldap32DLL.NewProc(
	"ldap_next_entry",
)

type certificateTemplatePrerequisiteState struct {
	EnrollAllowed bool
	OID           string
	ReadAllowed   bool
	TemplateName  string
}

type certificateEnrollmentGroupPrerequisiteState struct {
	DistinguishedName  string
	SID                string
	SecurityDescriptor []byte
}

type enterpriseCertificateAuthorityState struct {
	CommonName    string
	Configuration string
	DNSHostName   string
	Templates     []string
}

type installerTokenPrerequisiteState struct {
	Account            string
	AllowSIDs          map[string]struct{}
	DenyOnlyGroupCount int
	DenySIDs           map[string]struct{}
	EnabledGroupCount  int
	SID                string
}

func prerequisitePKIEnvironment(
	result *PrerequisiteReport,
	report Report,
) {
	if transportPKIComplete(report) {
		result.add(
			prerequisitePass,
			"FI transport PKI",
			"existing FI transport trust and identities satisfy discovery",
		)
		return
	}

	expectedDNS, err := approval1PKIExpectedDNS(
		report,
	)
	if err != nil {
		result.add(
			prerequisiteFail,
			"FI certificate DNS identity",
			err.Error(),
		)
		return
	}

	result.add(
		prerequisitePass,
		"FI certificate DNS identity",
		expectedDNS,
	)

	tokenState, err := currentInstallerTokenPrerequisiteState()
	if err != nil {
		result.add(
			prerequisiteFail,
			"Installer requester identity/token",
			err.Error(),
		)
		return
	}

	result.add(
		prerequisitePass,
		"Installer requester identity",
		fmt.Sprintf(
			"account=%s sid=%s",
			tokenState.Account,
			tokenState.SID,
		),
	)
	result.add(
		prerequisitePass,
		"Installer requester token",
		fmt.Sprintf(
			"elevated=%t enabled_groups=%d deny_only_groups=%d",
			report.Host.Elevated,
			tokenState.EnabledGroupCount,
			tokenState.DenyOnlyGroupCount,
		),
	)

	if strings.TrimSpace(report.AD.DomainController) == "" ||
		strings.TrimSpace(report.AD.DefaultNamingContext) == "" ||
		strings.TrimSpace(report.AD.ConfigurationNamingContext) == "" {
		result.add(
			prerequisiteFail,
			"FI certificate authority discovery",
			"Active Directory naming context/domain controller is unavailable",
		)
		return
	}

	session, err := openLDAPSession(
		report.AD.DomainController,
	)
	if err != nil {
		result.add(
			prerequisiteFail,
			"FI certificate authority discovery",
			err.Error(),
		)
		return
	}
	defer session.close()

	group, err := discoverCertificateEnrollmentGroupPrerequisite(
		session,
		report.AD.DefaultNamingContext,
		fiCertificateEnrollmentGroupName,
	)
	if err != nil {
		result.add(
			prerequisiteFail,
			"FI certificate enrollment group",
			err.Error(),
		)
		return
	}

	machineAllowSIDs, machineDenySIDs, err :=
		activeDirectoryObjectSIDMembership(
			session,
			report.AD.ComputerDN,
			report.AD.ComputerSID,
		)
	if err != nil {
		result.add(
			prerequisiteFail,
			"FI source-computer authorization token",
			err.Error(),
		)
		return
	}

	groupSID := strings.ToUpper(
		strings.TrimSpace(group.SID),
	)
	_, alreadyMember := machineAllowSIDs[groupSID]

	// Evaluate the exact post-Approval-1 machine authorization state without
	// mutating AD: the existing group SID is added to the source computer's
	// current AD tokenGroups set. This predicts the token after the approved
	// direct membership change and mandatory SYSTEM Kerberos purge.
	machineAllowSIDs[groupSID] = struct{}{}
	machineDenySIDs[groupSID] = struct{}{}

	result.add(
		prerequisitePass,
		"FI certificate enrollment group",
		fmt.Sprintf(
			"group=%s sid=%s source_computer=%s member=%t",
			fiCertificateEnrollmentGroupName,
			group.SID,
			report.AD.ComputerDN,
			alreadyMember,
		),
	)

	if alreadyMember {
		result.add(
			prerequisitePass,
			"FI enrollment-group membership authority",
			"source computer is already authorized by the existing FI certificate-enrollment group; no group mutation is required",
		)
	} else {
		canWriteMember, err := securityDescriptorAllowsDirectoryMemberWrite(
			group.SecurityDescriptor,
			tokenState.AllowSIDs,
			tokenState.DenySIDs,
		)
		if err != nil {
			result.add(
				prerequisiteFail,
				"FI enrollment-group membership authority",
				err.Error(),
			)
			return
		}
		if !canWriteMember {
			result.add(
				prerequisiteFail,
				"FI enrollment-group membership authority",
				fmt.Sprintf(
					"requester=%s cannot write the member attribute on existing group %s; source computer %s cannot be authorized during Approval 1",
					tokenState.Account,
					fiCertificateEnrollmentGroupName,
					report.AD.ComputerDN,
				),
			)
			return
		}
		result.add(
			prerequisitePass,
			"FI enrollment-group membership authority",
			fmt.Sprintf(
				"requester=%s can add source computer %s to existing group %s during Approval 1",
				tokenState.Account,
				report.AD.ComputerDN,
				fiCertificateEnrollmentGroupName,
			),
		)
	}

	if err := machineKerberosPurgePrerequisite(); err != nil {
		result.add(
			prerequisiteFail,
			"Machine Kerberos refresh",
			err.Error(),
		)
		return
	}
	result.add(
		prerequisitePass,
		"Machine Kerberos refresh",
		"klist.exe is available; Approval 1 will purge SYSTEM logon session LUID 0x3e7 after membership verification and before certificate enrollment",
	)

	cas, err := discoverEnterpriseCertificateAuthorities(
		session,
		report.AD.ConfigurationNamingContext,
	)
	if err != nil {
		result.add(
			prerequisiteFail,
			"FI certificate authority discovery",
			err.Error(),
		)
		return
	}

	sourceEnrollmentTemplates := []string{
		fiTransportClientTemplateName,
		fiBatchSigningTemplateName,
	}
	publicationTemplates := []string{
		fiTransportClientTemplateName,
		fiBatchSigningTemplateName,
		fiReceiverTLSTemplateName,
	}

	// Resolve and evaluate the two source-enrollment template definitions
	// against the exact post-membership source-computer token before offering
	// to change shared CA publication state. FI-Receiver-TLS is a receiver-side
	// server identity template and is not an enrollment right required by the
	// Windows source computer.
	templateStates := make(
		map[string]certificateTemplatePrerequisiteState,
		len(sourceEnrollmentTemplates),
	)
	for _, templateName := range sourceEnrollmentTemplates {
		state, err := inspectCertificateTemplatePrerequisite(
			session,
			report.AD.ConfigurationNamingContext,
			machineAllowSIDs,
			machineDenySIDs,
			templateName,
		)
		if err != nil {
			result.add(
				prerequisiteFail,
				templateName+" template",
				err.Error(),
			)
			return
		}
		templateStates[templateName] = state

		if !state.ReadAllowed {
			result.add(
				prerequisiteFail,
				templateName+" source-computer Read",
				fmt.Sprintf(
					"source=%s would not have effective template Read even after membership in %s",
					report.AD.ComputerDN,
					fiCertificateEnrollmentGroupName,
				),
			)
			return
		}
		if !state.EnrollAllowed {
			result.add(
				prerequisiteFail,
				templateName+" source-computer Enroll",
				fmt.Sprintf(
					"source=%s would not have effective certificate Enroll control access even after membership in %s",
					report.AD.ComputerDN,
					fiCertificateEnrollmentGroupName,
				),
			)
			return
		}
	}

	receiverTemplateOID, err := resolveCertificateTemplateOID(
		session,
		report.AD.ConfigurationNamingContext,
		fiReceiverTLSTemplateName,
	)
	if err != nil {
		result.add(
			prerequisiteFail,
			fiReceiverTLSTemplateName+" template",
			err.Error(),
		)
		return
	}

	publicationPlan, publicationRequired, err :=
		buildCATemplatePublicationPlanFromCAs(
			report.AD.DomainController,
			cas,
			publicationTemplates,
			nil,
		)
	if err != nil {
		result.add(
			prerequisiteFail,
			"Enterprise CA template publication",
			err.Error(),
		)
		return
	}

	if publicationRequired {
		result.add(
			prerequisiteApproval,
			"Enterprise CA template publication",
			fmt.Sprintf(
				"issuing_ca=%s missing=%s; explicit approval is required before deployment input; FI will publish the existing AD certificate template definition(s) to this CA's available-template list and will not alter template ACLs, template cryptographic settings, or CA keys",
				publicationPlan.CAConfiguration,
				strings.Join(publicationPlan.MissingTemplates, ","),
			),
		)
	} else {
		commonCAs := enterpriseCAsPublishingAll(
			cas,
			publicationTemplates,
		)
		caConfigurations := enterpriseCAConfigurations(
			commonCAs,
		)
		for _, templateName := range publicationTemplates {
			result.add(
				prerequisitePass,
				templateName+" publication",
				fmt.Sprintf(
					"published by issuing CA(s): %s",
					strings.Join(caConfigurations, ", "),
				),
			)
		}
	}

	for _, templateName := range sourceEnrollmentTemplates {
		state := templateStates[templateName]
		result.add(
			prerequisitePass,
			templateName+" template",
			"exists and OID="+state.OID,
		)
		result.add(
			prerequisitePass,
			templateName+" source-computer Read",
			fmt.Sprintf(
				"source=%s has effective template Read in the post-membership machine token",
				report.AD.ComputerDN,
			),
		)
		result.add(
			prerequisitePass,
			templateName+" source-computer Enroll",
			fmt.Sprintf(
				"source=%s has effective certificate Enroll control access in the post-membership machine token",
				report.AD.ComputerDN,
			),
		)
	}
	result.add(
		prerequisitePass,
		fiReceiverTLSTemplateName+" template",
		"exists and OID="+receiverTemplateOID+"; receiver-side server identity template is included in FI CA publication readiness",
	)

}

func discoverCertificateEnrollmentGroupPrerequisite(
	session *ldapSession,
	defaultNamingContext string,
	groupName string,
) (certificateEnrollmentGroupPrerequisiteState, error) {
	if session == nil || session.handle == 0 {
		return certificateEnrollmentGroupPrerequisiteState{}, fmt.Errorf(
			"LDAP session is unavailable",
		)
	}

	entry, result, err := session.searchSingleEntry(
		strings.TrimSpace(defaultNamingContext),
		uint32(2),
		fmt.Sprintf(
			"(&(objectClass=group)(sAMAccountName=%s))",
			escapeLDAPFilterValue(groupName),
		),
		[]string{
			"distinguishedName",
			"objectSid",
			"nTSecurityDescriptor",
		},
	)
	if result != 0 {
		defer ldapMsgFreeProc.Call(result)
	}
	if err != nil {
		return certificateEnrollmentGroupPrerequisiteState{}, fmt.Errorf(
			"discover existing FI certificate enrollment group %s: %w",
			groupName,
			err,
		)
	}

	dn, err := session.getStringValue(
		entry,
		"distinguishedName",
	)
	if err != nil {
		return certificateEnrollmentGroupPrerequisiteState{}, err
	}

	sidBytes, err := session.getBinaryValue(
		entry,
		"objectSid",
	)
	if err != nil {
		return certificateEnrollmentGroupPrerequisiteState{}, err
	}
	sid, err := sidStringFromACEBytes(
		sidBytes,
	)
	if err != nil {
		return certificateEnrollmentGroupPrerequisiteState{}, fmt.Errorf(
			"decode %s SID: %w",
			groupName,
			err,
		)
	}

	descriptor, err := session.getBinaryValue(
		entry,
		"nTSecurityDescriptor",
	)
	if err != nil {
		return certificateEnrollmentGroupPrerequisiteState{}, fmt.Errorf(
			"read %s security descriptor: %w",
			groupName,
			err,
		)
	}

	return certificateEnrollmentGroupPrerequisiteState{
		DistinguishedName:  strings.TrimSpace(dn),
		SID:                strings.ToUpper(strings.TrimSpace(sid)),
		SecurityDescriptor: append([]byte(nil), descriptor...),
	}, nil
}

func activeDirectoryObjectSIDMembership(
	session *ldapSession,
	distinguishedName string,
	objectSID string,
) (
	map[string]struct{},
	map[string]struct{},
	error,
) {
	if session == nil || session.handle == 0 {
		return nil, nil, fmt.Errorf(
			"LDAP session is unavailable",
		)
	}

	distinguishedName = strings.TrimSpace(
		distinguishedName,
	)
	objectSID = strings.ToUpper(
		strings.TrimSpace(
			objectSID,
		),
	)
	if distinguishedName == "" || objectSID == "" {
		return nil, nil, fmt.Errorf(
			"source computer DN/SID is unavailable",
		)
	}

	entry, result, err := session.searchSingleEntry(
		distinguishedName,
		uint32(ldapScopeBase),
		"(objectClass=computer)",
		[]string{
			"tokenGroups",
		},
	)
	if result != 0 {
		defer ldapMsgFreeProc.Call(result)
	}
	if err != nil {
		return nil, nil, err
	}

	values, err := session.getOptionalBinaryValues(
		entry,
		"tokenGroups",
	)
	if err != nil {
		return nil, nil, err
	}

	allow := make(map[string]struct{}, len(values)+3)
	deny := make(map[string]struct{}, len(values)+3)
	for _, sid := range []string{
		objectSID,
		"S-1-1-0",  // Everyone
		"S-1-5-11", // Authenticated Users
	} {
		allow[sid] = struct{}{}
		deny[sid] = struct{}{}
	}

	for _, value := range values {
		sid, err := sidStringFromACEBytes(
			value,
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"decode tokenGroups SID: %w",
				err,
			)
		}
		sid = strings.ToUpper(strings.TrimSpace(sid))
		if sid == "" {
			continue
		}
		allow[sid] = struct{}{}
		deny[sid] = struct{}{}
	}

	return allow, deny, nil
}

func securityDescriptorAllowsDirectoryMemberWrite(
	descriptor []byte,
	allowSIDs map[string]struct{},
	denySIDs map[string]struct{},
) (bool, error) {
	if len(descriptor) < 20 {
		return false, fmt.Errorf(
			"security descriptor is too short: %d bytes",
			len(descriptor),
		)
	}

	daclOffset := int(binary.LittleEndian.Uint32(descriptor[16:20]))
	if daclOffset == 0 {
		return false, fmt.Errorf("enrollment group has no DACL")
	}
	if daclOffset < 0 || daclOffset+8 > len(descriptor) {
		return false, fmt.Errorf("enrollment group DACL offset is invalid")
	}

	aclSize := int(binary.LittleEndian.Uint16(descriptor[daclOffset+2 : daclOffset+4]))
	aceCount := int(binary.LittleEndian.Uint16(descriptor[daclOffset+4 : daclOffset+6]))
	if aclSize < 8 || daclOffset+aclSize > len(descriptor) {
		return false, fmt.Errorf("enrollment group DACL size=%d is invalid", aclSize)
	}

	offset := daclOffset + 8
	allowed := false
	for index := 0; index < aceCount; index++ {
		if offset+4 > daclOffset+aclSize {
			return false, fmt.Errorf("ACE %d header exceeds DACL boundary", index)
		}
		aceSize := int(binary.LittleEndian.Uint16(descriptor[offset+2 : offset+4]))
		if aceSize < 8 || offset+aceSize > daclOffset+aclSize {
			return false, fmt.Errorf("ACE %d size=%d is invalid", index, aceSize)
		}

		aceType := descriptor[offset]
		applies, sid, mask, err := directoryMemberWriteACE(
			descriptor[offset : offset+aceSize],
		)
		if err != nil {
			return false, fmt.Errorf("parse ACE %d: %w", index, err)
		}
		if applies && (mask&adsRightDSWriteProp != 0 ||
			mask&genericWriteAccess != 0 ||
			mask&genericAllAccess != 0) {
			switch aceType {
			case accessDeniedACE, accessDeniedObjectACE:
				if _, found := denySIDs[sid]; found {
					return false, nil
				}
			case accessAllowedACE, accessAllowedObjectACE:
				if _, found := allowSIDs[sid]; found {
					allowed = true
				}
			}
		}
		offset += aceSize
	}
	return allowed, nil
}

func directoryMemberWriteACE(
	ace []byte,
) (
	applies bool,
	sid string,
	mask uint32,
	err error,
) {
	if len(ace) < 8 {
		return false, "", 0, fmt.Errorf("ACE is too short: %d bytes", len(ace))
	}

	aceType := ace[0]
	mask = binary.LittleEndian.Uint32(ace[4:8])
	sidOffset := 8
	applies = true

	switch aceType {
	case accessAllowedACE, accessDeniedACE:
	case accessAllowedObjectACE, accessDeniedObjectACE:
		if len(ace) < 12 {
			return false, "", 0, fmt.Errorf("object ACE is too short: %d bytes", len(ace))
		}
		flags := binary.LittleEndian.Uint32(ace[8:12])
		sidOffset = 12
		if flags&aceObjectTypePresent != 0 {
			if sidOffset+16 > len(ace) {
				return false, "", 0, fmt.Errorf("object ACE ObjectType exceeds ACE boundary")
			}
			applies = equalGUIDBytes(
				ace[sidOffset:sidOffset+16],
				activeDirectoryMemberAttributeGUID[:],
			)
			sidOffset += 16
		}
		if flags&aceInheritedObjectTypePresent != 0 {
			sidOffset += 16
		}
	default:
		return false, "", mask, nil
	}

	if sidOffset >= len(ace) {
		return false, "", 0, fmt.Errorf("ACE SID offset=%d exceeds ACE bytes=%d", sidOffset, len(ace))
	}
	sid, err = sidStringFromACEBytes(ace[sidOffset:])
	if err != nil {
		return false, "", 0, err
	}
	return applies, strings.ToUpper(sid), mask, nil
}

func (session *ldapSession) getOptionalBinaryValues(
	entry uintptr,
	attribute string,
) ([][]byte, error) {
	attributePointer, err := syscall.UTF16PtrFromString(attribute)
	if err != nil {
		return nil, fmt.Errorf("encode LDAP attribute %q: %w", attribute, err)
	}

	values, _, _ := ldapGetValuesLenWProc.Call(
		session.handle,
		entry,
		uintptr(unsafe.Pointer(attributePointer)),
	)
	runtime.KeepAlive(attributePointer)
	if values == 0 {
		return nil, nil
	}
	defer ldapValueFreeLenProc.Call(values)

	result := make([][]byte, 0)
	for index := 0; ; index++ {
		valuePointer := *(**ldapBerval)(unsafe.Pointer(values + uintptr(index)*unsafe.Sizeof(uintptr(0))))
		if valuePointer == nil {
			break
		}
		if valuePointer.Length == 0 || valuePointer.Value == nil {
			continue
		}
		value := append([]byte(nil), unsafe.Slice(valuePointer.Value, int(valuePointer.Length))...)
		result = append(result, value)
	}
	return result, nil
}

func prerequisitePKIInput(
	result *PrerequisiteReport,
	report Report,
	inputs PlanInputs,
) {
	if transportPKIComplete(report) {
		return
	}

	choice := strings.ToLower(
		strings.TrimSpace(
			inputs.PKIChoice,
		),
	)
	if choice == "" {
		result.add(
			prerequisiteFail,
			"FI PKI bootstrap path",
			"PKI bootstrap choice is required after environment prerequisites pass",
		)
		return
	}

	if choice != "enroll" {
		result.add(
			prerequisiteFail,
			"FI PKI bootstrap path",
			fmt.Sprintf(
				"current native mutation backend supports only enroll; observed=%q",
				inputs.PKIChoice,
			),
		)
		return
	}

	result.add(
		prerequisitePass,
		"FI PKI bootstrap path",
		"enroll",
	)
}

func inspectCertificateTemplatePrerequisite(
	session *ldapSession,
	configurationNamingContext string,
	allowSIDs map[string]struct{},
	denySIDs map[string]struct{},
	templateName string,
) (certificateTemplatePrerequisiteState, error) {
	if session == nil || session.handle == 0 {
		return certificateTemplatePrerequisiteState{}, fmt.Errorf(
			"LDAP session is unavailable",
		)
	}

	templateBase := fmt.Sprintf(
		"CN=Certificate Templates,CN=Public Key Services,CN=Services,%s",
		configurationNamingContext,
	)

	entry, result, err := session.searchSingleEntry(
		templateBase,
		uint32(ldapScopeOneLevel),
		fmt.Sprintf(
			"(&(objectClass=pKICertificateTemplate)(cn=%s))",
			escapeLDAPFilterValue(templateName),
		),
		[]string{
			"cn",
			"msPKI-Cert-Template-OID",
			"nTSecurityDescriptor",
		},
	)
	if result != 0 {
		defer ldapMsgFreeProc.Call(result)
	}
	if err != nil {
		return certificateTemplatePrerequisiteState{}, fmt.Errorf(
			"discover certificate template %s: %w",
			templateName,
			err,
		)
	}

	oid, err := session.getStringValue(
		entry,
		"msPKI-Cert-Template-OID",
	)
	if err != nil {
		return certificateTemplatePrerequisiteState{}, fmt.Errorf(
			"read %s template OID: %w",
			templateName,
			err,
		)
	}

	descriptor, err := session.getBinaryValue(
		entry,
		"nTSecurityDescriptor",
	)
	if err != nil {
		return certificateTemplatePrerequisiteState{}, fmt.Errorf(
			"read %s template security descriptor: %w",
			templateName,
			err,
		)
	}

	readAllowed, err := securityDescriptorAllowsCertificateTemplateRead(
		descriptor,
		allowSIDs,
		denySIDs,
	)
	if err != nil {
		return certificateTemplatePrerequisiteState{}, fmt.Errorf(
			"evaluate %s template Read authorization: %w",
			templateName,
			err,
		)
	}

	enrollAllowed, err := securityDescriptorAllowsCertificateEnrollment(
		descriptor,
		allowSIDs,
		denySIDs,
	)
	if err != nil {
		return certificateTemplatePrerequisiteState{}, fmt.Errorf(
			"evaluate %s template Enroll authorization: %w",
			templateName,
			err,
		)
	}

	return certificateTemplatePrerequisiteState{
		EnrollAllowed: enrollAllowed,
		OID:           strings.TrimSpace(oid),
		ReadAllowed:   readAllowed,
		TemplateName:  templateName,
	}, nil
}

func discoverEnterpriseCertificateAuthorities(
	session *ldapSession,
	configurationNamingContext string,
) ([]enterpriseCertificateAuthorityState, error) {
	if session == nil || session.handle == 0 {
		return nil, fmt.Errorf(
			"LDAP session is unavailable",
		)
	}

	base := fmt.Sprintf(
		"CN=Enrollment Services,CN=Public Key Services,CN=Services,%s",
		configurationNamingContext,
	)

	result, err := session.search(
		base,
		uint32(ldapScopeOneLevel),
		"(objectClass=pKIEnrollmentService)",
		[]string{
			"cn",
			"dNSHostName",
			"certificateTemplates",
		},
	)
	if result != 0 {
		defer ldapMsgFreeProc.Call(result)
	}
	if err != nil {
		return nil, err
	}

	entry, _, _ := ldapFirstEntryProc.Call(
		session.handle,
		result,
	)

	states := make(
		[]enterpriseCertificateAuthorityState,
		0,
	)

	for entry != 0 {
		commonName, err := session.getStringValue(
			entry,
			"cn",
		)
		if err != nil {
			return nil, fmt.Errorf(
				"read Enterprise CA common name: %w",
				err,
			)
		}

		dnsHostName, err := session.getStringValue(
			entry,
			"dNSHostName",
		)
		if err != nil {
			return nil, fmt.Errorf(
				"read Enterprise CA DNS host name for %s: %w",
				commonName,
				err,
			)
		}

		templates, err := session.getOptionalStringValues(
			entry,
			"certificateTemplates",
		)
		if err != nil {
			return nil, fmt.Errorf(
				"read Enterprise CA template publication for %s: %w",
				commonName,
				err,
			)
		}

		commonName = strings.TrimSpace(commonName)
		dnsHostName = strings.TrimSpace(dnsHostName)
		if commonName == "" || dnsHostName == "" {
			return nil, fmt.Errorf(
				"Enterprise CA discovery returned incomplete identity: cn=%q dns=%q",
				commonName,
				dnsHostName,
			)
		}

		states = append(
			states,
			enterpriseCertificateAuthorityState{
				CommonName:    commonName,
				Configuration: dnsHostName + `\` + commonName,
				DNSHostName:   dnsHostName,
				Templates:     append([]string(nil), templates...),
			},
		)

		next, _, _ := ldapNextEntryPrerequisiteProc.Call(
			session.handle,
			entry,
		)
		entry = next
	}

	if len(states) == 0 {
		return nil, fmt.Errorf(
			"no Enterprise CA enrollment-service objects were discovered",
		)
	}

	sort.Slice(
		states,
		func(left int, right int) bool {
			return strings.ToLower(states[left].Configuration) <
				strings.ToLower(states[right].Configuration)
		},
	)

	return states, nil
}

func enterpriseCAsPublishingAll(
	cas []enterpriseCertificateAuthorityState,
	templates []string,
) []enterpriseCertificateAuthorityState {
	result := make(
		[]enterpriseCertificateAuthorityState,
		0,
	)

	for _, ca := range cas {
		all := true
		for _, templateName := range templates {
			if !enterpriseCAPublishesTemplate(
				ca,
				templateName,
			) {
				all = false
				break
			}
		}
		if all {
			result = append(
				result,
				ca,
			)
		}
	}

	return result
}

func enterpriseCAsPublishingTemplate(
	cas []enterpriseCertificateAuthorityState,
	templateName string,
) []string {
	result := make(
		[]string,
		0,
	)
	for _, ca := range cas {
		if enterpriseCAPublishesTemplate(
			ca,
			templateName,
		) {
			result = append(
				result,
				ca.Configuration,
			)
		}
	}
	sort.Strings(result)
	return result
}

func enterpriseCAPublishesTemplate(
	ca enterpriseCertificateAuthorityState,
	templateName string,
) bool {
	for _, current := range ca.Templates {
		if strings.EqualFold(
			strings.TrimSpace(current),
			strings.TrimSpace(templateName),
		) {
			return true
		}
	}
	return false
}

func enterpriseCAConfigurations(
	cas []enterpriseCertificateAuthorityState,
) []string {
	result := make(
		[]string,
		0,
		len(cas),
	)
	for _, ca := range cas {
		result = append(
			result,
			ca.Configuration,
		)
	}
	sort.Strings(result)
	return result
}

func certificateAuthorityCurrentCallerRequestAccess(
	configuration string,
) (string, error) {
	configuration = strings.TrimSpace(configuration)
	if configuration == "" {
		return "", fmt.Errorf(
			"CA configuration string is required",
		)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	initializeResult, _, _ := coInitializeExPKIProc.Call(
		0,
		uintptr(coinitApartmentThreaded),
	)
	if certEnrollHRESULTFailed(
		initializeResult,
	) {
		return "", certEnrollHRESULTError(
			"CoInitializeEx",
			initializeResult,
		)
	}
	defer coUninitializePKIProc.Call()

	dispatch, err := certificateAuthorityRequestDispatch()
	if err != nil {
		return "", err
	}
	defer syscall.SyscallN(
		dispatch.VTable.Release,
		uintptr(
			unsafe.Pointer(
				dispatch,
			),
		),
	)

	configurationPointer, err := syscall.UTF16PtrFromString(
		configuration,
	)
	if err != nil {
		return "", fmt.Errorf(
			"encode CA configuration %q: %w",
			configuration,
			err,
		)
	}

	configurationBSTR, _, _ := sysAllocStringPKIProc.Call(
		uintptr(
			unsafe.Pointer(
				configurationPointer,
			),
		),
	)
	runtime.KeepAlive(configurationPointer)
	if configurationBSTR == 0 {
		return "", fmt.Errorf(
			"SysAllocString failed for CA configuration %q",
			configuration,
		)
	}
	defer sysFreeStringPKIProc.Call(
		configurationBSTR,
	)

	arguments := []certEnrollVariant{
		{
			Type:  variantI4,
			Value: 0,
		},
		{
			Type:  variantI4,
			Value: uintptr(caPropertyTypeString),
		},
		{
			Type:  variantI4,
			Value: 0,
		},
		{
			Type:  variantI4,
			Value: uintptr(caPropertyCAName),
		},
		{
			Type:  variantBSTR,
			Value: configurationBSTR,
		},
	}

	caName, err := certificateAuthorityRequestInvokeBSTR(
		dispatch,
		"GetCAProperty",
		arguments,
	)
	if err != nil {
		return "", fmt.Errorf(
			"ICertRequest2.GetCAProperty(CR_PROP_CANAME) on %s: %w; the request interface requires CA Request Certificates/Enroll authority, and CA Enroll implies CA Read",
			configuration,
			err,
		)
	}

	runtime.KeepAlive(arguments)

	caName = strings.TrimSpace(caName)
	if caName == "" {
		return "", fmt.Errorf(
			"ICertRequest2.GetCAProperty(CR_PROP_CANAME) on %s returned an empty CA name",
			configuration,
		)
	}

	separator := strings.LastIndex(
		configuration,
		`\`,
	)
	if separator >= 0 &&
		separator+1 < len(configuration) {
		expectedCAName := strings.TrimSpace(
			configuration[separator+1:],
		)
		if expectedCAName != "" &&
			!strings.EqualFold(
				caName,
				expectedCAName,
			) {
			return "", fmt.Errorf(
				"ICertRequest2.GetCAProperty(CR_PROP_CANAME) on %s returned CA name=%q; expected=%q",
				configuration,
				caName,
				expectedCAName,
			)
		}
	}

	return caName, nil
}

func certificateAuthorityRequestDispatch() (
	*certEnrollDispatch,
	error,
) {
	classID := certificateAuthorityRequestCLSID

	var dispatch *certEnrollDispatch

	result, _, _ := coCreateInstancePKIProc.Call(
		uintptr(
			unsafe.Pointer(
				&classID,
			),
		),
		0,
		uintptr(clsctxInprocServer),
		uintptr(
			unsafe.Pointer(
				&certEnrollIIDIDispatch,
			),
		),
		uintptr(
			unsafe.Pointer(
				&dispatch,
			),
		),
	)
	if certEnrollHRESULTFailed(result) {
		return nil, certEnrollHRESULTError(
			"CoCreateInstance(CLSID_CCertRequest)",
			result,
		)
	}
	if dispatch == nil || dispatch.VTable == nil {
		return nil, fmt.Errorf(
			"CLSID_CCertRequest returned no IDispatch interface",
		)
	}

	runtime.KeepAlive(classID)
	return dispatch, nil
}

func certificateAuthorityRequestInvokeBSTR(
	dispatch *certEnrollDispatch,
	name string,
	arguments []certEnrollVariant,
) (string, error) {
	dispatchID, err := certEnrollGetDispatchID(
		dispatch,
		name,
	)
	if err != nil {
		return "", err
	}

	parameters := certEnrollDispatchParams{
		ArgumentCount: uint32(
			len(arguments),
		),
	}
	if len(arguments) != 0 {
		parameters.Arguments = &arguments[0]
	}

	var (
		argumentError uint32
		exception     certEnrollExceptionInfo
		value         certEnrollVariant
	)

	result, _, _ := syscall.SyscallN(
		dispatch.VTable.Invoke,
		uintptr(
			unsafe.Pointer(
				dispatch,
			),
		),
		uintptr(
			uint32(dispatchID),
		),
		uintptr(
			unsafe.Pointer(
				&certEnrollIIDNull,
			),
		),
		uintptr(localeUserDefault),
		uintptr(dispatchMethod),
		uintptr(
			unsafe.Pointer(
				&parameters,
			),
		),
		uintptr(
			unsafe.Pointer(
				&value,
			),
		),
		uintptr(
			unsafe.Pointer(
				&exception,
			),
		),
		uintptr(
			unsafe.Pointer(
				&argumentError,
			),
		),
	)

	runtime.KeepAlive(arguments)

	if certEnrollHRESULTFailed(result) {
		source := certEnrollBSTRString(
			exception.Source,
		)
		description := certEnrollBSTRString(
			exception.Description,
		)
		scode := exception.SCode
		certEnrollFreeExceptionInfo(
			&exception,
		)

		return "", fmt.Errorf(
			"IDispatch.Invoke(%s): HRESULT=0x%08X exception_scode=0x%08X source=%q description=%q argument_index=%d",
			name,
			uint32(result),
			uint32(scode),
			source,
			description,
			argumentError,
		)
	}

	if value.Type != variantBSTR {
		return "", fmt.Errorf(
			"IDispatch.Invoke(%s) returned VARIANT type=%d; expected BSTR",
			name,
			value.Type,
		)
	}
	if value.Value == 0 {
		return "", fmt.Errorf(
			"IDispatch.Invoke(%s) returned a nil BSTR",
			name,
		)
	}

	bstr := (*uint16)(
		unsafe.Pointer(
			value.Value,
		),
	)
	resultValue := certEnrollBSTRString(
		bstr,
	)
	sysFreeStringPKIProc.Call(
		value.Value,
	)

	return resultValue, nil
}

func currentInstallerTokenPrerequisiteState() (
	installerTokenPrerequisiteState,
	error,
) {
	token := windows.GetCurrentProcessToken()

	user, err := token.GetTokenUser()
	if err != nil {
		return installerTokenPrerequisiteState{}, fmt.Errorf(
			"read current token user: %w",
			err,
		)
	}
	if user.User.Sid == nil {
		return installerTokenPrerequisiteState{}, fmt.Errorf(
			"current token user SID is unavailable",
		)
	}

	account, domain, _, err := user.User.Sid.LookupAccount(
		"",
	)
	if err != nil {
		return installerTokenPrerequisiteState{}, fmt.Errorf(
			"resolve current token user SID %s: %w",
			user.User.Sid.String(),
			err,
		)
	}

	account = strings.TrimSpace(account)
	domain = strings.TrimSpace(domain)
	if domain != "" {
		account = domain + `\` + account
	}
	if account == "" {
		return installerTokenPrerequisiteState{}, fmt.Errorf(
			"current token user account name is unavailable",
		)
	}

	groups, err := token.GetTokenGroups()
	if err != nil {
		return installerTokenPrerequisiteState{}, fmt.Errorf(
			"read current token groups: %w",
			err,
		)
	}

	allow := make(map[string]struct{})
	deny := make(map[string]struct{})

	userSID := strings.ToUpper(
		user.User.Sid.String(),
	)
	allow[userSID] = struct{}{}
	deny[userSID] = struct{}{}

	state := installerTokenPrerequisiteState{
		Account:   account,
		AllowSIDs: allow,
		DenySIDs:  deny,
		SID:       userSID,
	}

	for _, group := range groups.AllGroups() {
		if group.Sid == nil {
			continue
		}

		sid := strings.ToUpper(
			group.Sid.String(),
		)

		if group.Attributes&seGroupUseForDenyOnly != 0 {
			state.DenyOnlyGroupCount++
			deny[sid] = struct{}{}
			continue
		}
		if group.Attributes&seGroupEnabled == 0 {
			continue
		}

		state.EnabledGroupCount++
		allow[sid] = struct{}{}
		deny[sid] = struct{}{}
	}

	return state, nil
}

func currentTokenHasCertificateEnrollRight(
	descriptor []byte,
) (bool, error) {
	allowSIDs, denySIDs, err := currentTokenSIDMembership()
	if err != nil {
		return false, err
	}

	return securityDescriptorAllowsCertificateEnrollment(
		descriptor,
		allowSIDs,
		denySIDs,
	)
}

func currentTokenSIDMembership() (
	map[string]struct{},
	map[string]struct{},
	error,
) {
	state, err := currentInstallerTokenPrerequisiteState()
	if err != nil {
		return nil, nil, err
	}
	return state.AllowSIDs, state.DenySIDs, nil
}

func securityDescriptorAllowsCertificateTemplateRead(
	descriptor []byte,
	allowSIDs map[string]struct{},
	denySIDs map[string]struct{},
) (bool, error) {
	if len(descriptor) < 20 {
		return false, fmt.Errorf(
			"security descriptor is too short: %d bytes",
			len(descriptor),
		)
	}

	daclOffset := int(
		binary.LittleEndian.Uint32(
			descriptor[16:20],
		),
	)
	if daclOffset == 0 {
		return false, fmt.Errorf(
			"certificate template has no DACL",
		)
	}
	if daclOffset < 0 || daclOffset+8 > len(descriptor) {
		return false, fmt.Errorf(
			"certificate template DACL offset=%d is outside descriptor bytes=%d",
			daclOffset,
			len(descriptor),
		)
	}

	aclSize := int(
		binary.LittleEndian.Uint16(
			descriptor[daclOffset+2 : daclOffset+4],
		),
	)
	aceCount := int(
		binary.LittleEndian.Uint16(
			descriptor[daclOffset+4 : daclOffset+6],
		),
	)
	if aclSize < 8 || daclOffset+aclSize > len(descriptor) {
		return false, fmt.Errorf(
			"certificate template DACL size=%d is invalid",
			aclSize,
		)
	}

	offset := daclOffset + 8
	allowedMask := uint32(0)
	deniedMask := uint32(0)

	for index := 0; index < aceCount; index++ {
		if offset+4 > daclOffset+aclSize {
			return false, fmt.Errorf(
				"ACE %d header exceeds DACL boundary",
				index,
			)
		}

		aceType := descriptor[offset]
		aceSize := int(
			binary.LittleEndian.Uint16(
				descriptor[offset+2 : offset+4],
			),
		)
		if aceSize < 8 || offset+aceSize > daclOffset+aclSize {
			return false, fmt.Errorf(
				"ACE %d size=%d is invalid",
				index,
				aceSize,
			)
		}

		applies, sid, mask, err := certificateTemplateReadACE(
			descriptor[offset : offset+aceSize],
		)
		if err != nil {
			return false, fmt.Errorf(
				"parse ACE %d: %w",
				index,
				err,
			)
		}

		if applies {
			relevant := mask & certificateTemplateGenericReadMask
			switch aceType {
			case accessDeniedACE,
				accessDeniedObjectACE:
				if _, found := denySIDs[sid]; found {
					deniedMask |= relevant
				}
			case accessAllowedACE,
				accessAllowedObjectACE:
				if _, found := allowSIDs[sid]; found {
					allowedMask |= relevant
				}
			}
		}

		offset += aceSize
	}

	if deniedMask != 0 {
		return false, nil
	}

	return allowedMask&certificateTemplateGenericReadMask ==
		certificateTemplateGenericReadMask, nil
}

func securityDescriptorAllowsCertificateEnrollment(
	descriptor []byte,
	allowSIDs map[string]struct{},
	denySIDs map[string]struct{},
) (bool, error) {
	if len(descriptor) < 20 {
		return false, fmt.Errorf(
			"security descriptor is too short: %d bytes",
			len(descriptor),
		)
	}

	daclOffset := int(
		binary.LittleEndian.Uint32(
			descriptor[16:20],
		),
	)
	if daclOffset == 0 {
		return false, fmt.Errorf(
			"certificate template has no DACL",
		)
	}
	if daclOffset < 0 || daclOffset+8 > len(descriptor) {
		return false, fmt.Errorf(
			"certificate template DACL offset=%d is outside descriptor bytes=%d",
			daclOffset,
			len(descriptor),
		)
	}

	aclSize := int(
		binary.LittleEndian.Uint16(
			descriptor[daclOffset+2 : daclOffset+4],
		),
	)
	aceCount := int(
		binary.LittleEndian.Uint16(
			descriptor[daclOffset+4 : daclOffset+6],
		),
	)
	if aclSize < 8 || daclOffset+aclSize > len(descriptor) {
		return false, fmt.Errorf(
			"certificate template DACL size=%d is invalid",
			aclSize,
		)
	}

	offset := daclOffset + 8
	allowed := false

	for index := 0; index < aceCount; index++ {
		if offset+4 > daclOffset+aclSize {
			return false, fmt.Errorf(
				"ACE %d header exceeds DACL boundary",
				index,
			)
		}

		aceType := descriptor[offset]
		aceSize := int(
			binary.LittleEndian.Uint16(
				descriptor[offset+2 : offset+4],
			),
		)
		if aceSize < 8 || offset+aceSize > daclOffset+aclSize {
			return false, fmt.Errorf(
				"ACE %d size=%d is invalid",
				index,
				aceSize,
			)
		}

		applies, sid, mask, err := certificateEnrollACE(
			descriptor[offset : offset+aceSize],
		)
		if err != nil {
			return false, fmt.Errorf(
				"parse ACE %d: %w",
				index,
				err,
			)
		}

		if applies && mask&adsRightDSControlAccess != 0 {
			switch aceType {
			case accessDeniedACE,
				accessDeniedObjectACE:
				if _, found := denySIDs[sid]; found {
					return false, nil
				}

			case accessAllowedACE,
				accessAllowedObjectACE:
				if _, found := allowSIDs[sid]; found {
					allowed = true
				}
			}
		}

		offset += aceSize
	}

	return allowed, nil
}

func certificateTemplateReadACE(
	ace []byte,
) (
	applies bool,
	sid string,
	mask uint32,
	err error,
) {
	if len(ace) < 8 {
		return false, "", 0, fmt.Errorf(
			"ACE is too short: %d bytes",
			len(ace),
		)
	}

	aceType := ace[0]
	mask = binary.LittleEndian.Uint32(
		ace[4:8],
	)

	sidOffset := 8
	applies = true

	switch aceType {
	case accessAllowedACE,
		accessDeniedACE:

	case accessAllowedObjectACE,
		accessDeniedObjectACE:
		if len(ace) < 12 {
			return false, "", 0, fmt.Errorf(
				"object ACE is too short: %d bytes",
				len(ace),
			)
		}

		flags := binary.LittleEndian.Uint32(
			ace[8:12],
		)
		sidOffset = 12

		// A template-level Read grant must cover the object generally. If the
		// ObjectType field is present, READ_PROP is scoped to a particular
		// property/property-set and is not sufficient for generic template Read.
		if flags&aceObjectTypePresent != 0 {
			applies = false
			sidOffset += 16
		}
		if flags&aceInheritedObjectTypePresent != 0 {
			sidOffset += 16
		}

	default:
		return false, "", mask, nil
	}

	if sidOffset >= len(ace) {
		return false, "", 0, fmt.Errorf(
			"ACE SID offset=%d exceeds ACE bytes=%d",
			sidOffset,
			len(ace),
		)
	}

	sid, err = sidStringFromACEBytes(
		ace[sidOffset:],
	)
	if err != nil {
		return false, "", 0, err
	}

	return applies, strings.ToUpper(sid), mask, nil
}

func certificateEnrollACE(
	ace []byte,
) (
	applies bool,
	sid string,
	mask uint32,
	err error,
) {
	if len(ace) < 8 {
		return false, "", 0, fmt.Errorf(
			"ACE is too short: %d bytes",
			len(ace),
		)
	}

	aceType := ace[0]
	mask = binary.LittleEndian.Uint32(
		ace[4:8],
	)

	sidOffset := 8
	applies = true

	switch aceType {
	case accessAllowedACE,
		accessDeniedACE:

	case accessAllowedObjectACE,
		accessDeniedObjectACE:
		if len(ace) < 12 {
			return false, "", 0, fmt.Errorf(
				"object ACE is too short: %d bytes",
				len(ace),
			)
		}

		flags := binary.LittleEndian.Uint32(
			ace[8:12],
		)
		sidOffset = 12

		if flags&aceObjectTypePresent != 0 {
			if sidOffset+16 > len(ace) {
				return false, "", 0, fmt.Errorf(
					"object ACE ObjectType exceeds ACE boundary",
				)
			}

			applies = equalGUIDBytes(
				ace[sidOffset:sidOffset+16],
				certificateEnrollmentExtendedRightGUID[:],
			)
			sidOffset += 16
		}

		if flags&aceInheritedObjectTypePresent != 0 {
			sidOffset += 16
		}

	default:
		return false, "", mask, nil
	}

	if sidOffset >= len(ace) {
		return false, "", 0, fmt.Errorf(
			"ACE SID offset=%d exceeds ACE bytes=%d",
			sidOffset,
			len(ace),
		)
	}

	sid, err = sidStringFromACEBytes(
		ace[sidOffset:],
	)
	if err != nil {
		return false, "", 0, err
	}

	return applies, strings.ToUpper(sid), mask, nil
}

func equalGUIDBytes(
	left []byte,
	right []byte,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sidStringFromACEBytes(
	value []byte,
) (string, error) {
	if len(value) < 8 {
		return "", fmt.Errorf(
			"SID is too short: %d bytes",
			len(value),
		)
	}

	revision := value[0]
	subAuthorityCount := int(value[1])
	required := 8 + subAuthorityCount*4
	if required > len(value) {
		return "", fmt.Errorf(
			"SID requires %d bytes, ACE provides %d",
			required,
			len(value),
		)
	}

	identifierAuthority := uint64(0)
	for _, current := range value[2:8] {
		identifierAuthority = identifierAuthority<<8 |
			uint64(current)
	}

	builder := strings.Builder{}
	fmt.Fprintf(
		&builder,
		"S-%d-%d",
		revision,
		identifierAuthority,
	)

	offset := 8
	for index := 0; index < subAuthorityCount; index++ {
		fmt.Fprintf(
			&builder,
			"-%d",
			binary.LittleEndian.Uint32(
				value[offset:offset+4],
			),
		)
		offset += 4
	}

	return builder.String(), nil
}
