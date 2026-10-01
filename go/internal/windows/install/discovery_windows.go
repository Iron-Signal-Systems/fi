// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	checkFail = "FAIL"
	checkInfo = "INFO"
	checkPass = "PASS"
	checkWarn = "WARN"

	notKnown = "not_known"

	presenceAbsent  = "absent"
	presencePresent = "present"
	presenceUnknown = "unknown"
)

type BinaryState struct {
	Name     string
	Path     string
	Presence string
	SHA256   string
}

type AccountRightsState struct {
	Account string
	Role    string
	Rights  []string
}

type Check struct {
	Detail string
	Name   string
	Status string
}

type ConfigState struct {
	GovernedRoots   []string
	Presence        string
	Path            string
	ReceiverAddress string
	ReceiverName    string
	SourceID        string
	SpoolDir        string
	StageDir        string
	StateDir        string
	VersionID       string
}

type HostState struct {
	BuildNumber uint32
	Computer    string
	DomainDNS   string
	Elevated    bool
	ProductName string
	Profile     WindowsProfile
}

type Report struct {
	ACLs          []ACLState
	AD            ActiveDirectoryState
	AccountRights []AccountRightsState
	GMSAs         []GMSAState
	Binaries      []BinaryState
	Checks        []Check
	Config        ConfigState
	Host          HostState
	Join          DomainJoinState
	PKI           []TrustObjectState
	Package       PackageState
	ReleaseTrust  ReleaseTrustState
	Services      []ServiceState
	Trust         TransportTrustState
}

type ServiceState struct {
	Account        string
	BinaryPath     string
	DisplayName    string
	ManagedAccount string
	Name           string
	Presence       string
	ProcessID      uint32
	SIDType        string
	StartType      string
	State          string
}

type TransportTrustState struct {
	BatchSigningCertificateSHA256 string
	Presence                      string
	Path                          string
	RootCertificateSHA256         string
	TransportCertificateSHA256    string
	TransportCRLPath              string
	TransportIssuerSHA256         string
	VersionID                     string
}

type TrustObjectState struct {
	Detail string
	Name   string
	State  string
}

type serviceContract struct {
	DisplayName string
	Name        string
	Path        string
	SIDType     uint32
}

type localGroupMembersInfo3 struct {
	DomainAndName *uint16
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

var (
	advapi32DLL = syscall.NewLazyDLL("advapi32.dll")
	kernel32DLL = syscall.NewLazyDLL("kernel32.dll")
	netapi32DLL = syscall.NewLazyDLL("netapi32.dll")

	lookupAccountNameProc         = advapi32DLL.NewProc("LookupAccountNameW")
	lsaCloseProc                  = advapi32DLL.NewProc("LsaClose")
	lsaEnumerateAccountRightsProc = advapi32DLL.NewProc("LsaEnumerateAccountRights")
	lsaFreeMemoryProc             = advapi32DLL.NewProc("LsaFreeMemory")
	lsaNtStatusToWinErrorProc     = advapi32DLL.NewProc("LsaNtStatusToWinError")
	lsaOpenPolicyProc             = advapi32DLL.NewProc("LsaOpenPolicy")
	netApiBufferFreeProc          = netapi32DLL.NewProc("NetApiBufferFree")
	netLocalGroupGetMembersProc   = netapi32DLL.NewProc("NetLocalGroupGetMembers")
	waitNamedPipeProc             = kernel32DLL.NewProc("WaitNamedPipeW")
)

const (
	errorFileNotFound        = syscall.Errno(2)
	errorPathNotFound        = syscall.Errno(3)
	errorInsufficientBuffer  = syscall.Errno(122)
	errorMoreData            = syscall.Errno(234)
	errorSemTimeout          = syscall.Errno(121)
	maxPreferredSize         = uint32(0xffffffff)
	policyLookupNames        = uint32(0x00000800)
	statusObjectNameNotFound = uint32(0xC0000034)
)

func (report *Report) addCheck(status string, name string, detail string) {
	report.Checks = append(report.Checks, Check{
		Detail: detail,
		Name:   name,
		Status: status,
	})
}

func discoverBinary(name string, path string) (BinaryState, error) {
	state := BinaryState{
		Name:     name,
		Path:     path,
		Presence: presenceUnknown,
		SHA256:   notKnown,
	}

	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			state.Presence = presenceAbsent
			return state, nil
		}
		return state, fmt.Errorf(
			"inspect %s: %w",
			path,
			err,
		)
	}
	if !info.Mode().IsRegular() {
		return state, fmt.Errorf(
			"%s exists but is not a regular file",
			path,
		)
	}

	digest, err := fileSHA256(path)
	if err != nil {
		return state, err
	}

	state.Presence = presencePresent
	state.SHA256 = digest
	return state, nil
}

func discoverBinaries(report *Report) {
	contracts := []struct {
		name string
		path string
	}{
		{name: "FICollector", path: `C:\Program Files\FI\fi.exe`},
		{name: "FIUSNReader", path: `C:\Program Files\FI\fi-usn.exe`},
		{name: "FIObjReader", path: `C:\Program Files\FI\fi-obj.exe`},
		{name: "FISender", path: `C:\Program Files\FI\fi-sender.exe`},
	}

	for _, contract := range contracts {
		state, err := discoverBinary(contract.name, contract.path)
		report.Binaries = append(report.Binaries, state)
		if err != nil {
			report.addCheck(
				checkFail,
				contract.name+" binary",
				err.Error(),
			)
			continue
		}

		switch state.Presence {
		case presenceAbsent:
			report.addCheck(
				checkInfo,
				contract.name+" binary",
				contract.path+" is not present",
			)
		case presencePresent:
			report.addCheck(
				checkPass,
				contract.name+" binary",
				fmt.Sprintf("%s SHA256=%s", state.Path, state.SHA256),
			)
		default:
			report.addCheck(
				checkFail,
				contract.name+" binary",
				"binary presence is unknown",
			)
		}
	}
}

func discoverConfig(report *Report) {
	value, path, err := config.LoadDefault()
	report.Config.Path = path
	report.Config.Presence = presenceUnknown
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			report.Config.Presence = presenceAbsent
			report.addCheck(
				checkInfo,
				"FI operational configuration",
				path+" is not present",
			)
			return
		}
		report.addCheck(
			checkFail,
			"FI operational configuration",
			err.Error(),
		)
		return
	}

	report.Config = ConfigState{
		GovernedRoots:   append([]string(nil), value.GovernedRoots...),
		Path:            path,
		Presence:        presencePresent,
		ReceiverAddress: value.Receiver.Address,
		ReceiverName:    value.Receiver.Name,
		SourceID:        value.Source.ID,
		SpoolDir:        value.Storage.SpoolDir,
		StageDir:        value.Storage.StageDir,
		StateDir:        value.Storage.StateDir,
		VersionID:       value.VersionID,
	}

	report.addCheck(
		checkPass,
		"FI operational configuration",
		fmt.Sprintf("%s version=%s", path, value.VersionID),
	)

	for _, root := range value.GovernedRoots {
		discoverPath(report, "governed root", root)
	}
	discoverPath(report, "spool directory", value.Storage.SpoolDir)
	discoverPath(report, "stage directory", value.Storage.StageDir)
	discoverPath(report, "state directory", value.Storage.StateDir)
}

func discoverHost(report *Report) {
	computer, err := os.Hostname()
	if err != nil {
		computer = notKnown
		report.addCheck(
			checkFail,
			"computer name",
			err.Error(),
		)
	}

	buildNumber, productName, err := readWindowsVersion()
	if err != nil {
		report.addCheck(
			checkFail,
			"Windows version",
			err.Error(),
		)
	}

	profile, supported := ProfileForBuild(buildNumber)
	domain := readDomainDNS()

	report.Host = HostState{
		BuildNumber: buildNumber,
		Computer:    computer,
		DomainDNS:   domain,
		Elevated:    windows.GetCurrentProcessToken().IsElevated(),
		ProductName: valueOrNotKnown(productName),
		Profile:     profile,
	}

	if report.Host.Elevated {
		report.addCheck(
			checkPass,
			"administrator session",
			"process token is elevated",
		)
	} else {
		report.addCheck(
			checkFail,
			"administrator session",
			"fi-install must run from an elevated administrator session",
		)
	}

	if supported {
		report.addCheck(
			checkPass,
			"Windows profile",
			fmt.Sprintf(
				"%s exact build %d",
				profile.Name,
				profile.BuildNumber,
			),
		)
	} else {
		report.addCheck(
			checkFail,
			"Windows profile",
			fmt.Sprintf(
				"build %d has no accepted FI installer profile",
				buildNumber,
			),
		)
	}
}

func discoverPath(report *Report, name string, path string) {
	if strings.TrimSpace(path) == "" {
		report.addCheck(
			checkFail,
			name,
			"path is empty",
		)
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		report.addCheck(
			checkFail,
			name,
			fmt.Sprintf("%s: %v", path, err),
		)
		return
	}
	if !info.IsDir() {
		report.addCheck(
			checkFail,
			name,
			fmt.Sprintf("%s is not a directory", path),
		)
		return
	}

	report.addCheck(
		checkPass,
		name,
		path,
	)
}

func discoverPKI(report *Report, trust config.TransportTrustConfig) {
	checkCertificate := func(
		name string,
		store string,
		fingerprint string,
	) {
		_, err := certstore.LoadLocalMachineCertificate(
			store,
			fingerprint,
		)
		if err != nil {
			report.PKI = append(report.PKI, TrustObjectState{
				Detail: err.Error(),
				Name:   name,
				State:  checkFail,
			})
			report.addCheck(checkFail, name, err.Error())
			return
		}

		detail := fmt.Sprintf(
			"LocalMachine\\%s SHA256=%s",
			store,
			fingerprint,
		)
		report.PKI = append(report.PKI, TrustObjectState{
			Detail: detail,
			Name:   name,
			State:  checkPass,
		})
		report.addCheck(checkPass, name, detail)
	}

	checkSigningIdentity := func(
		name string,
		fingerprint string,
	) {
		identity, err := certstore.LoadLocalMachineSigningIdentity(
			fingerprint,
		)
		if err != nil {
			report.PKI = append(report.PKI, TrustObjectState{
				Detail: err.Error(),
				Name:   name,
				State:  checkFail,
			})
			report.addCheck(checkFail, name, err.Error())
			return
		}
		defer identity.Close()

		detail := fmt.Sprintf(
			"LocalMachine\\MY SHA256=%s private-key=available",
			fingerprint,
		)
		report.PKI = append(report.PKI, TrustObjectState{
			Detail: detail,
			Name:   name,
			State:  checkPass,
		})
		report.addCheck(checkPass, name, detail)
	}

	checkCertificate(
		"transport root certificate",
		certstore.StoreRoot,
		trust.RootCertificateSHA256,
	)
	_, issuerStore, err := loadLocalMachineTransportIssuer(
		trust.TransportIssuerSHA256,
		trust.RootCertificateSHA256,
	)
	if err != nil {
		report.PKI = append(
			report.PKI,
			TrustObjectState{
				Detail: err.Error(),
				Name:   "transport issuer certificate",
				State:  checkFail,
			},
		)
		report.addCheck(
			checkFail,
			"transport issuer certificate",
			err.Error(),
		)
	} else {
		detail := fmt.Sprintf(
			"LocalMachine\\%s SHA256=%s",
			issuerStore,
			trust.TransportIssuerSHA256,
		)
		report.PKI = append(
			report.PKI,
			TrustObjectState{
				Detail: detail,
				Name:   "transport issuer certificate",
				State:  checkPass,
			},
		)
		report.addCheck(
			checkPass,
			"transport issuer certificate",
			detail,
		)
	}
	checkSigningIdentity(
		"source transport signing identity",
		trust.TransportCertificateSHA256,
	)
	checkSigningIdentity(
		"batch signing identity",
		trust.BatchSigningCertificateSHA256,
	)

	info, err := os.Stat(trust.TransportCRLPath)
	if err != nil {
		report.PKI = append(report.PKI, TrustObjectState{
			Detail: err.Error(),
			Name:   "transport CRL",
			State:  checkFail,
		})
		report.addCheck(
			checkFail,
			"transport CRL",
			err.Error(),
		)
		return
	}
	if info.IsDir() {
		detail := fmt.Sprintf(
			"%s is a directory",
			trust.TransportCRLPath,
		)
		report.PKI = append(report.PKI, TrustObjectState{
			Detail: detail,
			Name:   "transport CRL",
			State:  checkFail,
		})
		report.addCheck(
			checkFail,
			"transport CRL",
			detail,
		)
		return
	}

	report.PKI = append(report.PKI, TrustObjectState{
		Detail: trust.TransportCRLPath,
		Name:   "transport CRL",
		State:  checkPass,
	})
	report.addCheck(
		checkPass,
		"transport CRL",
		trust.TransportCRLPath,
	)
}

func accountIsDirectLocalGroupMember(group string, account string) (bool, error) {
	groupName, err := syscall.UTF16PtrFromString(group)
	if err != nil {
		return false, fmt.Errorf("encode local group %q name: %w", group, err)
	}

	var resume uintptr

	for {
		var buffer uintptr
		var entriesRead uint32
		var totalEntries uint32

		status, _, _ := netLocalGroupGetMembersProc.Call(
			0,
			uintptr(unsafe.Pointer(groupName)),
			3,
			uintptr(unsafe.Pointer(&buffer)),
			uintptr(maxPreferredSize),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resume)),
		)

		if buffer != 0 {
			entrySize := unsafe.Sizeof(localGroupMembersInfo3{})
			for index := uint32(0); index < entriesRead; index++ {
				entry := (*localGroupMembersInfo3)(
					unsafe.Pointer(buffer + uintptr(index)*entrySize),
				)
				member := windows.UTF16PtrToString(entry.DomainAndName)
				if strings.EqualFold(member, account) {
					_, _, _ = netApiBufferFreeProc.Call(buffer)
					return true, nil
				}
			}
			_, _, _ = netApiBufferFreeProc.Call(buffer)
		}

		switch syscall.Errno(status) {
		case 0:
			return false, nil
		case errorMoreData:
			continue
		default:
			return false, fmt.Errorf(
				"enumerate local group %q members: status=%d",
				group,
				status,
			)
		}
	}
}

func discoverIdentityBoundary(
	report *Report,
	states map[string]ServiceState,
) {
	collector := states["FICollector"].Account
	usnReader := states["FIUSNReader"].Account
	objReader := states["FIObjReader"].Account

	checks := []struct {
		account string
		group   string
		name    string
		want    bool
	}{
		{
			account: collector,
			group:   "Administrators",
			name:    "FICollector direct local Administrator membership",
			want:    false,
		},
		{
			account: collector,
			group:   "Event Log Readers",
			name:    "FICollector/FISender direct Event Log Readers membership",
			want:    true,
		},
		{
			account: usnReader,
			group:   "Administrators",
			name:    "FIUSNReader direct local Administrator membership",
			want:    true,
		},
		{
			account: objReader,
			group:   "Administrators",
			name:    "FIObjReader direct local Administrator membership",
			want:    false,
		},
	}

	for _, check := range checks {
		if strings.TrimSpace(check.account) == "" {
			report.addCheck(
				checkFail,
				check.name,
				"service account is unavailable",
			)
			continue
		}

		member, err := accountIsDirectLocalGroupMember(check.group, check.account)
		if err != nil {
			report.addCheck(
				checkFail,
				check.name,
				err.Error(),
			)
			continue
		}

		if member != check.want {
			report.addCheck(
				checkFail,
				check.name,
				fmt.Sprintf(
					"account=%s direct_member=%t expected=%t",
					check.account,
					member,
					check.want,
				),
			)
			continue
		}

		report.addCheck(
			checkPass,
			check.name,
			fmt.Sprintf(
				"account=%s direct_member=%t",
				check.account,
				member,
			),
		)
	}

	if strings.TrimSpace(objReader) != "" {
		member, err := accountIsDirectLocalGroupMember(
			"Backup Operators",
			objReader,
		)
		if err != nil {
			report.addCheck(
				checkFail,
				"FIObjReader direct Backup Operators membership",
				err.Error(),
			)
		} else if member {
			report.addCheck(
				checkFail,
				"FIObjReader direct Backup Operators membership",
				fmt.Sprintf(
					"account=%s direct_member=true expected=false",
					objReader,
				),
			)
		} else {
			report.addCheck(
				checkPass,
				"FIObjReader direct Backup Operators membership",
				fmt.Sprintf(
					"account=%s direct_member=false",
					objReader,
				),
			)
		}
	}
}

func lookupAccountSID(account string) (*windows.SID, []byte, error) {
	accountName, err := syscall.UTF16PtrFromString(account)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"encode account name %q: %w",
			account,
			err,
		)
	}

	var sidBytes uint32
	var domainChars uint32
	var use uint32

	result, _, callErr := lookupAccountNameProc.Call(
		0,
		uintptr(unsafe.Pointer(accountName)),
		0,
		uintptr(unsafe.Pointer(&sidBytes)),
		0,
		uintptr(unsafe.Pointer(&domainChars)),
		uintptr(unsafe.Pointer(&use)),
	)
	if result != 0 {
		return nil, nil, fmt.Errorf(
			"size SID for account %q unexpectedly succeeded",
			account,
		)
	}
	if callErr != errorInsufficientBuffer {
		return nil, nil, fmt.Errorf(
			"size SID for account %q: %w",
			account,
			callErr,
		)
	}
	if sidBytes == 0 {
		return nil, nil, fmt.Errorf(
			"size SID for account %q returned zero bytes",
			account,
		)
	}

	sidBuffer := make([]byte, sidBytes)
	domainBuffer := make([]uint16, domainChars)

	var domainPointer uintptr
	if len(domainBuffer) != 0 {
		domainPointer = uintptr(
			unsafe.Pointer(&domainBuffer[0]),
		)
	}

	result, _, callErr = lookupAccountNameProc.Call(
		0,
		uintptr(unsafe.Pointer(accountName)),
		uintptr(unsafe.Pointer(&sidBuffer[0])),
		uintptr(unsafe.Pointer(&sidBytes)),
		domainPointer,
		uintptr(unsafe.Pointer(&domainChars)),
		uintptr(unsafe.Pointer(&use)),
	)
	if result == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return nil, nil, fmt.Errorf(
				"resolve SID for account %q: %w",
				account,
				callErr,
			)
		}
		return nil, nil, fmt.Errorf(
			"resolve SID for account %q failed",
			account,
		)
	}

	return (*windows.SID)(unsafe.Pointer(&sidBuffer[0])), sidBuffer, nil
}

func lsaStatusError(operation string, status uintptr) error {
	if uint32(status) == 0 {
		return nil
	}

	winError, _, _ := lsaNtStatusToWinErrorProc.Call(status)
	if winError == 0 {
		return fmt.Errorf(
			"%s: NTSTATUS=0x%08x",
			operation,
			uint32(status),
		)
	}

	return fmt.Errorf(
		"%s: NTSTATUS=0x%08x Win32=%d",
		operation,
		uint32(status),
		uint32(winError),
	)
}

func enumerateDirectAccountRights(account string) ([]string, error) {
	sid, sidBuffer, err := lookupAccountSID(account)
	if err != nil {
		return nil, err
	}
	// Keep the backing storage alive through the LSA call.
	_ = sidBuffer

	attributes := lsaObjectAttributes{
		Length: uint32(unsafe.Sizeof(lsaObjectAttributes{})),
	}

	var policyHandle uintptr

	status, _, _ := lsaOpenPolicyProc.Call(
		0,
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(policyLookupNames),
		uintptr(unsafe.Pointer(&policyHandle)),
	)
	if status != 0 {
		return nil, lsaStatusError("open local security policy", status)
	}
	defer lsaCloseProc.Call(policyHandle)

	var rightsPointer uintptr
	var rightsCount uint32

	status, _, _ = lsaEnumerateAccountRightsProc.Call(
		policyHandle,
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&rightsPointer)),
		uintptr(unsafe.Pointer(&rightsCount)),
	)

	if uint32(status) == statusObjectNameNotFound {
		return []string{}, nil
	}
	if status != 0 {
		return nil, lsaStatusError(
			"enumerate direct account rights for "+account,
			status,
		)
	}
	if rightsPointer == 0 || rightsCount == 0 {
		return []string{}, nil
	}
	defer lsaFreeMemoryProc.Call(rightsPointer)

	values := unsafe.Slice(
		(*lsaUnicodeString)(unsafe.Pointer(rightsPointer)),
		int(rightsCount),
	)

	rights := make([]string, 0, rightsCount)
	for _, value := range values {
		if value.Buffer == nil || value.Length == 0 {
			continue
		}
		characters := unsafe.Slice(
			value.Buffer,
			int(value.Length/2),
		)
		right := windows.UTF16ToString(characters)
		if strings.TrimSpace(right) != "" {
			rights = append(rights, right)
		}
	}

	sort.Strings(rights)
	return rights, nil
}

func containsRight(rights []string, right string) bool {
	for _, current := range rights {
		if current == right {
			return true
		}
	}
	return false
}

func discoverAccountRights(
	report *Report,
	states map[string]ServiceState,
) {
	roles := []struct {
		account string
		role    string
	}{
		{
			account: states["FICollector"].Account,
			role:    "FICollector/FISender",
		},
		{
			account: states["FIUSNReader"].Account,
			role:    "FIUSNReader",
		},
		{
			account: states["FIObjReader"].Account,
			role:    "FIObjReader",
		},
	}

	seen := make(map[string]struct{})
	rightsByRole := make(map[string][]string)

	for _, item := range roles {
		account := strings.TrimSpace(item.account)
		if account == "" {
			report.addCheck(
				checkFail,
				item.role+" direct account rights",
				"service account is unavailable",
			)
			continue
		}

		key := strings.ToLower(account)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		rights, err := enumerateDirectAccountRights(account)
		if err != nil {
			report.addCheck(
				checkFail,
				item.role+" direct account rights",
				err.Error(),
			)
			continue
		}

		report.AccountRights = append(
			report.AccountRights,
			AccountRightsState{
				Account: account,
				Role:    item.role,
				Rights:  append([]string(nil), rights...),
			},
		)
		rightsByRole[item.role] = rights

		detail := "none"
		if len(rights) != 0 {
			detail = strings.Join(rights, ", ")
		}

		report.addCheck(
			checkInfo,
			item.role+" direct account rights",
			fmt.Sprintf(
				"account=%s rights=%s",
				account,
				detail,
			),
		)
	}

	collectorRights, collectorOK := rightsByRole["FICollector/FISender"]
	if collectorOK {
		if !containsRight(collectorRights, "SeServiceLogonRight") {
			report.addCheck(
				checkFail,
				"FICollector/FISender service-logon right",
				"SeServiceLogonRight is missing",
			)
		} else {
			report.addCheck(
				checkPass,
				"FICollector/FISender service-logon right",
				"SeServiceLogonRight is present",
			)
		}

		if containsRight(collectorRights, "SeManageVolumePrivilege") {
			report.addCheck(
				checkWarn,
				"FICollector/FISender unnecessary direct right",
				"SeManageVolumePrivilege is assigned directly; current FI design keeps raw-volume USN work in FIUSNReader and does not require this collector/sender right",
			)
		}
	}

	usnRights, usnOK := rightsByRole["FIUSNReader"]
	if usnOK {
		if !containsRight(usnRights, "SeServiceLogonRight") {
			report.addCheck(
				checkFail,
				"FIUSNReader service-logon right",
				"SeServiceLogonRight is missing",
			)
		} else {
			report.addCheck(
				checkPass,
				"FIUSNReader service-logon right",
				"SeServiceLogonRight is present",
			)
		}

		if containsRight(usnRights, "SeManageVolumePrivilege") {
			report.addCheck(
				checkWarn,
				"FIUSNReader unnecessary direct right",
				"SeManageVolumePrivilege is assigned directly; the accepted production raw-volume path uses the local-Administrator helper boundary instead",
			)
		}
	}

	if report.Host.BuildNumber != 14393 {
		report.addCheck(
			checkInfo,
			"FIObjReader release-specific rights",
			fmt.Sprintf(
				"build %d has not yet been characterized by this installer milestone",
				report.Host.BuildNumber,
			),
		)
		return
	}

	objRights, ok := rightsByRole["FIObjReader"]
	if !ok {
		report.addCheck(
			checkFail,
			"FIObjReader Server 2016 rights contract",
			"direct account rights were not available",
		)
		return
	}

	required := []string{
		"SeBackupPrivilege",
		"SeSecurityPrivilege",
		"SeServiceLogonRight",
	}
	forbidden := []string{
		"SeManageVolumePrivilege",
		"SeRestorePrivilege",
	}

	var failures []string

	for _, right := range required {
		if !containsRight(objRights, right) {
			failures = append(
				failures,
				"missing "+right,
			)
		}
	}
	for _, right := range forbidden {
		if containsRight(objRights, right) {
			failures = append(
				failures,
				"unexpected "+right,
			)
		}
	}

	if len(failures) != 0 {
		report.addCheck(
			checkFail,
			"FIObjReader Server 2016 rights contract",
			strings.Join(failures, "; "),
		)
		return
	}

	report.addCheck(
		checkPass,
		"FIObjReader Server 2016 rights contract",
		"SeServiceLogonRight, SeBackupPrivilege, SeSecurityPrivilege present; SeRestorePrivilege and SeManageVolumePrivilege absent",
	)
}

func namedPipePresent(name string) (bool, error) {
	path, err := syscall.UTF16PtrFromString(`\\.\pipe\` + name)
	if err != nil {
		return false, fmt.Errorf("encode named-pipe path: %w", err)
	}

	result, _, callErr := waitNamedPipeProc.Call(
		uintptr(unsafe.Pointer(path)),
		0,
	)
	if result != 0 {
		return true, nil
	}

	if callErr == errorSemTimeout {
		// The pipe exists but all instances are busy.
		return true, nil
	}
	if callErr == errorFileNotFound ||
		callErr == errorPathNotFound {
		// WaitNamedPipeW uses ERROR_FILE_NOT_FOUND when the named pipe
		// does not exist. That is an observed absence, not a discovery
		// failure; the caller decides whether absence is expected from
		// the corresponding service state.
		return false, nil
	}
	if callErr != nil && callErr != syscall.Errno(0) {
		return false, callErr
	}

	return false, nil
}

func discoverBrokerPipes(report *Report) {
	contracts := []struct {
		pipe    string
		service string
	}{
		{
			pipe:    "FI-USN",
			service: "FIUSNReader",
		},
		{
			pipe:    "FI-OBJ",
			service: "FIObjReader",
		},
	}

	for _, contract := range contracts {
		service, found := findService(
			report.Services,
			contract.service,
		)

		present, err := namedPipePresent(contract.pipe)
		if err != nil {
			report.addCheck(
				checkFail,
				contract.pipe+" broker pipe",
				err.Error(),
			)
			continue
		}

		if !present {
			switch {
			case !found ||
				service.Presence == presenceUnknown:
				report.addCheck(
					checkFail,
					contract.pipe+" broker pipe",
					"corresponding service discovery is unknown; pipe absence cannot be interpreted safely",
				)
			case service.Presence == presenceAbsent:
				report.addCheck(
					checkInfo,
					contract.pipe+" broker pipe",
					fmt.Sprintf(
						`\\.\pipe\%s is not present because %s is authoritatively absent; runtime pipe verification is deferred until installation`,
						contract.pipe,
						contract.service,
					),
				)
			case service.State != "Running":
				report.addCheck(
					checkInfo,
					contract.pipe+" broker pipe",
					fmt.Sprintf(
						`\\.\pipe\%s is not present while %s state=%s; runtime pipe verification is deferred until that service is running`,
						contract.pipe,
						contract.service,
						valueOrNotKnown(service.State),
					),
				)
			default:
				report.addCheck(
					checkFail,
					contract.pipe+" broker pipe",
					`\\.\pipe\`+contract.pipe+" is not present while "+contract.service+" is Running",
				)
			}
			continue
		}

		report.addCheck(
			checkPass,
			contract.pipe+" broker pipe",
			`\\.\pipe\`+contract.pipe,
		)
	}
}

func runningProcessIDsByName(name string) ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPPROCESS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{})),
	}

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, fmt.Errorf("enumerate first process: %w", err)
	}

	var ids []uint32

	for {
		executable := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(executable, name) {
			ids = append(ids, entry.ProcessID)
		}

		err := windows.Process32Next(snapshot, &entry)
		if err == nil {
			continue
		}
		if err == syscall.ERROR_NO_MORE_FILES {
			break
		}
		return nil, fmt.Errorf("enumerate processes: %w", err)
	}

	return ids, nil
}

func discoverSenderOwnership(
	report *Report,
	states map[string]ServiceState,
) {
	sender := states["FISender"]

	if sender.State != "Running" || sender.ProcessID == 0 {
		report.addCheck(
			checkFail,
			"FISender singleton ownership",
			fmt.Sprintf(
				"service state=%s service_pid=%d",
				sender.State,
				sender.ProcessID,
			),
		)
		return
	}

	processIDs, err := runningProcessIDsByName("fi-sender.exe")
	if err != nil {
		report.addCheck(
			checkFail,
			"FISender singleton ownership",
			err.Error(),
		)
		return
	}

	if len(processIDs) != 1 || processIDs[0] != sender.ProcessID {
		report.addCheck(
			checkFail,
			"FISender singleton ownership",
			fmt.Sprintf(
				"SCM PID=%d observed fi-sender.exe PID(s)=%v",
				sender.ProcessID,
				processIDs,
			),
		)
		return
	}

	report.addCheck(
		checkPass,
		"FISender singleton ownership",
		fmt.Sprintf(
			"exactly one fi-sender.exe exists and is owned by SCM FISender PID=%d",
			sender.ProcessID,
		),
	)
}

func discoverService(
	manager *mgr.Mgr,
	contract serviceContract,
) (ServiceState, error) {
	service, err := manager.OpenService(contract.Name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return ServiceState{
				ManagedAccount: notKnown,
				Name:           contract.Name,
				Presence:       presenceAbsent,
				ProcessID:      0,
				SIDType:        notKnown,
				StartType:      notKnown,
				State:          notKnown,
			}, nil
		}
		return ServiceState{
			ManagedAccount: notKnown,
			Name:           contract.Name,
			Presence:       presenceUnknown,
			ProcessID:      0,
			SIDType:        notKnown,
			StartType:      notKnown,
			State:          notKnown,
		}, fmt.Errorf("open service %s: %w", contract.Name, err)
	}
	defer service.Close()

	value, err := service.Config()
	if err != nil {
		return ServiceState{
			ManagedAccount: notKnown,
			Name:           contract.Name,
			Presence:       presenceUnknown,
			ProcessID:      0,
			SIDType:        notKnown,
			StartType:      notKnown,
			State:          notKnown,
		}, fmt.Errorf("read service %s configuration: %w", contract.Name, err)
	}

	status, err := service.Query()
	if err != nil {
		return ServiceState{
			Account:        value.ServiceStartName,
			BinaryPath:     value.BinaryPathName,
			DisplayName:    value.DisplayName,
			ManagedAccount: notKnown,
			Name:           contract.Name,
			Presence:       presenceUnknown,
			ProcessID:      0,
			SIDType:        serviceSIDTypeName(value.SidType),
			StartType:      serviceStartTypeName(value.StartType),
			State:          notKnown,
		}, fmt.Errorf("query service %s status: %w", contract.Name, err)
	}

	managed := readManagedAccountState(contract.Name)

	return ServiceState{
		Account:        value.ServiceStartName,
		BinaryPath:     value.BinaryPathName,
		DisplayName:    value.DisplayName,
		ManagedAccount: managed,
		Name:           contract.Name,
		Presence:       presencePresent,
		ProcessID:      status.ProcessId,
		SIDType:        serviceSIDTypeName(value.SidType),
		StartType:      serviceStartTypeName(value.StartType),
		State:          serviceStateName(status.State),
	}, nil
}

func discoverServices(report *Report) {
	contracts := []serviceContract{
		{
			DisplayName: "FI Collector",
			Name:        "FICollector",
			Path:        `"C:\Program Files\FI\fi.exe" -service`,
			SIDType:     windows.SERVICE_SID_TYPE_UNRESTRICTED,
		},
		{
			DisplayName: "FIUSNReader",
			Name:        "FIUSNReader",
			Path:        `"C:\Program Files\FI\fi-usn.exe"`,
			SIDType:     windows.SERVICE_SID_TYPE_UNRESTRICTED,
		},
		{
			DisplayName: "FI Object Reader",
			Name:        "FIObjReader",
			Path:        `"C:\Program Files\FI\fi-obj.exe"`,
			SIDType:     windows.SERVICE_SID_TYPE_UNRESTRICTED,
		},
		{
			DisplayName: "FI Sender",
			Name:        "FISender",
			Path:        `"C:\Program Files\FI\fi-sender.exe"`,
			SIDType:     windows.SERVICE_SID_TYPE_NONE,
		},
	}

	manager, err := mgr.Connect()
	if err != nil {
		report.addCheck(
			checkFail,
			"service control manager",
			err.Error(),
		)
		return
	}
	defer manager.Disconnect()

	states := make(map[string]ServiceState)
	presentCount := 0
	absentCount := 0
	unknownCount := 0

	for _, contract := range contracts {
		state, err := discoverService(manager, contract)
		report.Services = append(report.Services, state)
		states[contract.Name] = state

		if err != nil {
			unknownCount++
			report.addCheck(
				checkFail,
				contract.Name+" service",
				err.Error(),
			)
			continue
		}

		switch state.Presence {
		case presenceAbsent:
			absentCount++
			report.addCheck(
				checkInfo,
				contract.Name+" service",
				"service is not present",
			)
			continue
		case presencePresent:
			presentCount++
		default:
			unknownCount++
			report.addCheck(
				checkFail,
				contract.Name+" service",
				"service presence is unknown",
			)
			continue
		}

		failures := make([]string, 0)
		if !strings.EqualFold(
			strings.TrimSpace(state.BinaryPath),
			contract.Path,
		) {
			failures = append(
				failures,
				fmt.Sprintf(
					"path=%q expected=%q",
					state.BinaryPath,
					contract.Path,
				),
			)
		}
		if state.DisplayName != contract.DisplayName {
			failures = append(
				failures,
				fmt.Sprintf(
					"display=%q expected=%q",
					state.DisplayName,
					contract.DisplayName,
				),
			)
		}
		if state.ManagedAccount != "true" {
			failures = append(
				failures,
				"managed_account="+state.ManagedAccount,
			)
		}
		if state.SIDType != serviceSIDTypeName(contract.SIDType) {
			failures = append(
				failures,
				fmt.Sprintf(
					"sid_type=%s expected=%s",
					state.SIDType,
					serviceSIDTypeName(contract.SIDType),
				),
			)
		}
		if state.StartType != "Automatic" {
			failures = append(
				failures,
				"start_type="+state.StartType,
			)
		}
		if state.State != "Running" {
			failures = append(
				failures,
				"state="+state.State,
			)
		}
		if strings.TrimSpace(state.Account) == "" {
			failures = append(
				failures,
				"service_account=not_known",
			)
		}

		if len(failures) != 0 {
			report.addCheck(
				checkFail,
				contract.Name+" service",
				strings.Join(failures, "; "),
			)
			continue
		}

		report.addCheck(
			checkPass,
			contract.Name+" service",
			fmt.Sprintf(
				"account=%s path=%s sid=%s",
				state.Account,
				state.BinaryPath,
				state.SIDType,
			),
		)
	}

	if unknownCount != 0 {
		report.addCheck(
			checkFail,
			"FI service-set discovery",
			"one or more FI service presence/configuration checks are unknown",
		)
		return
	}

	if absentCount == len(contracts) {
		report.addCheck(
			checkInfo,
			"FI service-set discovery",
			"all four FI services are authoritatively absent; service-dependent runtime checks are deferred to installation",
		)
		return
	}

	if presentCount != len(contracts) {
		report.addCheck(
			checkFail,
			"FI service-set discovery",
			fmt.Sprintf(
				"partial FI service set observed: present=%d absent=%d; reconcile as an existing/partial installation",
				presentCount,
				absentCount,
			),
		)
		return
	}

	discoverServiceIdentityRelationships(report, states)
	discoverIdentityBoundary(report, states)
	discoverAccountRights(report, states)
	discoverSenderOwnership(report, states)
}

func discoverServiceIdentityRelationships(
	report *Report,
	states map[string]ServiceState,
) {
	collector := states["FICollector"].Account
	objReader := states["FIObjReader"].Account
	sender := states["FISender"].Account
	usnReader := states["FIUSNReader"].Account

	if collector == "" ||
		objReader == "" ||
		sender == "" ||
		usnReader == "" {
		report.addCheck(
			checkFail,
			"service identity separation",
			"one or more service identities are unavailable",
		)
		return
	}

	if !strings.EqualFold(collector, sender) {
		report.addCheck(
			checkFail,
			"collector/sender identity",
			fmt.Sprintf(
				"FICollector=%s FISender=%s",
				collector,
				sender,
			),
		)
	} else {
		report.addCheck(
			checkPass,
			"collector/sender identity",
			collector,
		)
	}

	switch {
	case strings.EqualFold(collector, usnReader):
		report.addCheck(
			checkFail,
			"service identity separation",
			"FICollector and FIUSNReader use the same account",
		)
	case strings.EqualFold(collector, objReader):
		report.addCheck(
			checkFail,
			"service identity separation",
			"FICollector and FIObjReader use the same account",
		)
	case strings.EqualFold(usnReader, objReader):
		report.addCheck(
			checkFail,
			"service identity separation",
			"FIUSNReader and FIObjReader use the same account",
		)
	default:
		report.addCheck(
			checkPass,
			"service identity separation",
			fmt.Sprintf(
				"collector=%s usn=%s obj=%s",
				collector,
				usnReader,
				objReader,
			),
		)
	}
}

func discoverTransportTrust(report *Report) {
	value, path, err := config.LoadDefaultTransportTrust()
	report.Trust.Path = path
	report.Trust.Presence = presenceUnknown
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			report.Trust.Presence = presenceAbsent
			report.addCheck(
				checkInfo,
				"FI transport trust configuration",
				path+" is not present",
			)
			return
		}
		report.addCheck(
			checkFail,
			"FI transport trust configuration",
			err.Error(),
		)
		return
	}

	report.Trust = TransportTrustState{
		BatchSigningCertificateSHA256: value.BatchSigningCertificateSHA256,
		Path:                          path,
		Presence:                      presencePresent,
		RootCertificateSHA256:         value.RootCertificateSHA256,
		TransportCertificateSHA256:    value.TransportCertificateSHA256,
		TransportCRLPath:              value.TransportCRLPath,
		TransportIssuerSHA256:         value.TransportIssuerSHA256,
		VersionID:                     value.VersionID,
	}

	report.addCheck(
		checkPass,
		"FI transport trust configuration",
		fmt.Sprintf("%s version=%s", path, value.VersionID),
	)

	discoverPKI(report, value)
	discoverCNGKeyACLs(report)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}

	return strings.ToUpper(
		hex.EncodeToString(digest.Sum(nil)),
	), nil
}

func readDomainDNS() string {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return notKnown
	}
	defer key.Close()

	for _, name := range []string{"NV Domain", "Domain"} {
		value, _, err := key.GetStringValue(name)
		if err == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}

	return notKnown
}

func readManagedAccountState(serviceName string) string {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+serviceName,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return notKnown
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("ServiceAccountManaged")
	if err != nil {
		return notKnown
	}

	if value == 0 {
		return "false"
	}
	return "true"
}

func readWindowsVersion() (uint32, string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return 0, "", fmt.Errorf(
			"open Windows version registry key: %w",
			err,
		)
	}
	defer key.Close()

	buildText, _, err := key.GetStringValue("CurrentBuildNumber")
	if err != nil {
		return 0, "", fmt.Errorf(
			"read CurrentBuildNumber: %w",
			err,
		)
	}

	build, err := strconv.ParseUint(
		strings.TrimSpace(buildText),
		10,
		32,
	)
	if err != nil {
		return 0, "", fmt.Errorf(
			"parse CurrentBuildNumber %q: %w",
			buildText,
			err,
		)
	}

	productName, _, err := key.GetStringValue("ProductName")
	if err != nil {
		productName = notKnown
	}

	return uint32(build), productName, nil
}

func serviceSIDTypeName(value uint32) string {
	switch value {
	case windows.SERVICE_SID_TYPE_NONE:
		return "NONE"
	case windows.SERVICE_SID_TYPE_RESTRICTED:
		return "RESTRICTED"
	case windows.SERVICE_SID_TYPE_UNRESTRICTED:
		return "UNRESTRICTED"
	default:
		return fmt.Sprintf("not_known(%d)", value)
	}
}

func serviceStartTypeName(value uint32) string {
	switch value {
	case mgr.StartAutomatic:
		return "Automatic"
	case mgr.StartDisabled:
		return "Disabled"
	case mgr.StartManual:
		return "Manual"
	default:
		return fmt.Sprintf("not_known(%d)", value)
	}
}

func serviceStateName(value svc.State) string {
	switch value {
	case svc.ContinuePending:
		return "ContinuePending"
	case svc.PausePending:
		return "PausePending"
	case svc.Paused:
		return "Paused"
	case svc.Running:
		return "Running"
	case svc.StartPending:
		return "StartPending"
	case svc.StopPending:
		return "StopPending"
	case svc.Stopped:
		return "Stopped"
	default:
		return fmt.Sprintf("not_known(%d)", value)
	}
}

func valueOrNotKnown(value string) string {
	if strings.TrimSpace(value) == "" {
		return notKnown
	}
	return value
}

func Discover() Report {
	var report Report

	discoverHost(&report)
	discoverDomainJoin(&report)
	discoverConfig(&report)
	discoverTransportTrust(&report)
	discoverServices(&report)
	discoverActiveDirectory(&report)
	discoverGMSAs(&report)
	discoverBrokerPipes(&report)
	discoverACLs(&report)
	discoverBinaries(&report)
	discoverPackage(&report)
	discoverReleaseTrust(&report)

	report.addCheck(
		checkInfo,
		"installer mode",
		"read-only discovery; no host, AD, PKI, service, ACL, or file changes are performed",
	)

	return report
}

func (report Report) HasFailures() bool {
	for _, check := range report.Checks {
		if check.Status == checkFail {
			return true
		}
	}
	return false
}

func (report Report) HasWarnings() bool {
	for _, check := range report.Checks {
		if check.Status == checkWarn {
			return true
		}
	}
	return false
}

func writeReleaseTrustDocumentText(
	writer io.Writer,
	label string,
	state ReleaseTrustDocumentState,
) {
	fmt.Fprintf(
		writer,
		"%s policy:                             %s\n",
		label,
		valueOrNotKnown(state.Path),
	)
	fmt.Fprintf(
		writer,
		"%s signature:                          %s\n",
		label,
		valueOrNotKnown(state.SignaturePath),
	)
	fmt.Fprintf(
		writer,
		"%s present:                            %t\n",
		label,
		state.Present,
	)
	fmt.Fprintf(
		writer,
		"%s valid:                              %t\n",
		label,
		state.Valid,
	)
	if state.Policy.Generation != 0 {
		fmt.Fprintf(
			writer,
			"%s generation:                         %d\n",
			label,
			state.Policy.Generation,
		)
	}
	if state.PolicySHA256 != "" {
		fmt.Fprintf(
			writer,
			"%s policy SHA256:                      %s\n",
			label,
			state.PolicySHA256,
		)
	}
	if state.Signature.SignerSubject != "" {
		fmt.Fprintf(
			writer,
			"%s policy signer:                      %s\n",
			label,
			state.Signature.SignerSubject,
		)
	}
	if state.Signature.SignerSPKISHA256 != "" {
		fmt.Fprintf(
			writer,
			"%s policy signer SPKI SHA256:          %s\n",
			label,
			state.Signature.SignerSPKISHA256,
		)
	}
	fmt.Fprintf(
		writer,
		"%s policy authority pinned:             %t\n",
		label,
		state.AuthorityPinned,
	)
	if state.Error != "" {
		fmt.Fprintf(
			writer,
			"%s error:                              %s\n",
			label,
			state.Error,
		)
	}

	if state.Valid {
		for _, signer := range sortedReleaseTrustSigners(
			state.Policy.ActiveSigners,
		) {
			fmt.Fprintf(
				writer,
				"%s active signer:                    id=%s cert_sha256=%s spki_sha256=%s\n",
				label,
				signer.ID,
				signer.CertificateSHA256,
				signer.SPKISHA256,
			)
		}
		for _, signer := range sortedReleaseTrustSigners(
			state.Policy.NextSigners,
		) {
			fmt.Fprintf(
				writer,
				"%s next signer:                      id=%s cert_sha256=%s spki_sha256=%s\n",
				label,
				signer.ID,
				signer.CertificateSHA256,
				signer.SPKISHA256,
			)
		}
	}
}

func (report Report) WriteText(writer io.Writer) error {
	if writer == nil {
		return fmt.Errorf("output writer is required")
	}

	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintln(writer, "FI WINDOWS INSTALLER - READ-ONLY DISCOVERY")
	fmt.Fprintln(writer, "============================================================")
	fmt.Fprintf(writer, "Computer:     %s\n", valueOrNotKnown(report.Host.Computer))
	fmt.Fprintf(writer, "Domain DNS:   %s\n", valueOrNotKnown(report.Host.DomainDNS))
	fmt.Fprintf(writer, "OS:           %s\n", valueOrNotKnown(report.Host.ProductName))
	fmt.Fprintf(writer, "Build:        %d\n", report.Host.BuildNumber)
	fmt.Fprintf(writer, "FI profile:   %s\n", valueOrNotKnown(report.Host.Profile.Name))
	fmt.Fprintf(writer, "Elevated:     %t\n", report.Host.Elevated)
	fmt.Fprintf(writer, "Join status:  %s\n", valueOrNotKnown(report.Join.Status))
	fmt.Fprintf(writer, "Join name:    %s\n", valueOrNotKnown(report.Join.Name))

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== FI CONFIGURATION =====")
	fmt.Fprintf(writer, "Path:         %s\n", valueOrNotKnown(report.Config.Path))
	fmt.Fprintf(writer, "Presence:     %s\n", valueOrNotKnown(report.Config.Presence))
	fmt.Fprintf(writer, "Version:      %s\n", valueOrNotKnown(report.Config.VersionID))
	fmt.Fprintf(writer, "Source:       %s\n", valueOrNotKnown(report.Config.SourceID))
	fmt.Fprintf(writer, "Receiver:     %s\n", valueOrNotKnown(report.Config.ReceiverAddress))
	fmt.Fprintf(writer, "ReceiverName: %s\n", valueOrNotKnown(report.Config.ReceiverName))
	fmt.Fprintf(writer, "Spool:        %s\n", valueOrNotKnown(report.Config.SpoolDir))
	fmt.Fprintf(writer, "Stage:        %s\n", valueOrNotKnown(report.Config.StageDir))
	fmt.Fprintf(writer, "State:        %s\n", valueOrNotKnown(report.Config.StateDir))
	if len(report.Config.GovernedRoots) == 0 {
		fmt.Fprintln(writer, "GovernedRoot: not_known")
	} else {
		for _, root := range report.Config.GovernedRoots {
			fmt.Fprintf(writer, "GovernedRoot: %s\n", root)
		}
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== SERVICES =====")
	for _, service := range report.Services {
		fmt.Fprintf(
			writer,
			"%-12s presence=%-8s state=%-12s start=%-10s managed=%-9s sid=%-12s pid=%-6d account=%s\n",
			service.Name,
			valueOrNotKnown(service.Presence),
			service.State,
			service.StartType,
			service.ManagedAccount,
			service.SIDType,
			service.ProcessID,
			valueOrNotKnown(service.Account),
		)
		fmt.Fprintf(
			writer,
			"             path=%s\n",
			valueOrNotKnown(service.BinaryPath),
		)
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== ACTIVE DIRECTORY DISCOVERY =====")
	fmt.Fprintf(writer, "DC:                 %s\n", valueOrNotKnown(report.AD.DomainController))
	fmt.Fprintf(writer, "Domain NC:          %s\n", valueOrNotKnown(report.AD.DefaultNamingContext))
	fmt.Fprintf(writer, "Configuration NC:   %s\n", valueOrNotKnown(report.AD.ConfigurationNamingContext))
	fmt.Fprintf(writer, "Forest:             %s\n", valueOrNotKnown(report.AD.ForestDNS))
	fmt.Fprintf(writer, "DC site:            %s\n", valueOrNotKnown(report.AD.DCSite))
	fmt.Fprintf(writer, "Client site:        %s\n", valueOrNotKnown(report.AD.ClientSite))
	fmt.Fprintf(writer, "Computer DN:        %s\n", valueOrNotKnown(report.AD.ComputerDN))
	fmt.Fprintf(writer, "Computer SID:       %s\n", valueOrNotKnown(report.AD.ComputerSID))
	if report.AD.KDSRootKeyKnown {
		fmt.Fprintf(writer, "KDS root keys:      %d\n", report.AD.KDSRootKeyCount)
	} else {
		fmt.Fprintln(writer, "KDS root keys:      not_known")
	}
	if len(report.AD.GMSAs) == 0 {
		if report.AD.GMSADiscoveryKnown {
			fmt.Fprintln(writer, "AD gMSAs:           none")
		} else {
			fmt.Fprintln(writer, "AD gMSAs:           not_known")
		}
	} else {
		for _, account := range report.AD.GMSAs {
			fmt.Fprintf(
				writer,
				"AD gMSA %-14s sam=%-20s dns=%-36s interval=%-4s membership_sd_bytes=%d\n",
				account.Role,
				valueOrNotKnown(account.SAMAccountName),
				valueOrNotKnown(account.DNSHostName),
				valueOrNotKnown(account.ManagedPasswordIntervalDays),
				account.GroupMSAMembershipBytes,
			)
			fmt.Fprintf(
				writer,
				"                     dn=%s\n",
				valueOrNotKnown(account.DistinguishedName),
			)
			for _, trustee := range account.PasswordRetrievalTrustees {
				fmt.Fprintf(
					writer,
					"                     password-trustee type=%s flags=0x%02X mask=0x%08X account=%s sid=%s\n",
					trustee.Type,
					trustee.Flags,
					trustee.Mask,
					valueOrNotKnown(trustee.Account),
					valueOrNotKnown(trustee.SID),
				)
			}
		}
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== MANAGED SERVICE ACCOUNTS =====")
	if len(report.GMSAs) == 0 {
		fmt.Fprintln(writer, "not_known")
	} else {
		for _, account := range report.GMSAs {
			fmt.Fprintf(
				writer,
				"%-22s account=%-24s sam=%-20s state=%s\n",
				account.Role,
				account.Account,
				account.SAMAccountName,
				account.State,
			)
		}
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== DIRECT ACCOUNT RIGHTS =====")
	if len(report.AccountRights) == 0 {
		fmt.Fprintln(writer, "not_known")
	} else {
		for _, account := range report.AccountRights {
			rights := "none"
			if len(account.Rights) != 0 {
				rights = strings.Join(account.Rights, ", ")
			}
			fmt.Fprintf(
				writer,
				"%-22s account=%s\n",
				account.Role,
				account.Account,
			)
			fmt.Fprintf(
				writer,
				"                       rights=%s\n",
				rights,
			)
		}
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== FILE / DIRECTORY DACL DISCOVERY =====")
	if len(report.ACLs) == 0 {
		fmt.Fprintln(writer, "not_known")
	} else {
		for _, acl := range report.ACLs {
			fmt.Fprintf(
				writer,
				"%s\n  path=%s\n  owner=%s protected=%t\n",
				acl.Label,
				acl.Path,
				valueOrNotKnown(acl.Owner),
				acl.Protected,
			)
			if len(acl.Entries) == 0 {
				fmt.Fprintln(writer, "  entries=none")
				continue
			}
			for _, entry := range acl.Entries {
				fmt.Fprintf(
					writer,
					"  %-5s inherited=%-5t flags=0x%02X mask=0x%08X account=%s sid=%s\n",
					entry.Type,
					entry.Inherited,
					entry.Flags,
					entry.Mask,
					valueOrNotKnown(entry.Account),
					valueOrNotKnown(entry.SID),
				)
			}
		}
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== BINARIES =====")
	for _, binaryState := range report.Binaries {
		fmt.Fprintf(
			writer,
			"%-12s presence=%-8s %s\n",
			binaryState.Name,
			valueOrNotKnown(binaryState.Presence),
			binaryState.Path,
		)
		fmt.Fprintf(
			writer,
			"             SHA256=%s\n",
			valueOrNotKnown(binaryState.SHA256),
		)
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== FI RELEASE MANIFEST =====")
	fmt.Fprintf(writer, "Package root:  %s\n", valueOrNotKnown(report.Package.Root))
	fmt.Fprintf(writer, "Manifest:      %s\n", valueOrNotKnown(report.Package.ManifestPath))
	fmt.Fprintf(writer, "Signature:     %s\n", valueOrNotKnown(report.Package.ManifestSignaturePath))
	fmt.Fprintf(writer, "Payload root:  %s\n", valueOrNotKnown(report.Package.PayloadRoot))
	fmt.Fprintf(writer, "Valid:         %t\n", report.Package.ManifestValid)
	fmt.Fprintf(writer, "Release ID:    %s\n", valueOrNotKnown(report.Package.ReleaseID))
	fmt.Fprintf(writer, "Version:       %s\n", valueOrNotKnown(report.Package.Version))
	fmt.Fprintf(writer, "Platform:      %s\n", valueOrNotKnown(report.Package.Platform))
	fmt.Fprintf(writer, "Architecture:  %s\n", valueOrNotKnown(report.Package.Architecture))
	fmt.Fprintf(
		writer,
		"Installer Authenticode trusted: %t\n",
		report.Package.InstallerAuthenticodeTrusted,
	)
	if report.Package.InstallerAuthenticodeSignerSubject != "" {
		fmt.Fprintf(
			writer,
			"Installer Authenticode signer:  %s\n",
			report.Package.InstallerAuthenticodeSignerSubject,
		)
	}
	if report.Package.InstallerAuthenticodeSignerCertSHA256 != "" {
		fmt.Fprintf(
			writer,
			"Installer signer cert SHA256:   %s\n",
			report.Package.InstallerAuthenticodeSignerCertSHA256,
		)
	}
	if report.Package.InstallerAuthenticodeSignerSPKISHA256 != "" {
		fmt.Fprintf(
			writer,
			"Installer signer SPKI SHA256:   %s\n",
			report.Package.InstallerAuthenticodeSignerSPKISHA256,
		)
	}
	if report.Package.InstallerAuthenticodeSignerID != "" {
		fmt.Fprintf(
			writer,
			"Installer release signer ID:    %s authorized=%t next_only=%t\n",
			report.Package.InstallerAuthenticodeSignerID,
			report.Package.InstallerAuthenticodeSignerAuthorized,
			report.Package.InstallerAuthenticodeSignerKnownNext,
		)
	}
	fmt.Fprintf(
		writer,
		"Manifest detached signature valid: %t\n",
		report.Package.ManifestSignature.SignatureValid,
	)
	fmt.Fprintf(
		writer,
		"Manifest signer chain trusted:     %t\n",
		report.Package.ManifestSignature.SignerChainTrusted,
	)
	if report.Package.ManifestSignature.SignerSubject != "" {
		fmt.Fprintf(
			writer,
			"Manifest signer subject:           %s\n",
			report.Package.ManifestSignature.SignerSubject,
		)
	}
	if report.Package.ManifestSignature.SignerCertSHA256 != "" {
		fmt.Fprintf(
			writer,
			"Manifest signer cert SHA256:       %s\n",
			report.Package.ManifestSignature.SignerCertSHA256,
		)
	}
	if report.Package.ManifestSignature.SignerSPKISHA256 != "" {
		fmt.Fprintf(
			writer,
			"Manifest signer SPKI SHA256:       %s\n",
			report.Package.ManifestSignature.SignerSPKISHA256,
		)
	}
	if report.Package.ManifestSignature.Error != "" {
		fmt.Fprintf(
			writer,
			"Manifest signature error:          %s\n",
			report.Package.ManifestSignature.Error,
		)
	}
	if report.Package.InstallerAuthenticodeError != "" {
		fmt.Fprintf(
			writer,
			"Installer Authenticode error:   %s\n",
			report.Package.InstallerAuthenticodeError,
		)
	}
	if report.Package.InstallerAuthenticodeSignerIdentityError != "" {
		fmt.Fprintf(
			writer,
			"Installer signer identity error: %s\n",
			report.Package.InstallerAuthenticodeSignerIdentityError,
		)
	}
	if report.Package.Error != "" {
		fmt.Fprintf(writer, "Error:         %s\n", report.Package.Error)
	}
	for _, file := range sortedPackageFiles(report.Package.Files) {
		fmt.Fprintf(
			writer,
			"%-12s name=%-14s payload_match=%-5t installed_match=%-5t expected=%s\n",
			file.Role,
			file.Name,
			file.PayloadMatch,
			file.Match,
			valueOrNotKnown(file.ExpectedSHA256),
		)
		fmt.Fprintf(
			writer,
			"             payload=%s SHA256=%s authenticode_trusted=%t\n",
			valueOrNotKnown(file.PayloadPath),
			valueOrNotKnown(file.PayloadSHA256),
			file.PayloadAuthenticodeTrusted,
		)
		if file.PayloadAuthenticodeSignerSubject != "" {
			fmt.Fprintf(
				writer,
				"             signer=%s cert_sha256=%s spki_sha256=%s signer_id=%s authorized=%t next_only=%t\n",
				file.PayloadAuthenticodeSignerSubject,
				valueOrNotKnown(file.PayloadAuthenticodeSignerCertSHA256),
				valueOrNotKnown(file.PayloadAuthenticodeSignerSPKISHA256),
				valueOrNotKnown(file.PayloadAuthenticodeSignerID),
				file.PayloadAuthenticodeSignerAuthorized,
				file.PayloadAuthenticodeSignerKnownNext,
			)
		}
		if file.PayloadAuthenticodeError != "" {
			fmt.Fprintf(
				writer,
				"             payload_authenticode_error=%s\n",
				file.PayloadAuthenticodeError,
			)
		}
		if file.PayloadAuthenticodeSignerIdentityError != "" {
			fmt.Fprintf(
				writer,
				"             payload_signer_identity_error=%s\n",
				file.PayloadAuthenticodeSignerIdentityError,
			)
		}
		fmt.Fprintf(
			writer,
			"             installed=%s SHA256=%s\n",
			valueOrNotKnown(file.InstalledPath),
			valueOrNotKnown(file.ActualSHA256),
		)
	}
	fmt.Fprintf(writer, "Payload hashes match manifest:   %t\n", report.Package.PayloadHashesMatch)
	fmt.Fprintf(writer, "Installed hashes match manifest: %t\n", report.Package.InstalledHashesMatch)
	fmt.Fprintf(writer, "Installer + payload Authenticode trusted: %t\n", report.Package.AuthenticodeFilesTrusted)
	fmt.Fprintf(writer, "Authenticode signer identities complete:  %t\n", report.Package.AuthenticodeSignerIdentitiesComplete)
	fmt.Fprintf(writer, "Authenticode signers release-authorized:  %t\n", report.Package.AuthenticodeSignersAuthorized)

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== FI RELEASE TRUST =====")
	fmt.Fprintf(
		writer,
		"Bootstrap policy authority pin configured: %t\n",
		report.ReleaseTrust.BootstrapAuthorityConfigured,
	)
	fmt.Fprintf(
		writer,
		"Bootstrap policy authority SPKI SHA256:   %s\n",
		valueOrNotKnown(
			report.ReleaseTrust.BootstrapAuthoritySPKISHA256,
		),
	)
	writeReleaseTrustDocumentText(
		writer,
		"Installed",
		report.ReleaseTrust.Installed,
	)
	writeReleaseTrustDocumentText(
		writer,
		"Package",
		report.ReleaseTrust.Package,
	)
	fmt.Fprintf(
		writer,
		"Effective policy source:                  %s\n",
		valueOrNotKnown(
			report.ReleaseTrust.EffectivePolicySource,
		),
	)
	fmt.Fprintf(
		writer,
		"Transition allowed:                       %t\n",
		report.ReleaseTrust.TransitionAllowed,
	)
	fmt.Fprintf(
		writer,
		"Manifest signer authorized:               %t\n",
		report.ReleaseTrust.ManifestSignerAuthorized,
	)
	fmt.Fprintf(
		writer,
		"Manifest signer ID:                       %s\n",
		valueOrNotKnown(
			report.ReleaseTrust.ManifestSignerID,
		),
	)
	fmt.Fprintf(
		writer,
		"Manifest signer staged as next only:      %t\n",
		report.ReleaseTrust.ManifestSignerKnownNext,
	)
	if report.ReleaseTrust.Error != "" {
		fmt.Fprintf(
			writer,
			"Release trust error:                     %s\n",
			report.ReleaseTrust.Error,
		)
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== TRANSPORT TRUST / PKI =====")
	fmt.Fprintf(writer, "Path:         %s\n", valueOrNotKnown(report.Trust.Path))
	fmt.Fprintf(writer, "Presence:     %s\n", valueOrNotKnown(report.Trust.Presence))
	fmt.Fprintf(writer, "Version:      %s\n", valueOrNotKnown(report.Trust.VersionID))
	for _, object := range report.PKI {
		fmt.Fprintf(
			writer,
			"[%s] %-34s %s\n",
			object.State,
			object.Name,
			object.Detail,
		)
	}

	fmt.Fprintln(writer, "")
	fmt.Fprintln(writer, "===== CHECKS =====")
	for _, check := range report.Checks {
		fmt.Fprintf(
			writer,
			"[%s] %-34s %s\n",
			check.Status,
			check.Name,
			check.Detail,
		)
	}

	fmt.Fprintln(writer, "")
	if report.HasFailures() {
		fmt.Fprintln(writer, "FI INSTALLER DISCOVERY RESULT: FAIL")
	} else if report.HasWarnings() {
		fmt.Fprintln(writer, "FI INSTALLER DISCOVERY RESULT: PASS WITH WARNINGS")
	} else {
		fmt.Fprintln(writer, "FI INSTALLER DISCOVERY RESULT: PASS")
	}
	fmt.Fprintln(
		writer,
		"No changes were made. This milestone is discovery-only.",
	)

	return nil
}
