// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TokenIsAppContainer is TOKEN_INFORMATION_CLASS 29 on Windows 8 /
// Server 2012 and later. x/sys/windows exposes TokenLogonSid=28 but does
// not expose this newer class in every supported dependency version.
const nativeTokenIsAppContainer uint32 = 29
const maxInstallerTokenInfoBytes = 16384

// queryInstallerTokenDword inspects one scalar TOKEN_INFORMATION_CLASS.
// Unlike Token.IsElevated(), it preserves native errors and rejects
// truncated/ambiguous output rather than silently treating errors as false.
func queryInstallerTokenDword(token windows.Token, class uint32) (uint32,error) {
	var value uint32
	var returned uint32
	err := windows.GetTokenInformation(token,class,
		(*byte)(unsafe.Pointer(&value)),uint32(unsafe.Sizeof(value)),&returned)
	if err!=nil || returned!=uint32(unsafe.Sizeof(value)) {
		return 0,fmt.Errorf("%w: query token class %d: %v (bytes=%d)",
			ErrUnqualifiedInstallerToken,class,err,returned)
	}
	return value,nil
}

// queryInstallerTokenVariable obtains a bounded single native token
// information snapshot. It refuses a growing/ill-formed structure rather
// than allocating unlimited memory or accepting an inconsistent result.
func queryInstallerTokenVariable(token windows.Token,class uint32) ([]byte,error) {
	var required uint32
	firstErr:=windows.GetTokenInformation(token,class,nil,0,&required)
	if !errors.Is(firstErr,windows.ERROR_INSUFFICIENT_BUFFER) ||
		required==0 || required>maxInstallerTokenInfoBytes {
		return nil,fmt.Errorf("%w: class %d invalid required native length %d: %v",
			ErrUnqualifiedInstallerToken,class,required,firstErr)
	}
	buffer:=make([]byte,required)
	var returned uint32
	if err:=windows.GetTokenInformation(token,class,&buffer[0],uint32(len(buffer)),&returned);err!=nil{
		return nil,fmt.Errorf("%w: class %d native read: %v",ErrUnqualifiedInstallerToken,class,err)
	}
	if returned==0 || returned>uint32(len(buffer)) {
		return nil,fmt.Errorf("%w: class %d inconsistent native length %d",ErrUnqualifiedInstallerToken,class,returned)
	}
	return buffer[:returned],nil
}

func installerTokenIntegrityRID(token windows.Token) (uint32,error) {
	buffer,err:=queryInstallerTokenVariable(token,windows.TokenIntegrityLevel)
	if err!=nil{return 0,err}
	if len(buffer)<int(unsafe.Sizeof(windows.Tokenmandatorylabel{})){
		return 0,fmt.Errorf("%w: truncated TOKEN_MANDATORY_LABEL",ErrUnqualifiedInstallerToken)
	}
	label:=(*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	if label.Label.Sid==nil || !label.Label.Sid.IsValid() {
		return 0,fmt.Errorf("%w: invalid mandatory integrity SID",ErrUnqualifiedInstallerToken)
	}
	sid:=label.Label.Sid.String()
	runtime.KeepAlive(buffer)
	if !strings.HasPrefix(sid,"S-1-16-") {
		return 0,fmt.Errorf("%w: unexpected mandatory integrity SID",ErrUnqualifiedInstallerToken)
	}
	rid,err:=strconv.ParseUint(strings.TrimPrefix(sid,"S-1-16-"),10,32)
	if err!=nil || rid==0 {
		return 0,fmt.Errorf("%w: malformed mandatory integrity RID: %v",ErrUnqualifiedInstallerToken,err)
	}
	return uint32(rid),nil
}

// installerTokenPrivilegesBounded decodes the Windows TOKEN_PRIVILEGES ABI
// (4-byte count, then count * 12-byte LUID_AND_ATTRIBUTES). It enumerates
// no more than 256 actual privileges and explicitly resolves the six
// privilege LUIDs we want to record. Nothing is enabled or adjusted.
func installerTokenPrivilegesBounded(token windows.Token) ([]InstallerPrivilegeObservation,error) {
	data,err:=queryInstallerTokenVariable(token,windows.TokenPrivileges)
	if err!=nil{return nil,err}
	if len(data)<4 {
		return nil,fmt.Errorf("%w: truncated TOKEN_PRIVILEGES header",ErrUnqualifiedInstallerToken)
	}
	count:=binary.LittleEndian.Uint32(data[:4])
	if count>maxInstallerPrivileges || len(data)!=4+int(count)*12 {
		return nil,fmt.Errorf("%w: unsupported/truncated TOKEN_PRIVILEGES array (count=%d bytes=%d)",
			ErrUnqualifiedInstallerToken,count,len(data))
	}
	observed:=make(map[[2]uint32]uint32,int(count))
	for i:=0;i<int(count);i++ {
		offset:=4+i*12
		low:=binary.LittleEndian.Uint32(data[offset:offset+4])
		high:=binary.LittleEndian.Uint32(data[offset+4:offset+8])
		attrs:=binary.LittleEndian.Uint32(data[offset+8:offset+12])
		if attrs & ^uint32(windows.SE_PRIVILEGE_ENABLED_BY_DEFAULT|
			windows.SE_PRIVILEGE_ENABLED|windows.SE_PRIVILEGE_REMOVED|
			windows.SE_PRIVILEGE_USED_FOR_ACCESS)!=0 {
			return nil,fmt.Errorf("%w: unknown privilege attribute flags",ErrUnqualifiedInstallerToken)
		}
		key:=[2]uint32{low,high}
		if _,exists:=observed[key];exists {
			return nil,fmt.Errorf("%w: duplicate native privilege LUID",ErrUnqualifiedInstallerToken)
		}
		observed[key]=attrs
	}
	result:=make([]InstallerPrivilegeObservation,0,len(inspectedInstallerPrivileges))
	for _,name:=range inspectedInstallerPrivileges {
		ptr,err:=windows.UTF16PtrFromString(name)
		if err!=nil{return nil,fmt.Errorf("%w: invalid known privilege name: %v",ErrUnqualifiedInstallerToken,err)}
		var id windows.LUID
		if err:=windows.LookupPrivilegeValue(nil,ptr,&id);err!=nil {
			return nil,fmt.Errorf("%w: native privilege name resolution for %s: %v",ErrUnqualifiedInstallerToken,name,err)
		}
		attrs,found:=observed[[2]uint32{id.LowPart,uint32(id.HighPart)}]
		result=append(result,InstallerPrivilegeObservation{
			Name:name,Present:found,
			Enabled:found && (attrs&windows.SE_PRIVILEGE_ENABLED)!=0,
		})
	}
	return result,nil
}

// enabledInstallerAdministratorsGroup inspects TokenGroups directly from the
// queried PRIMARY process token. CheckTokenMembership/Token.IsMember can
// require an impersonation token; we must NOT impersonate or duplicate a
// privileged token merely to answer this read-only preflight question.
//
// The enabled Administrators SID must not be deny-only. Group enumeration
// is bounded, and ambiguous duplicates fail rather than granting authority.
func enabledInstallerAdministratorsGroup(token windows.Token) (bool,error) {
	groups,err:=token.GetTokenGroups()
	if err!=nil || groups==nil {
		return false,fmt.Errorf("%w: query primary token groups: %v",ErrUnqualifiedInstallerToken,err)
	}
	if groups.GroupCount==0 || groups.GroupCount>512 {
		return false,fmt.Errorf("%w: missing or excessive native group inventory (%d)",ErrUnqualifiedInstallerToken,groups.GroupCount)
	}
	seen:=false
	enabled:=false
	for _,g:=range groups.AllGroups() {
		if g.Sid==nil || !g.Sid.IsValid() {
			return false,fmt.Errorf("%w: malformed token group SID",ErrUnqualifiedInstallerToken)
		}
		if g.Sid.String()!=journalAdministratorsSID {continue}
		if seen {
			return false,fmt.Errorf("%w: duplicate built-in Administrators SID",ErrUnqualifiedInstallerToken)
		}
		seen=true
		enabled=installerAdministratorsGroupEnabled(g.Attributes)
	}
	return enabled,nil
}

// isInstallerThreadImpersonating observes the CURRENT pinned OS thread,
// not just the process primary token. ERROR_NO_TOKEN is the only clean
// absence result. Any other failure or attached impersonation token blocks
// use of the process token as FI installer-user evidence.
func isInstallerThreadImpersonating() (bool,error) {
	thread,err:=windows.GetCurrentThread()
	if err!=nil {
		return false,fmt.Errorf("%w: obtain pinned OS thread for token preflight: %v",ErrUnqualifiedInstallerToken,err)
	}
	var threadToken windows.Token
	err=windows.OpenThreadToken(thread,windows.TOKEN_QUERY,true,&threadToken)
	if err==nil {
		defer threadToken.Close()
		return true,nil
	}
	if errors.Is(err,windows.ERROR_NO_TOKEN) {
		return false,nil
	}
	return false,fmt.Errorf("%w: inspect thread impersonation token: %v",ErrUnqualifiedInstallerToken,err)
}

// inspectNativeInstallerProcessToken observes an elevated administrator's
// native current PROCESS token under a pinned OS thread. This read-only
// diagnostic never impersonates a user, duplicates a privileged token,
// adjusts token privileges or starts an installer phase.
//
// A thread impersonation token is refused both before and after the process
// observation. Evidence is not a reusable capability: a future installer
// must still establish its own authenticated, operator-approved transaction.
func inspectNativeInstallerProcessToken() (InstallerTokenEvidence,error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	impersonating,err:=isInstallerThreadImpersonating()
	if err!=nil{return InstallerTokenEvidence{},err}
	if impersonating {
		return InstallerTokenEvidence{},fmt.Errorf("%w: current thread is impersonating another security context",ErrUnqualifiedInstallerToken)
	}

	var token windows.Token
	if err:=windows.OpenProcessToken(windows.CurrentProcess(),windows.TOKEN_QUERY,&token);err!=nil {
		return InstallerTokenEvidence{},fmt.Errorf("%w: open current process query-only token: %v",ErrUnqualifiedInstallerToken,err)
	}
	defer token.Close()
	e:=InstallerTokenEvidence{Primary:false}
	user,err:=token.GetTokenUser()
	if err!=nil || user==nil || user.User.Sid==nil || !user.User.Sid.IsValid() {
		return InstallerTokenEvidence{},fmt.Errorf("%w: query process token user SID: %v",ErrUnqualifiedInstallerToken,err)
	}
	e.UserSID=user.User.Sid.String()

	tokenType,err:=queryInstallerTokenDword(token,windows.TokenType)
	if err!=nil{return InstallerTokenEvidence{},err}
	e.Primary=tokenType==installerTokenPrimary

	elevated,err:=queryInstallerTokenDword(token,windows.TokenElevation)
	if err!=nil{return InstallerTokenEvidence{},err}
	e.Elevated=elevated==1
	e.ElevationType,err=queryInstallerTokenDword(token,windows.TokenElevationType)
	if err!=nil{return InstallerTokenEvidence{},err}
	e.IntegrityRID,err=installerTokenIntegrityRID(token)
	if err!=nil{return InstallerTokenEvidence{},err}

	// Read the primary token's group attributes directly. Do not call
	// CheckTokenMembership on the primary handle (which can require an
	// impersonation token) or temporarily impersonate an elevated user.
	e.AdministratorsEnabled,err=enabledInstallerAdministratorsGroup(token)
	if err!=nil{return InstallerTokenEvidence{},err}

	restricted,err:=token.IsRestricted()
	if err!=nil{return InstallerTokenEvidence{},fmt.Errorf("%w: query token restrictions: %v",ErrUnqualifiedInstallerToken,err)}
	e.Restricted=restricted
	hadRestrictions,err:=queryInstallerTokenDword(token,windows.TokenHasRestrictions)
	if err!=nil{return InstallerTokenEvidence{},err}
	e.Restricted=e.Restricted||hadRestrictions!=0
	appContainer,err:=queryInstallerTokenDword(token,nativeTokenIsAppContainer)
	if err!=nil{return InstallerTokenEvidence{},err}
	e.AppContainer=appContainer!=0
	e.Privileges,err=installerTokenPrivilegesBounded(token)
	if err!=nil{return InstallerTokenEvidence{},err}
	e.PrivilegesInspected=true

	impersonating,err=isInstallerThreadImpersonating()
	if err!=nil{return InstallerTokenEvidence{},err}
	e.ThreadImpersonating=impersonating
	return e,nil
}
