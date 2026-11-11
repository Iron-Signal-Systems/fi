// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const nativeParentFileIDInfoClass = 18 // GetFileInformationByHandleEx(FileIdInfo)
var (
	nativeParentFileIDProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetFileInformationByHandleEx")
	nativeParentVolumeInfoProc = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetVolumeInformationW")
)

// Windows FILE_ID_INFO is exactly 8-byte volume serial + 16-byte FileID.
var (
	_ [24 - unsafe.Sizeof(SystemDirectoryID{})]byte
	_ [unsafe.Sizeof(SystemDirectoryID{}) - 24]byte
)

// nativeSystemDirectory preserves the LIVE handle and the identity seen when
// the object was first opened. Neither the original path nor its present
// existence is a trusted issuer; all reads are read-only and never mutate ACLs.
type nativeSystemDirectory struct {
	path string
	nativePath string
	id SystemDirectoryID
	handle windows.Handle
}

type nativeSystemParentInspection struct {
	root nativeSystemDirectory
	programData nativeSystemDirectory
	windowsDir nativeSystemDirectory
	closed bool
}

// Close releases retained read-only handles. Inspection NEVER removes,
// creates or repairs any directory, and cannot serve as installer authority.
func (p *nativeSystemParentInspection) Close() error {
	if p==nil || p.closed {return nil}
	p.closed=true
	var errs []error
	for _,h:=range []windows.Handle{p.programData.handle,p.windowsDir.handle,p.root.handle}{
		if h!=0 && h!=windows.InvalidHandle {errs=append(errs,windows.CloseHandle(h))}
	}
	p.root.handle,p.programData.handle,p.windowsDir.handle=0,0,0
	return errors.Join(errs...)
}

func openNativeSystemDirectory(path string) (nativeSystemDirectory,error) {
	// Live system-origin observations never permit delete-sharing.
	return openNativeSystemDirectoryWithSharing(path,windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
}

// The explicit share variant is private and is used only by native fixture
// tests that intentionally allow a disposable directory to be relocated.
// It cannot authorize a service, installation or privileged journal read.
func openNativeSystemDirectoryWithSharing(path string,share uint32) (nativeSystemDirectory,error) {
	if !validSystemPath(path) {
		return nativeSystemDirectory{},fmt.Errorf("%w: invalid absolute local drive path",ErrUnattestedSystemParent)
	}
	ptr,err:=windows.UTF16PtrFromString(path)
	if err!=nil{return nativeSystemDirectory{},err}
	h,err:=windows.CreateFile(ptr,windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		share,
		nil,windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,0)
	if err!=nil{return nativeSystemDirectory{},fmt.Errorf("%w: open read-only system directory %q: %v",ErrUnattestedSystemParent,path,err)}
	ok:=false
	defer func(){if !ok {_=windows.CloseHandle(h)}}()
	if err:=requireNativeHandleType(h,true);err!=nil{
		return nativeSystemDirectory{},fmt.Errorf("%w: non-directory/reparse system object: %v",ErrUnattestedSystemParent,err)
	}
	native,err:=nativeFinalPath(h)
	if err!=nil||native==""{return nativeSystemDirectory{},fmt.Errorf("%w: resolve system directory native name: %v",ErrUnattestedSystemParent,err)}
	id,err:=systemDirectoryIDFromHandle(h)
	if err!=nil{return nativeSystemDirectory{},err}
	out:=nativeSystemDirectory{path:path,nativePath:native,id:id,handle:h}
	ok=true
	return out,nil
}

func systemDirectoryIDFromHandle(h windows.Handle) (SystemDirectoryID,error) {
	if h==0 || h==windows.InvalidHandle {
		return SystemDirectoryID{},fmt.Errorf("%w: no valid native directory handle",ErrUnattestedSystemParent)
	}
	var id SystemDirectoryID
	r,_,callErr:=nativeParentFileIDProc.Call(uintptr(h),nativeParentFileIDInfoClass,
		uintptr(unsafe.Pointer(&id)),unsafe.Sizeof(id))
	if r==0 || !validDirectoryID(id) {
		return SystemDirectoryID{},fmt.Errorf("%w: missing full-width FILE_ID_INFO: %v",ErrUnattestedSystemParent,callErr)
	}
	return id,nil
}

// verifyObservedSystemDirectory prevents a stale Windows path from being
// silently reinterpreted as an original observed directory after a rename,
// replacement, reparse substitution or identity change. This method is
// deliberately read-only and usable by native disposable fixture tests.
func verifyObservedSystemDirectory(obs nativeSystemDirectory) error {
	if obs.handle==0 || obs.handle==windows.InvalidHandle {
		return fmt.Errorf("%w: retained system directory handle missing",ErrUnattestedSystemParent)
	}
	if err:=requireNativeHandleType(obs.handle,true);err!=nil {
		return fmt.Errorf("%w: retained system directory changed type: %v",ErrUnattestedSystemParent,err)
	}
	actualID,err:=systemDirectoryIDFromHandle(obs.handle)
	if err!=nil{return err}
	if actualID!=obs.id {
		return fmt.Errorf("%w: original retained directory identity changed",ErrUnattestedSystemParent)
	}
	now,err:=nativeFinalPath(obs.handle)
	if err!=nil || !sameNativePath(now,obs.nativePath){
		return fmt.Errorf("%w: retained native system directory relocated: %v",ErrUnattestedSystemParent,err)
	}
	reopened,err:=openNativeSystemDirectory(obs.path)
	if err!=nil{return err}
	same:=reopened.id==obs.id && sameNativePath(reopened.nativePath,obs.nativePath)
	_ = windows.CloseHandle(reopened.handle)
	if !same {return fmt.Errorf("%w: system directory path now resolves to a different object",ErrUnattestedSystemParent)}
	return nil
}

// requireNativeSystemNTFS checks the actual filesystem at the original
// system volume root. FILE_ID_INFO on a non-NTFS filesystem is not an
// acceptable basis for FI's NTFS-only privileged installation model.
func requireNativeSystemNTFS(root string) error {
	ptr,err:=windows.UTF16PtrFromString(root)
	if err!=nil {return fmt.Errorf("%w: encode OS system volume root: %v",ErrUnattestedSystemParent,err)}
	var fsName [32]uint16
	ok,_,callErr:=nativeParentVolumeInfoProc.Call(
		uintptr(unsafe.Pointer(ptr)),0,0,0,0,0,
		uintptr(unsafe.Pointer(&fsName[0])),uintptr(len(fsName)),
	)
	if ok==0 || !strings.EqualFold(windows.UTF16ToString(fsName[:]),"NTFS") {
		return fmt.Errorf("%w: OS system volume is not attested as NTFS: %v",ErrUnattestedSystemParent,callErr)
	}
	return nil
}

// inspectNativeSystemProgramData observes independently reported common
// ProgramData and system Windows directories from native Windows APIs.
// The known-folder query has flags=0: NEVER request KF_FLAG_CREATE.
// It then retains live read-only root, Windows, and ProgramData handles and
// verifies their native FILE_ID_INFO and direct-child relationships.
//
// The result is diagnostic identity evidence only. An admin/malicious actor
// may alter known-folder registry state, directory ACLs or the host itself.
// No real installation or service can use this result as a grant.
func inspectNativeSystemProgramData() (p *nativeSystemParentInspection,err error) {
	pd,err:=windows.KnownFolderPath(windows.FOLDERID_ProgramData,0)
	if err!=nil {return nil,fmt.Errorf("%w: query system ProgramData known-folder: %v",ErrUnattestedSystemParent,err)}
	win,err:=windows.GetSystemWindowsDirectory()
	if err!=nil {return nil,fmt.Errorf("%w: query shared system Windows directory: %v",ErrUnattestedSystemParent,err)}
	if !validSystemPath(win) || !validSystemPath(pd) {
		return nil,fmt.Errorf("%w: OS returned noncanonical native system paths",ErrUnattestedSystemParent)
	}
	rootPath:=filepath.VolumeName(win)+`\`
	if err:=requireNativeSystemNTFS(rootPath);err!=nil{return nil,err}
	// Check the OS-reported layout BEFORE opening any handles; actual
	// full-width IDs are obtained from the live native objects below.
	if err:=validateSystemParentLayout(pd,win,rootPath);err!=nil{return nil,err}
	p=&nativeSystemParentInspection{}
	success:=false
	defer func(){
		if !success {err=errors.Join(err,p.Close());p=nil}
	}()
	if p.root,err=openNativeSystemDirectory(rootPath);err!=nil{return p,err}
	if p.windowsDir,err=openNativeSystemDirectory(win);err!=nil{return p,err}
	if p.programData,err=openNativeSystemDirectory(pd);err!=nil{return p,err}
	if err=p.verifyRetained();err!=nil{return p,err}
	success=true
	return p,nil
}

func (p *nativeSystemParentInspection) Evidence() SystemParentEvidence {
	if p==nil {return SystemParentEvidence{}}
	return SystemParentEvidence{
		KnownProgramData:p.programData.path,SystemWindows:p.windowsDir.path,
		RootPath:p.root.path,RootID:p.root.id,
		ProgramDataID:p.programData.id,WindowsID:p.windowsDir.id,
	}
}

// verifyRetained rechecks path identity and full-width FILE_ID_INFO for all
// three retained handles AND independently reopens each OS path. This detects
// directory replacement/rename after observation, but like any separate
// filesystem queries cannot make the original OS path or ancestor chain an
// atomic, authenticated host trust anchor.
func (p *nativeSystemParentInspection) verifyRetained() error {
	if p==nil || p.closed {return ErrUnattestedSystemParent}
	if err:=AssessSystemParentEvidence(p.Evidence());err!=nil{return err}
	// The current system API mappings can change after first observation.
	// Even if the original object still exists at its old path, a changed
	// mapping must fail closed rather than being silently retained.
	currentPD,err:=windows.KnownFolderPath(windows.FOLDERID_ProgramData,0)
	if err!=nil || !strings.EqualFold(currentPD,p.programData.path) {
		return fmt.Errorf("%w: OS ProgramData known-folder mapping changed: %v",ErrUnattestedSystemParent,err)
	}
	currentWindows,err:=windows.GetSystemWindowsDirectory()
	if err!=nil || !strings.EqualFold(currentWindows,p.windowsDir.path) {
		return fmt.Errorf("%w: OS system Windows directory mapping changed: %v",ErrUnattestedSystemParent,err)
	}
	if err:=requireNativeSystemNTFS(p.root.path);err!=nil{return err}
	objects:=[]nativeSystemDirectory{p.root,p.windowsDir,p.programData}
	for _,obs:=range objects {
		if err:=verifyObservedSystemDirectory(obs);err!=nil{return err}
	}
	if !sameNativePath(filepath.Dir(p.programData.nativePath),p.root.nativePath) ||
		!sameNativePath(filepath.Dir(p.windowsDir.nativePath),p.root.nativePath) ||
		!strings.EqualFold(filepath.Base(p.programData.nativePath),"ProgramData"){
		return fmt.Errorf("%w: native directory relationship is not a direct system-root child",ErrUnattestedSystemParent)
	}
	// A later service/installer must still authenticate the actual trusted
	// OS root, owner/ACL and actor independently. This private function does
	// not enable any installation mutation.
	return nil
}
