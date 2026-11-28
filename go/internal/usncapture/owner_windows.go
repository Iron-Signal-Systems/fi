// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usncapture

import (
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "syscall"
    "unsafe"
)

const (
    captureOwnerLockExclusive = 0x00000002
    captureOwnerLockNonblocking = 0x00000001
    captureOwnerFile = "capture-owner.lock"
)

var captureOwnerKernel32 = syscall.NewLazyDLL("kernel32.dll")
var captureOwnerLockFileEx = captureOwnerKernel32.NewProc("LockFileEx")
var captureOwnerUnlockFileEx = captureOwnerKernel32.NewProc("UnlockFileEx")

// CaptureOwner is the machine-local cross-process source-capture guard.
// Hold ONE instance for the full lifetime of a volume's capture and
// processing workers; a second collector must fail rather than corrupting
// independent capture/processed cursor files. The queue itself is still
// guarded by its in-process mutex.
type CaptureOwner struct {
    file *os.File
    overlapped syscall.Overlapped
}

func AcquireCaptureOwner(dir string) (io.Closer,error) {
    if !filepath.IsAbs(dir) || filepath.Clean(dir)=="."{
        return nil,errors.New("FI USN capture owner requires absolute directory")
    }
    info,err:=os.Lstat(dir)
    if err!=nil{return nil,err}
    if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{
        return nil,errors.New("FI USN capture owner requires real queue directory")
    }
    path:=filepath.Join(dir,captureOwnerFile)
    file,err:=os.OpenFile(path,os.O_CREATE|os.O_RDWR,0600)
    if err!=nil{return nil,err}
    owner:=&CaptureOwner{file:file}
    status,_,callErr:=captureOwnerLockFileEx.Call(file.Fd(),
        uintptr(captureOwnerLockExclusive|captureOwnerLockNonblocking),
        0,1,0,uintptr(unsafe.Pointer(&owner.overlapped)))
    if status==0{
        _=file.Close()
        if callErr!=nil&&callErr!=syscall.Errno(0){
            return nil,fmt.Errorf("FI USN volume already owned or lock failed: %w",callErr)
        }
        return nil,errors.New("FI USN volume capture owner lock unavailable")
    }
    return owner,nil
}

func (owner *CaptureOwner) Close() error {
    if owner==nil||owner.file==nil{return nil}
    status,_,callErr:=captureOwnerUnlockFileEx.Call(owner.file.Fd(),0,1,0,
        uintptr(unsafe.Pointer(&owner.overlapped)))
    var unlockErr error
    if status==0{
        if callErr!=nil&&callErr!=syscall.Errno(0){
            unlockErr=fmt.Errorf("unlock FI USN volume capture owner: %w",callErr)
        }else{
            unlockErr=errors.New("FI USN volume capture owner unlock failed")
        }
    }
    err:=owner.file.Close()
    owner.file=nil
    return errors.Join(unlockErr,err)
}
