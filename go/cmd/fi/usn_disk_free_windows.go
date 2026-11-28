// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "errors"
    "fmt"
    "path/filepath"
    "syscall"
    "unsafe"
)

// Windows reports bytes available to THIS FI collector security token, not
// system-wide nominal free space. A failed query must never be interpreted
// as unlimited capacity.
var sourceFreeSpaceProc = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")
func volumeSourceAvailableFreeBytes(path string)(uint64,error){
    if !filepath.IsAbs(path){return 0,errors.New("FI source disk probe requires absolute path")}
    name,err:=syscall.UTF16PtrFromString(path)
    if err!=nil{return 0,err}
    var available uint64
    ok,_,callErr:=sourceFreeSpaceProc.Call(
        uintptr(unsafe.Pointer(name)),
        uintptr(unsafe.Pointer(&available)),0,0,
    )
    if ok==0{
        return 0,fmt.Errorf("GetDiskFreeSpaceExW: %w",callErr)
    }
    return available,nil
}
