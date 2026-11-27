//go:build !windows

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package c1handoff

import (
    "os"
    "syscall"
)
func openC1RAMExclusive(path string)(*os.File,error){
    return os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,0600)
}
func openC1RAMReadOnly(path string)(*os.File,error){
    return os.OpenFile(path,os.O_RDONLY|syscall.O_NOFOLLOW,0)
}
