//go:build windows

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The shared RAM transport exists ONLY between FreeBSD/Linux development
// jails. Do not turn off no-follow security when compiling Windows code.
package c1handoff

import (
    "errors"
    "os"
)
func openC1RAMExclusive(string)(*os.File,error){
    return nil,errors.New("C1 RAM: FreeBSD-only shared jail transport")
}
func openC1RAMReadOnly(string)(*os.File,error){
    return nil,errors.New("C1 RAM: FreeBSD-only shared jail transport")
}
