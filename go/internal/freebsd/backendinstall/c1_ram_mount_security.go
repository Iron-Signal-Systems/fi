// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package backendinstall

import (
    "errors"
    "fmt"
    "os"
)

// FreeBSD sys/mount.h flags, deliberately not Linux mount option values.
const c1FreeBSDNoExec uint64=0x00000004
const c1FreeBSDNoSuid uint64=0x00000008

// ValidateC1RAMMountSecurity protects the shared volatile P5/P6 objects
// from an accidentally world-readable/writable or executable host tmpfs.
// It is pure, so CI can test it without mounting anything.
func ValidateC1RAMMountSecurity(flags uint64,mode os.FileMode,
    actualUID,actualGID,requiredUID,requiredGID uint32)error{
    if requiredUID<1000||requiredUID>32000||
        requiredGID<1000||requiredGID>32000{
        return errors.New("FI C1 RAM: original runtime UID/GID required")
    }
    if actualUID!=requiredUID||actualGID!=requiredGID{
        return fmt.Errorf("FI C1 RAM: host tmpfs numeric ownership UID=%d GID=%d expected UID=%d GID=%d",
            actualUID,actualGID,requiredUID,requiredGID)
    }
    if !mode.IsDir()||mode.Perm()!=0770{
        return errors.New("FI C1 RAM: tmpfs root must be a group-restricted mode 0770 directory")
    }
    if flags&c1FreeBSDNoExec==0||flags&c1FreeBSDNoSuid==0{
        return errors.New("FI C1 RAM: host tmpfs must have noexec,nosuid mount flags")
    }
    return nil
}
