// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package backendinstall

import (
    "errors"
    "fmt"
)

// ValidateC1RAMFilesystemSize accepts the actual FreeBSD statfs capacity,
// not the fstab text. Reject unbounded tmpfs and undersized transports
// before either FI jail can start ingesting original signed records.
func ValidateC1RAMFilesystemSize(blocks,blockSize uint64)error{
    const min uint64=2<<30
    const max uint64=4<<30
    if blocks==0||blockSize==0||blockSize>max||
        blocks>max/blockSize{
        return errors.New("FI C1 RAM: tmpfs unbounded, zero or greater than 4 GiB")
    }
    size:=blocks*blockSize
    if size<min{
        return fmt.Errorf("FI C1 RAM: tmpfs capacity %d is below 2 GiB credit allowance",size)
    }
    return nil
}
