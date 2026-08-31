# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

@{
    Version = '1.0'

    Collectors = @(
        @{
            Host          = 'ISS-FS-01'
            CollectorGMSA = 'gFI-FS01'
            USNGMSA       = 'gFI-USN-FS01'
        },
        @{
            Host          = 'ISS-FS-02'
            CollectorGMSA = 'gFI-FS02'
            USNGMSA       = 'gFI-USN-FS02'
        }
    )
}
