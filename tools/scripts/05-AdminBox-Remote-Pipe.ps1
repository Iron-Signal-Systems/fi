# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

param(
    [Parameter(Mandatory=$true)]
    [string]$FileServer
)

Write-Host ""
Write-Host "FI USN Verification - Test 05: Remote Pipe Rejection"
Write-Host "Run from a SEPARATE ADMIN BOX, not on the FI file server."
Write-Host ""
Write-Host "Target file server: $FileServer"
Write-Host ""

$Pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
    $FileServer,
    "FI-USN",
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Impersonation
)

try {
    $Pipe.Connect(3000)

    if ($Pipe.IsConnected) {
        Write-Host "[FAIL] Remote connection unexpectedly succeeded."
        exit 1
    }
}
catch {
    Write-Host "[PASS] Remote pipe connection was rejected."
    Write-Host "[INFO] Windows error: $($_.Exception.Message)"
    exit 0
}
finally {
    $Pipe.Dispose()
}

Write-Host "[FAIL] Remote pipe test ended without an expected rejection."
exit 1
