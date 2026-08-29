param()

. "$PSScriptRoot\Common.ps1"

Write-Host ""
Write-Host "FI USN Verification - Test 03: Local Runtime Authorization"
Write-Host "Run on the FILE SERVER from an ordinary elevated administrator PowerShell."
Write-Host ""
Write-Host "Expected: pipe connection succeeds, request is denied because this process"
Write-Host "does not carry the NT SERVICE\FICollector service SID."
Write-Host ""

function Read-Exact {
    param(
        [System.IO.Stream]$Stream,
        [int]$Count
    )

    $Buffer = New-Object byte[] $Count
    $Offset = 0

    while ($Offset -lt $Count) {
        $Read = $Stream.Read($Buffer, $Offset, $Count - $Offset)

        if ($Read -eq 0) {
            throw "Pipe closed before $Count bytes were received."
        }

        $Offset += $Read
    }

    return ,$Buffer
}

$Roots = @(Get-FiConfiguredRoots)
if ($Roots.Count -eq 0) {
    throw "No governed root is configured."
}
$GovernedRoot = $Roots[0]

$Pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
    ".",
    "FI-USN",
    [System.IO.Pipes.PipeDirection]::InOut,
    [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Impersonation
)

try {
    $Pipe.Connect(3000)

    if (-not $Pipe.IsConnected) {
        Write-FiFail "Could not connect to local FI-USN pipe."
        exit 1
    }

    Write-FiPass "Local administrator process connected to the pipe."

    $UTF8 = New-Object System.Text.UTF8Encoding($false)
    $RootBytes = $UTF8.GetBytes($GovernedRoot)

    $RequestStream = New-Object System.IO.MemoryStream
    $Writer = New-Object System.IO.BinaryWriter($RequestStream)

    $Writer.Write([byte[]](0x46,0x49,0x55,0x51)) # FIUQ
    $Writer.Write([UInt16]1)                     # protocol version
    $Writer.Write([UInt16]1)                     # QueryJournal
    $Writer.Write([UInt32]$RootBytes.Length)
    $Writer.Write([UInt64]0)
    $Writer.Write([UInt32]0)
    $Writer.Write($RootBytes)
    $Writer.Flush()

    $Request = $RequestStream.ToArray()
    $Pipe.Write($Request, 0, $Request.Length)
    $Pipe.Flush()

    $Header = Read-Exact $Pipe 76

    $Magic       = [Text.Encoding]::ASCII.GetString($Header, 0, 4)
    $Version     = [BitConverter]::ToUInt16($Header, 4)
    $Status      = [BitConverter]::ToUInt16($Header, 6)
    $ErrorCode   = [BitConverter]::ToUInt32($Header, 8)
    $DataLength  = [BitConverter]::ToUInt32($Header, 68)
    $ErrorLength = [BitConverter]::ToUInt32($Header, 72)

    if ($DataLength -gt 0) {
        $null = Read-Exact $Pipe $DataLength
    }

    $ErrorText = ""
    if ($ErrorLength -gt 0) {
        $ErrorBytes = Read-Exact $Pipe $ErrorLength
        $ErrorText = $UTF8.GetString($ErrorBytes)
    }

    Write-FiInfo "ResponseMagic: $Magic"
    Write-FiInfo "ProtocolVersion: $Version"
    Write-FiInfo "Status: $Status"
    Write-FiInfo "ErrorCode: $ErrorCode"
    Write-FiInfo "DataLength: $DataLength"
    Write-FiInfo "Error: $ErrorText"

    if (
        $Magic -eq "FIUR" -and
        $Version -eq 1 -and
        $Status -eq 1 -and
        $ErrorCode -eq 5 -and
        $DataLength -eq 0 -and
        $ErrorText -eq "FICollector service SID is required"
    ) {
        Write-FiPass "Ordinary local administrator was rejected by runtime service-SID authorization."
    }
    else {
        Write-FiFail "Helper returned an unexpected authorization result."
        exit 1
    }
}
finally {
    $Pipe.Dispose()
}

if (-not (Test-FiServiceRunning -Name "FICollector")) {
    Write-FiFail "FICollector is not running after the rejected request."
    exit 1
}

if (-not (Test-FiServiceRunning -Name "FIUSNReader")) {
    Write-FiFail "FIUSNReader is not running after the rejected request."
    exit 1
}

Write-FiPass "Both FI services remained running."
Write-FiPass "TEST 03 PASSED."
exit 0
