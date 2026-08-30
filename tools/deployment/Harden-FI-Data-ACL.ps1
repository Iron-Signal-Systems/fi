param(
    [switch]$ConfirmChange
)

. "$PSScriptRoot\..\scripts\Common.ps1"

$CollectorService = "FICollector"
$StateDir = "C:\ProgramData\FI\state"
$SpoolDir = "C:\ProgramData\FI\spool"

if (-not $ConfirmChange) {
    throw "This script changes FI state/spool ACLs and briefly stops FICollector. Re-run with -ConfirmChange."
}

function Invoke-FIIcaclsChange {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $Output = @(
        & icacls.exe @Arguments 2>&1 |
            ForEach-Object { $_.ToString() }
    )

    $ExitCode = $LASTEXITCODE

    $Problems = @(
        $Output |
            Select-String -Pattern `
                'Access is denied', `
                'Failed processing\s+[1-9][0-9]*\s+files?'
    )

    if ($ExitCode -ne 0 -or $Problems.Count -gt 0) {
        $Output | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }
        throw "$Description failed. icacls exit code: $ExitCode"
    }

    $Output | Select-Object -Last 5 | ForEach-Object { Write-Host $_ }
    Write-FiPass $Description
}

function Test-FIUnexpectedExplicitRootEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$AllowedAccounts
    )

    $Acl = Get-Acl -LiteralPath $Path

    $Unexpected = @(
        $Acl.Access |
            Where-Object {
                -not $_.IsInherited -and
                -not ($AllowedAccounts -icontains $_.IdentityReference.Value)
            }
    )

    return $Unexpected
}

$Collector = Get-FiServiceInfo -Name $CollectorService
$CollectorAccount = $Collector.StartName

if (-not $CollectorAccount) {
    throw "Could not determine FICollector service account."
}

$AdminOutput = (net localgroup Administrators) -join "`n"
if ($AdminOutput -match [Regex]::Escape($CollectorAccount)) {
    throw "FICollector account $CollectorAccount is a local Administrator. Refusing data-ACL hardening until the collector identity is restricted."
}

$Targets = @($StateDir, $SpoolDir)
$AllowedRootAccounts = @(
    "BUILTIN\Administrators",
    "NT AUTHORITY\SYSTEM",
    $CollectorAccount
)

Write-Host ""
Write-Host "FI Phase 1 Deployment - Harden FI State / Spool ACLs"
Write-Host ""
Write-FiInfo "FICollector account: $CollectorAccount"

foreach ($Target in $Targets) {
    if (-not (Test-Path -LiteralPath $Target)) {
        throw "Required FI directory does not exist: $Target"
    }

    Write-Host ""
    Write-FiInfo "Preflight ACL traversal: $Target"

    $Audit = Get-FiIcaclsAudit -Path $Target -Recurse

    if ($Audit.HasProblems) {
        @(
            $Audit.AccessDenied
            $Audit.FailureSummaries
        ) |
            Select-Object -First 10 |
            ForEach-Object { Write-Host "  $_" }

        throw "Preflight ACL traversal failed for $Target. No ACL changes were started. Repair inaccessible FI-owned children before hardening."
    }

    Write-FiPass "Preflight ACL traversal completed cleanly for $Target."

    $Unexpected = @(Test-FIUnexpectedExplicitRootEntry `
        -Path $Target `
        -AllowedAccounts $AllowedRootAccounts)

    if ($Unexpected.Count -gt 0) {
        Write-Host "Unexpected explicit root ACL entries:"
        $Unexpected |
            Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited -AutoSize

        throw "Refusing to overwrite unexpected explicit ACL entries on $Target. Review them first."
    }
}

$CollectorWasRunning = ((Get-Service -Name $CollectorService).Status -eq "Running")

try {
    if ($CollectorWasRunning) {
        Write-Host ""
        Write-FiInfo "Stopping FICollector while FI-owned data ACLs are normalized."
        Stop-Service -Name $CollectorService -ErrorAction Stop
        Write-FiPass "FICollector stopped."
    }

    foreach ($Target in $Targets) {
        Write-Host ""
        Write-Host "=== HARDEN $Target ==="

        # Preserve administrative and collector access on every existing child
        # before removing inherited parent rights. This prevents populated FI
        # trees from temporarily collapsing to an empty child DACL.
        Invoke-FIIcaclsChange `
            -Arguments @(
                $Target,
                "/grant:r",
                "NT AUTHORITY\SYSTEM:(OI)(CI)(F)",
                "BUILTIN\Administrators:(OI)(CI)(F)",
                "${CollectorAccount}:(OI)(CI)(M)",
                "/T",
                "/C",
                "/Q"
            ) `
            -Description "Seeded required FI ACLs across existing children under $Target."

        Invoke-FIIcaclsChange `
            -Arguments @(
                $Target,
                "/inheritance:r"
            ) `
            -Description "Removed inherited ACLs from FI-owned root $Target."

        Invoke-FIIcaclsChange `
            -Arguments @(
                $Target,
                "/grant:r",
                "NT AUTHORITY\SYSTEM:(OI)(CI)(F)",
                "BUILTIN\Administrators:(OI)(CI)(F)",
                "${CollectorAccount}:(OI)(CI)(M)"
            ) `
            -Description "Applied required root ACLs to $Target."

        $HasChildren = @(
            Get-ChildItem -LiteralPath $Target -Force -ErrorAction Stop |
                Select-Object -First 1
        ).Count -gt 0

        if ($HasChildren) {
            Invoke-FIIcaclsChange `
                -Arguments @(
                    "$Target\*",
                    "/reset",
                    "/T",
                    "/C",
                    "/Q"
                ) `
                -Description "Reset existing child DACLs to inherit from hardened root $Target."
        }
        else {
            Write-FiInfo "$Target has no children to normalize."
        }

        $FinalAudit = Get-FiIcaclsAudit -Path $Target -Recurse

        if ($FinalAudit.HasProblems) {
            @(
                $FinalAudit.AccessDenied
                $FinalAudit.FailureSummaries
            ) |
                Select-Object -First 10 |
                ForEach-Object { Write-Host "  $_" }

            throw "Post-change ACL traversal failed for $Target."
        }

        $Users = @(
            $FinalAudit.Output |
                Select-String -SimpleMatch "BUILTIN\Users"
        )

        if ($Users.Count -gt 0) {
            $Users | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
            throw "BUILTIN\Users remains in the FI-owned ACL tree at $Target."
        }

        Write-FiPass "$Target is fully traversable and has no BUILTIN\Users ACL entries."
    }
}
finally {
    if ($CollectorWasRunning) {
        Write-Host ""
        Write-FiInfo "Restarting FICollector."
        Start-Service -Name $CollectorService -ErrorAction Stop
        Start-Sleep -Seconds 3

        if ((Get-Service -Name $CollectorService).Status -eq "Running") {
            Write-FiPass "FICollector restarted."
        }
        else {
            Write-FiFail "FICollector did not return to Running state."
        }
    }
}

Write-Host ""
Write-FiPass "FI state/spool ACL hardening completed."
Write-FiInfo "Run tools\scripts\07-FileServer-Config-ACL.ps1 for read-only verification."
