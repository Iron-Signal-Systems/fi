param()

. "$PSScriptRoot\..\Common.ps1"

$ConfigDir = "C:\ProgramData\FI\config"
$ConfigFile = "C:\ProgramData\FI\config\fi.conf"
$StateDir = "C:\ProgramData\FI\state"
$SpoolDir = "C:\ProgramData\FI\spool"

Write-Host ""
Write-Host "FI USN Verification - Test 07: Config / State / Spool ACL Boundary"
Write-Host "Run on the FILE SERVER in elevated Windows PowerShell."
Write-Host "This test is read-only."
Write-Host ""

$Collector = Get-FiServiceInfo -Name "FICollector"
$Helper = Get-FiServiceInfo -Name "FIUSNReader"
$Failures = 0

$ConfigDangerousMask = `
    [System.Security.AccessControl.FileSystemRights]::Write -bor `
    [System.Security.AccessControl.FileSystemRights]::Delete -bor `
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor `
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

function Test-FIAllowedIdentitySet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string[]]$AllowedAccounts,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $Acl = Get-Acl -LiteralPath $Target

    $Unexpected = @(
        $Acl.Access |
            Where-Object {
                -not ($AllowedAccounts -icontains $_.IdentityReference.Value) -or
                $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow
            }
    )

    if ($Unexpected.Count -gt 0) {
        Write-FiFail "$Label has unexpected ACL entries on $Target."
        $Unexpected |
            Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited -AutoSize
        return $false
    }

    Write-FiPass "$Label contains only the intended ACL principals on $Target."
    return $true
}

function Test-FIConfigDirectoryReadOnlyEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Account,

        [Parameter(Mandatory = $true)]
        [string]$Role
    )

    $Acl = Get-Acl -LiteralPath $Target
    $Rules = @(
        $Acl.Access |
            Where-Object {
                $_.IdentityReference.Value -ieq $Account -and
                -not $_.IsInherited -and
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
            }
    )

    if ($Rules.Count -eq 0) {
        Write-FiFail "$Role account $Account has no explicit Allow ACL entry on $Target."
        return $false
    }

    foreach ($Rule in $Rules) {
        if (($Rule.FileSystemRights -band $ConfigDangerousMask) -ne 0) {
            Write-FiFail "$Role account $Account has an explicit write/modify/administrative Allow entry on $Target."
            return $false
        }
    }

    Write-FiPass "$Role account $Account has only explicit non-write Allow access on $Target."
    return $true
}

function Test-FIConfigFileReadOnlyEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Account,

        [Parameter(Mandatory = $true)]
        [string]$Role
    )

    $Acl = Get-Acl -LiteralPath $Target
    $Rules = @(
        $Acl.Access |
            Where-Object {
                $_.IdentityReference.Value -ieq $Account -and
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
            }
    )

    if ($Rules.Count -eq 0) {
        Write-FiFail "$Role account $Account has no effective Allow ACL entry on $Target."
        return $false
    }

    foreach ($Rule in $Rules) {
        if (($Rule.FileSystemRights -band $ConfigDangerousMask) -ne 0) {
            Write-FiFail "$Role account $Account has effective write/modify/administrative Allow access on $Target."
            return $false
        }
    }

    $Inherited = @($Rules | Where-Object { $_.IsInherited })
    $Explicit = @($Rules | Where-Object { -not $_.IsInherited })

    if ($Explicit.Count -gt 0 -and $Inherited.Count -gt 0) {
        Write-FiPass "$Role account $Account has non-write Allow access on $Target through explicit and inherited ACEs."
    }
    elseif ($Explicit.Count -gt 0) {
        Write-FiPass "$Role account $Account has explicit non-write Allow access on $Target."
    }
    else {
        Write-FiPass "$Role account $Account has inherited non-write Allow access on $Target from the hardened config directory."
    }

    return $true
}

function Test-FICollectorDataEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Account
    )

    $Acl = Get-Acl -LiteralPath $Target
    $Rules = @(
        $Acl.Access |
            Where-Object {
                $_.IdentityReference.Value -ieq $Account -and
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
            }
    )

    if ($Rules.Count -eq 0) {
        Write-FiFail "FICollector account $Account has no Allow ACL entry on $Target."
        return $false
    }

    $HasModify = $false

    foreach ($Rule in $Rules) {
        if (($Rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -eq
            [System.Security.AccessControl.FileSystemRights]::Modify) {
            $HasModify = $true
        }

        if (($Rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ChangePermissions) -ne 0 -or
            ($Rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::TakeOwnership) -ne 0) {
            Write-FiFail "FICollector account $Account has ACL-administration rights on $Target."
            return $false
        }
    }

    if (-not $HasModify) {
        Write-FiFail "FICollector account $Account does not have the required Modify access on $Target."
        return $false
    }

    Write-FiPass "FICollector account $Account has Modify without ACL-administration rights on $Target."
    return $true
}

function Test-FIFullControlEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Account,

        [Parameter(Mandatory = $true)]
        [string]$Role
    )

    $Acl = Get-Acl -LiteralPath $Target
    $Rules = @(
        $Acl.Access |
            Where-Object {
                $_.IdentityReference.Value -ieq $Account -and
                $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
            }
    )

    foreach ($Rule in $Rules) {
        if (($Rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
            [System.Security.AccessControl.FileSystemRights]::FullControl) {
            Write-FiPass "$Role has FullControl on $Target."
            return $true
        }
    }

    Write-FiFail "$Role does not have FullControl on $Target."
    return $false
}

function Test-FINoDirectAccountEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Account,

        [Parameter(Mandatory = $true)]
        [string]$Role
    )

    $Acl = Get-Acl -LiteralPath $Target
    $Rules = @(
        $Acl.Access |
            Where-Object {
                $_.IdentityReference.Value -ieq $Account
            }
    )

    if ($Rules.Count -gt 0) {
        Write-FiFail "$Role account $Account has a direct ACL entry on $Target."
        return $false
    }

    Write-FiPass "$Role account $Account has no direct ACL entry on $Target."
    return $true
}

function Test-FITreeAudit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $Audit = Get-FiIcaclsAudit -Path $Target -Recurse

    Write-FiInfo "$Label icacls exit code: $($Audit.ExitCode)"
    Write-FiInfo "$Label access-denied lines: $($Audit.AccessDenied.Count)"
    Write-FiInfo "$Label failure summaries: $($Audit.FailureSummaries.Count)"

    if ($Audit.HasProblems) {
        Write-FiFail "$Label ACL traversal did not complete cleanly."

        @(
            $Audit.AccessDenied
            $Audit.FailureSummaries
        ) |
            Select-Object -First 10 |
            ForEach-Object { Write-Host "  $_" }

        return $false
    }

    $Users = @(
        $Audit.Output |
            Select-String -SimpleMatch "BUILTIN\Users"
    )

    if ($Users.Count -gt 0) {
        Write-FiFail "$Label contains BUILTIN\Users ACL entries."
        $Users | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
        return $false
    }

    Write-FiPass "$Label is fully traversable and contains no BUILTIN\Users ACL entries."
    return $true
}

Write-Host "=== CONFIG ACLS ==="

$ConfigDirAudit = Get-FiIcaclsAudit -Path $ConfigDir
$ConfigFileAudit = Get-FiIcaclsAudit -Path $ConfigFile

$ConfigDirAudit.Output | ForEach-Object { Write-Host $_ }
$ConfigFileAudit.Output | ForEach-Object { Write-Host $_ }

if ($ConfigDirAudit.HasProblems -or $ConfigFileAudit.HasProblems) {
    Write-FiFail "FI config ACL inspection did not complete cleanly."
    $Failures++
}
else {
    Write-FiPass "FI config ACL inspection completed without access failures."
}

$ConfigCombined = @(
    $ConfigDirAudit.Output
    $ConfigFileAudit.Output
) -join "`n"

if ($ConfigCombined -match 'BUILTIN\\Users') {
    Write-FiFail "BUILTIN\Users is present in FI config ACLs."
    $Failures++
}
else {
    Write-FiPass "BUILTIN\Users is absent from FI config ACLs."
}

$ConfigAllowedAccounts = @(
    "BUILTIN\Administrators",
    "NT AUTHORITY\SYSTEM",
    $Collector.StartName,
    $Helper.StartName
)

if (-not (Test-FIAllowedIdentitySet `
    -Target $ConfigDir `
    -AllowedAccounts $ConfigAllowedAccounts `
    -Label "FI config")) {
    $Failures++
}

if (-not (Test-FIConfigDirectoryReadOnlyEntry `
    -Target $ConfigDir `
    -Account $Collector.StartName `
    -Role "FICollector")) {
    $Failures++
}

if (-not (Test-FIConfigDirectoryReadOnlyEntry `
    -Target $ConfigDir `
    -Account $Helper.StartName `
    -Role "FIUSNReader")) {
    $Failures++
}

if (-not (Test-FIAllowedIdentitySet `
    -Target $ConfigFile `
    -AllowedAccounts $ConfigAllowedAccounts `
    -Label "FI config")) {
    $Failures++
}

if (-not (Test-FIConfigFileReadOnlyEntry `
    -Target $ConfigFile `
    -Account $Collector.StartName `
    -Role "FICollector")) {
    $Failures++
}

if (-not (Test-FIConfigFileReadOnlyEntry `
    -Target $ConfigFile `
    -Account $Helper.StartName `
    -Role "FIUSNReader")) {
    $Failures++
}

Write-Host ""
Write-Host "=== STATE / SPOOL ACLS ==="

$DataAllowedAccounts = @(
    "BUILTIN\Administrators",
    "NT AUTHORITY\SYSTEM",
    $Collector.StartName
)

foreach ($Target in @($StateDir, $SpoolDir)) {
    Write-Host ""
    icacls.exe $Target

    if (-not (Test-FIAllowedIdentitySet `
        -Target $Target `
        -AllowedAccounts $DataAllowedAccounts `
        -Label "FI data root")) {
        $Failures++
    }

    if (-not (Test-FICollectorDataEntry -Target $Target -Account $Collector.StartName)) {
        $Failures++
    }

    if (-not (Test-FIFullControlEntry `
        -Target $Target `
        -Account "BUILTIN\Administrators" `
        -Role "BUILTIN\Administrators")) {
        $Failures++
    }

    if (-not (Test-FIFullControlEntry `
        -Target $Target `
        -Account "NT AUTHORITY\SYSTEM" `
        -Role "SYSTEM")) {
        $Failures++
    }

    if (-not (Test-FINoDirectAccountEntry `
        -Target $Target `
        -Account $Helper.StartName `
        -Role "FIUSNReader")) {
        $Failures++
    }
}

if (-not (Test-FITreeAudit -Target $StateDir -Label "FI state")) {
    $Failures++
}

if (-not (Test-FITreeAudit -Target $SpoolDir -Label "FI spool")) {
    $Failures++
}

Write-Host ""
Write-Host "=== IDENTITY BOUNDARY ==="

$AdminOutput = (net localgroup Administrators) -join "`n"

if ($AdminOutput -match [Regex]::Escape($Collector.StartName)) {
    Write-FiFail "FICollector account $($Collector.StartName) is a local Administrator."
    $Failures++
}
else {
    Write-FiPass "FICollector account $($Collector.StartName) is not a local Administrator."
}

if ($AdminOutput -match [Regex]::Escape($Helper.StartName)) {
    Write-FiPass "FIUSNReader account $($Helper.StartName) is a local Administrator as required by the validated Windows Server USN design."
}
else {
    Write-FiFail "FIUSNReader account $($Helper.StartName) is not a local Administrator."
    $Failures++
}

$CollectorManaged = (sc.exe qmanagedaccount FICollector) -join "`n"
if ($CollectorManaged -match 'ACCOUNT MANAGED\s*:\s*TRUE') {
    Write-FiPass "FICollector is configured as a managed account."
}
else {
    Write-FiFail "FICollector is not configured as a managed account."
    $Failures++
}

$HelperManaged = (sc.exe qmanagedaccount FIUSNReader) -join "`n"
if ($HelperManaged -match 'ACCOUNT MANAGED\s*:\s*TRUE') {
    Write-FiPass "FIUSNReader is configured as a managed account."
}
else {
    Write-FiFail "FIUSNReader is not configured as a managed account."
    $Failures++
}

$SidType = (sc.exe qsidtype FICollector) -join "`n"
if ($SidType -match 'SERVICE_SID_TYPE:\s+UNRESTRICTED') {
    Write-FiPass "FICollector service SID type is UNRESTRICTED."
}
else {
    Write-FiFail "FICollector service SID type is not UNRESTRICTED."
    $Failures++
}

Write-Host ""
Write-Host "NOTE:"
Write-Host "  FI config is hardened at the directory boundary. Child config files may"
Write-Host "  inherit the intended non-write ACEs from that directory; duplicate explicit"
Write-Host "  ACEs on each child are not required. Test 07 validates the effective child"
Write-Host "  permissions and the allowed principal set instead."
Write-Host ""
Write-Host "  FIUSNReader is intentionally a local Administrator on this host."
Write-Host "  Its FI config access is read-only, but local Administrator membership means"
Write-Host "  the config ACL is not a security boundary against compromise of the helper."
Write-Host "  FIUSNReader has no direct FI state/spool ACE because normal checkpoint and"
Write-Host "  durable spool ownership remains with FICollector."
Write-Host ""

if ($Failures -eq 0) {
    Write-FiPass "TEST 07 PASSED."
    exit 0
}

Write-FiFail "TEST 07 FAILED with $Failures problem(s)."
exit 1
