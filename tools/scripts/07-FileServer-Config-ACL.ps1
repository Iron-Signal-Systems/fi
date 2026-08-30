param()

. "$PSScriptRoot\Common.ps1"

$ConfigDir = "C:\ProgramData\FI\config"
$ConfigFile = "C:\ProgramData\FI\config\fi.conf"

Write-Host ""
Write-Host "FI USN Verification - Test 07: Config ACL Boundary Verification"
Write-Host "Run on the FILE SERVER in elevated Windows PowerShell."
Write-Host ""

$Collector = Get-FiServiceInfo -Name "FICollector"
$Helper = Get-FiServiceInfo -Name "FIUSNReader"

$DirAclText = (icacls $ConfigDir) -join "`n"
$FileAclText = (icacls $ConfigFile) -join "`n"
$Combined = $DirAclText + "`n" + $FileAclText

Write-Host $DirAclText
Write-Host $FileAclText
Write-Host ""

$Failures = 0

if ($Combined -match 'BUILTIN\\Users') {
    Write-FiFail "BUILTIN\Users is present in FI config ACLs."
    $Failures++
}
else {
    Write-FiPass "BUILTIN\Users is absent from FI config ACLs."
}

$DangerousMask = `
    [System.Security.AccessControl.FileSystemRights]::Write -bor `
    [System.Security.AccessControl.FileSystemRights]::Modify -bor `
    [System.Security.AccessControl.FileSystemRights]::FullControl -bor `
    [System.Security.AccessControl.FileSystemRights]::Delete -bor `
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor `
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

function Test-FIExplicitReadOnlyEntry {
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
        Write-FiFail "$Role account $Account has no explicit Allow ACL entry on $Target."
        return $false
    }

    foreach ($Rule in $Rules) {
        if (($Rule.FileSystemRights -band $DangerousMask) -ne 0) {
            Write-FiFail "$Role account $Account has an explicit write/modify/administrative Allow entry on $Target."
            return $false
        }
    }

    Write-FiPass "$Role account $Account has only explicit non-write Allow access on $Target."
    return $true
}

foreach ($Target in @($ConfigDir, $ConfigFile)) {
    if (-not (Test-FIExplicitReadOnlyEntry `
        -Target $Target `
        -Account $Collector.StartName `
        -Role "FICollector")) {
        $Failures++
    }

    if (-not (Test-FIExplicitReadOnlyEntry `
        -Target $Target `
        -Account $Helper.StartName `
        -Role "FIUSNReader")) {
        $Failures++
    }
}

$AdminOutput = (net localgroup Administrators) -join "`n"

if ($AdminOutput -match [Regex]::Escape($Collector.StartName)) {
    Write-FiFail "FICollector account $($Collector.StartName) is a local Administrator."
    $Failures++
}
else {
    Write-FiPass "FICollector account $($Collector.StartName) is not a local Administrator."
}

if ($AdminOutput -match [Regex]::Escape($Helper.StartName)) {
    Write-FiPass "FIUSNReader account $($Helper.StartName) is a local Administrator as required by the validated Server 2016 USN design."
}
else {
    Write-FiFail "FIUSNReader account $($Helper.StartName) is not a local Administrator."
    $Failures++
}

Write-Host ""
Write-Host "NOTE:"
Write-Host "  FIUSNReader is intentionally a local Administrator on this host."
Write-Host "  Its explicit FI config ACE is read-only, but local Administrator membership"
Write-Host "  means the config ACL is not a security boundary against compromise of the"
Write-Host "  helper itself. The protected boundary is the non-admin FICollector and the"
Write-Host "  narrow authenticated FI-USN broker API."
Write-Host ""

if ($Failures -eq 0) {
    Write-FiPass "TEST 07 PASSED."
    exit 0
}

Write-FiFail "TEST 07 FAILED with $Failures problem(s)."
exit 1
