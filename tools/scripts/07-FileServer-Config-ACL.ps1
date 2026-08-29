param()

. "$PSScriptRoot\Common.ps1"

$ConfigDir = "C:\ProgramData\FI\config"
$ConfigFile = "C:\ProgramData\FI\config\fi.conf"

Write-Host ""
Write-Host "FI USN Verification - Test 07: Config ACL Verification"
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
} else {
    Write-FiPass "BUILTIN\Users is absent from FI config ACLs."
}

$DangerousMask = `
    [System.Security.AccessControl.FileSystemRights]::Write -bor `
    [System.Security.AccessControl.FileSystemRights]::Modify -bor `
    [System.Security.AccessControl.FileSystemRights]::FullControl -bor `
    [System.Security.AccessControl.FileSystemRights]::Delete -bor `
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor `
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

foreach ($Target in @($ConfigDir, $ConfigFile)) {
    $Acl = Get-Acl -LiteralPath $Target

    foreach ($Account in @($Collector.StartName, $Helper.StartName)) {
        $Rules = @(
            $Acl.Access |
                Where-Object {
                    $_.IdentityReference.Value -ieq $Account -and
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
                }
        )

        if ($Rules.Count -eq 0) {
            Write-FiFail "$Account has no explicit Allow ACL entry on $Target."
            $Failures++
            continue
        }

        $HasDangerousAllow = $false

        foreach ($Rule in $Rules) {
            if (($Rule.FileSystemRights -band $DangerousMask) -ne 0) {
                $HasDangerousAllow = $true
            }
        }

        if ($HasDangerousAllow) {
            Write-FiFail "$Account has write/modify/administrative rights on $Target."
            $Failures++
        } else {
            Write-FiPass "$Account is read-only on $Target."
        }
    }
}

if ($Failures -eq 0) {
    Write-FiPass "TEST 07 PASSED."
    exit 0
}

Write-FiFail "TEST 07 FAILED with $Failures problem(s)."
exit 1
