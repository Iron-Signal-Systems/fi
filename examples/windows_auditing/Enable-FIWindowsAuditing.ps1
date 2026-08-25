# FI Windows auditing - collector host example
# Windows Server 2016 / Windows PowerShell 5.1
#
# Run this from an elevated PowerShell prompt on an FI collector host.
# This is an administrator example. FI does not enable Windows auditing itself.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell prompt."
}

function Invoke-AuditPolSet {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & auditpol.exe @Arguments

    if ($LASTEXITCODE -ne 0) {
        throw "auditpol.exe failed: $($Arguments -join ' ')"
    }
}

Write-Host "Enabling FI Windows audit prerequisites..."

# File-system activity, including successful changes and failed access attempts.
Invoke-AuditPolSet -Arguments @(
    '/set',
    '/subcategory:File System',
    '/success:enable',
    '/failure:enable'
)

# Server 2016 validation showed that denied file-handle requests did not emit
# Event ID 4656 until Handle Manipulation failure auditing was enabled.
Invoke-AuditPolSet -Arguments @(
    '/set',
    '/subcategory:Handle Manipulation',
    '/failure:enable'
)

# Preserve changes to Windows audit policy itself.
Invoke-AuditPolSet -Arguments @(
    '/set',
    '/subcategory:Audit Policy Change',
    '/success:enable'
)

Write-Host ""
Write-Host "Current FI Windows audit prerequisites:"

auditpol.exe /get /subcategory:"File System" /r
auditpol.exe /get /subcategory:"Handle Manipulation" /r
auditpol.exe /get /subcategory:"Audit Policy Change" /r

Write-Host ""
Write-Host "Windows audit policy example complete."
Write-Host "A matching SACL is still required on each governed root."
