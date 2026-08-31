# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [int]$Minutes = 10,
    [string]$PathContains = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$start = (Get-Date).AddMinutes(-1 * [math]::Abs($Minutes))
$ids = 4656,4663,4660,4664,4670,4907,5145,1102,4719

$events = Get-WinEvent `
    -FilterHashtable @{
        LogName = 'Security'
        Id = $ids
        StartTime = $start
    } `
    -ErrorAction Stop

foreach ($event in $events) {
    $xml = $event.ToXml()

    if ($PathContains -and $xml -notlike "*$PathContains*") {
        continue
    }

    [pscustomobject]@{
        TimeCreated   = $event.TimeCreated
        EventRecordID = $event.RecordId
        EventID       = $event.Id
        Provider      = $event.ProviderName
        MachineName   = $event.MachineName
        XML           = $xml
    }
}
