# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

param(
    [string]$RepositoryRoot = ""
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "FI Repository - Pre-Commit Source / Script Audit"
Write-Host ""

if (-not $RepositoryRoot) {
    $GitRoot = @(
        & git rev-parse --show-toplevel 2>$null
    )

    if ($LASTEXITCODE -ne 0 -or $GitRoot.Count -ne 1) {
        throw "Could not determine repository root with git rev-parse. Re-run with -RepositoryRoot <path>."
    }

    $RepositoryRoot = $GitRoot[0].Trim()
}

$RepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)

if (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot ".git"))) {
    throw "Not a Git working tree: $RepositoryRoot"
}

Write-Host "[INFO] Repository root: $RepositoryRoot"

$LicensePath = Join-Path $RepositoryRoot "LICENSE"

if (-not (Test-Path -LiteralPath $LicensePath -PathType Leaf)) {
    throw "Repository root LICENSE file not found: $LicensePath"
}

Write-Host "[PASS] Root LICENSE file exists."

$CodeExtensions = @(
    ".go",
    ".ps1",
    ".psm1",
    ".psd1",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".bat",
    ".cmd"
)

$TextExtensions = @(
    ".md",
    ".txt",
    ".go",
    ".ps1",
    ".psm1",
    ".psd1",
    ".yml",
    ".yaml",
    ".json",
    ".jsonl",
    ".toml",
    ".conf",
    ".example",
    ".gitignore",
    ".gitattributes"
)

$LicenseNeedles = @(
    "Source Review License",
    "repository root LICENSE",
    "LICENSE file"
)

$AutomaticMatchVariableToken = '$' + 'Matches'

# Build retired-project search terms from fragments so the repository audit does
# not itself contain the exact historical strings it is designed to reject.
$RetiredRepoSlug = ('old-file-' + 'intelligence')
$RetiredRepoPath = ('Iron-Signal-Systems/' + $RetiredRepoSlug)
$RetiredRepoURL = ('github.com/' + $RetiredRepoPath)

$RetiredProjectPhrases = @(
    ('old FI ' + 'project'),
    ('old FI ' + 'implementation'),
    ('old File Intelligence ' + 'project'),
    ('old File Intelligence ' + 'implementation'),
    ('previous FI ' + 'project'),
    ('previous FI ' + 'implementation'),
    ('prior FI ' + 'project'),
    ('prior FI ' + 'implementation'),
    ('legacy FI ' + 'project'),
    ('legacy FI ' + 'implementation'),
    ('original FI ' + 'project'),
    ('original FI ' + 'implementation'),
    ('earlier FI ' + 'project'),
    ('earlier FI ' + 'implementation')
)

$RetiredProjectPatterns = @(
    $RetiredRepoSlug,
    $RetiredRepoPath,
    $RetiredRepoURL
) + $RetiredProjectPhrases

Push-Location $RepositoryRoot

try {
    $GitFiles = @(
        & git ls-files --cached --others --exclude-standard
    )

    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed."
    }
}
finally {
    Pop-Location
}

$CandidateFiles = @(
    $GitFiles |
        ForEach-Object {
            $RelativePath = $_.Trim()

            if (-not $RelativePath) {
                return
            }

            $Extension = [System.IO.Path]::GetExtension($RelativePath).ToLowerInvariant()

            if ($CodeExtensions -contains $Extension) {
                [PSCustomObject]@{
                    RelativePath = $RelativePath
                    FullPath = Join-Path $RepositoryRoot $RelativePath
                    Extension = $Extension
                }
            }
        } |
        Sort-Object RelativePath
)

Write-Host "[INFO] Source/script files under audit: $($CandidateFiles.Count)"

$MissingLicense = @()
$AutomaticMatchVariableOccurrences = @()
$Unreadable = @()

foreach ($File in $CandidateFiles) {
    if (-not (Test-Path -LiteralPath $File.FullPath -PathType Leaf)) {
        $Unreadable += $File.RelativePath
        continue
    }

    try {
        $Content = Get-Content -LiteralPath $File.FullPath -Raw -ErrorAction Stop
    }
    catch {
        $Unreadable += $File.RelativePath
        continue
    }

    $HasLicenseReference = $false

    foreach ($Needle in $LicenseNeedles) {
        if ($Content.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $HasLicenseReference = $true
            break
        }
    }

    if (-not $HasLicenseReference) {
        $MissingLicense += $File.RelativePath
    }

    if (
        $File.Extension -in @(".ps1", ".psm1", ".psd1") -and
        $Content.Contains($AutomaticMatchVariableToken)
    ) {
        $LineNumber = 0

        foreach ($Line in Get-Content -LiteralPath $File.FullPath) {
            $LineNumber++

            if ($Line.Contains($AutomaticMatchVariableToken)) {
                $AutomaticMatchVariableOccurrences += [PSCustomObject]@{
                    Path = $File.RelativePath
                    Line = $LineNumber
                    Text = $Line.Trim()
                }
            }
        }
    }
}

$RetiredProjectHits = @()

foreach ($RelativePath in $GitFiles) {
    $RelativePath = $RelativePath.Trim()

    if (-not $RelativePath) {
        continue
    }

    $FullPath = Join-Path $RepositoryRoot $RelativePath

    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        continue
    }

    $Extension = [System.IO.Path]::GetExtension($RelativePath).ToLowerInvariant()
    $FileName = [System.IO.Path]::GetFileName($RelativePath).ToLowerInvariant()

    $ShouldRead = (
        $TextExtensions -contains $Extension -or
        $FileName -in @(
            "license",
            "readme",
            "security.md"
        )
    )

    if (-not $ShouldRead) {
        continue
    }

    try {
        $Lines = Get-Content -LiteralPath $FullPath -ErrorAction Stop
    }
    catch {
        continue
    }

    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        $Line = [string]$Lines[$Index]

        foreach ($Pattern in $RetiredProjectPatterns) {
            if ($Line.IndexOf($Pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $RetiredProjectHits += [PSCustomObject]@{
                    Path = $RelativePath
                    Line = $Index + 1
                    Text = $Line.Trim()
                }

                break
            }
        }
    }
}

Write-Host ""
Write-Host "=== LICENSE / LICENSE-REFERENCE AUDIT ==="

if ($MissingLicense.Count -eq 0) {
    Write-Host "[PASS] Every audited source/script file contains an FI license or root-LICENSE reference."
}
else {
    Write-Host "[FAIL] Source/script files missing an FI license or root-LICENSE reference:"

    $MissingLicense |
        ForEach-Object {
            Write-Host "  $_"
        }
}

Write-Host ""
Write-Host "=== POWERSHELL AUTOMATIC MATCH-VARIABLE AUDIT ==="

if ($AutomaticMatchVariableOccurrences.Count -eq 0) {
    Write-Host "[PASS] No audited PowerShell file contains the automatic match variable."
}
else {
    Write-Host "[FAIL] PowerShell files still containing the automatic match variable:"

    $AutomaticMatchVariableOccurrences |
        Format-Table Path,Line,Text -AutoSize
}

Write-Host ""
Write-Host "=== RETIRED-PROJECT REFERENCE AUDIT ==="

if ($RetiredProjectHits.Count -eq 0) {
    Write-Host "[PASS] No retired-project references were found in tracked or untracked text files."
}
else {
    Write-Host "[FAIL] Retired-project references remain:"

    $RetiredProjectHits |
        Format-Table Path,Line,Text -AutoSize
}

Write-Host ""
Write-Host "=== READABILITY ==="

if ($Unreadable.Count -eq 0) {
    Write-Host "[PASS] All audited source/script files were readable."
}
else {
    Write-Host "[FAIL] Source/script files that could not be read:"

    $Unreadable |
        ForEach-Object {
            Write-Host "  $_"
        }
}

Write-Host ""
Write-Host "=== WORKING TREE ==="

Push-Location $RepositoryRoot

try {
    & git status --short

    if ($LASTEXITCODE -ne 0) {
        throw "git status --short failed."
    }
}
finally {
    Pop-Location
}

$FailureCount = (
    $MissingLicense.Count +
    $AutomaticMatchVariableOccurrences.Count +
    $RetiredProjectHits.Count +
    $Unreadable.Count
)

Write-Host ""

if ($FailureCount -eq 0) {
    Write-Host "[PASS] FI REPOSITORY PRE-COMMIT SOURCE / SCRIPT AUDIT PASSED."
    exit 0
}

Write-Host "[FAIL] FI REPOSITORY PRE-COMMIT SOURCE / SCRIPT AUDIT FAILED."
Write-Host "[INFO] Missing license/reference files:       $($MissingLicense.Count)"
Write-Host "[INFO] Automatic match-variable occurrences: $($AutomaticMatchVariableOccurrences.Count)"
Write-Host "[INFO] Retired-project references:            $($RetiredProjectHits.Count)"
Write-Host "[INFO] Unreadable files:                      $($Unreadable.Count)"
exit 1
