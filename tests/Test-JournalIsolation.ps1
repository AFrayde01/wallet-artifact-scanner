[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
[void][Reflection.Assembly]::LoadFile((Join-Path $repo 'CryptoMnemonicScanner-10.12.dll'))
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$testBase = Join-Path $tempRoot ('wallet-scanner-journal-isolation-' + [guid]::NewGuid().ToString('D'))
[void][IO.Directory]::CreateDirectory($testBase)
$script:Passed = 0
function Assert-JournalIsolation([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAIL: ' + $Name) }
    $script:Passed++
    Write-Host ('PASS: ' + $Name)
}
try {
    $state = Join-Path $testBase 'result.scanstate'
    $journal = Join-Path $testBase 'result.scanjournal'
    $source = Join-Path $testBase 'unrelated-source.bin'
    $algorithm = '1' * 64
    $roots = '2' * 64
    $evidenceIds = [string[]]@('cryptocurrency_terms')
    $firstId = 'a' * 64
    $firstHash = 'f' * 64
    $initial = [CryptoScanCache]::new($state, $algorithm, $roots, $evidenceIds, $true, $journal)
    $initial.Remember($firstId, $firstHash, 8, 1, $evidenceIds, 0, 0)
    [void]$initial.Checkpoint()
    [IO.File]::Copy($journal, $source)
    $sourceHash = (Get-FileHash -LiteralPath $source).Hash
    $sourceTime = [IO.File]::GetLastWriteTimeUtc($source)
    Remove-Item -LiteralPath $journal
    [void](New-Item -ItemType HardLink -Path $journal -Target $source)
    $current = [CryptoScanCache]::new($state, $algorithm, $roots, $evidenceIds, $true, $journal)
    $current.Remember($firstId, $firstHash, 8, 1, $evidenceIds, 0, 0)
    [void]$current.Checkpoint()
    $current.Remember(('b' * 64), ('e' * 64), 12, 2, $evidenceIds, 0, 0)
    [void]$current.Checkpoint()
    Assert-JournalIsolation ((Get-FileHash -LiteralPath $source).Hash -eq $sourceHash -and [IO.File]::GetLastWriteTimeUtc($source) -eq $sourceTime) 'Appending a checkpoint cannot modify a source hard-linked to an identical previous journal'
    $recovered = [CryptoScanCache]::new($state, $algorithm, $roots, $evidenceIds, $false, $journal)
    Assert-JournalIsolation ($recovered.RecoveredEntries -eq 2 -and $null -ne $recovered.Find($firstId) -and $null -ne $recovered.Find(('b' * 64))) 'Isolating the journal preserves both recoverable checkpoints'
    $current.Finish()
    Assert-JournalIsolation (-not (Test-Path -LiteralPath $journal) -and (Get-FileHash -LiteralPath $source).Hash -eq $sourceHash) 'Cleaning up the checkpoint journal preserves the unrelated source'
    Write-Host ('ALL PASSED: {0} journal isolation assertions; synthetic files only.' -f $script:Passed)
}
finally {
    $cleanupPath = [IO.Path]::GetFullPath($testBase)
    if (-not $cleanupPath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($cleanupPath) -notmatch '^wallet-scanner-journal-isolation-[0-9a-f-]{36}$') { throw 'Unsafe journal isolation fixture cleanup path.' }
    if (Test-Path -LiteralPath $cleanupPath) { Remove-Item -LiteralPath $cleanupPath -Recurse -Force }
}
