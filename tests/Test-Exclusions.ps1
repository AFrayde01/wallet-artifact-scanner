[CmdletBinding()]
param([string]$ScannerPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ScannerPath)) { $ScannerPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Scan-CryptoArtifacts.ps1' }
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$testBase = Join-Path $tempRoot ('wallet-scanner-exclusions-' + [guid]::NewGuid().ToString('D'))
$firstRoot = Join-Path $testBase 'first'
$secondRoot = Join-Path $testBase 'second'
$reportDirectory = Join-Path $firstRoot 'reports'
$similarDirectory = Join-Path $firstRoot 'reports-other'
$secondExcluded = Join-Path $secondRoot 'omitted'
$script:Passed = 0
$script:RunNumber = 0

function Assert-Exclusion([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAIL: ' + $Name) }
    $script:Passed++
    Write-Host ('PASS: ' + $Name)
}

function Invoke-ExclusionScan {
    param([string]$Csv, [string[]]$Locations, [string[]]$Exclusions,
        [switch]$NoProgress, [switch]$NoCache, [switch]$ExpectError)
    $script:RunNumber++
    $configPath = Join-Path $testBase ('config-' + $script:RunNumber + '.json')
    $summaryPath = Join-Path $testBase ('summary-' + $script:RunNumber + '.json')
    $progressPath = Join-Path $testBase ('progress-' + $script:RunNumber + '.json')
    $config = @{ Scanner=$ScannerPath; Roots=@($Locations); Csv=$Csv; ExcludePaths=@($Exclusions); Answers=@();
        NoProgress=[bool]$NoProgress; NoCache=[bool]$NoCache; Rescan=$false; LockFile=''; MaxMB=256;
        RepeatInSession=$false; AlternateScanner=''; StopAfterFiles=0; CheckpointFiles=1;
        MaxDocumentMB=32; MaxExpandedMB=256; CpuCorePercent=80; Workers=1 }
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $console = @(& $windowsPowerShell -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath $progressPath)
    $code = $LASTEXITCODE
    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    if ($code -ne 0 -and -not $ExpectError) { throw ('Exclusion fixture failed: ' + $summary.Error) }
    return [pscustomobject]@{ Summary=$summary; ExitCode=$code; Console=($console -join "`n");
        Progress=if (Test-Path -LiteralPath $progressPath) { @(Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json) } else { @() } }
}

try {
    foreach ($directory in @($reportDirectory, $similarDirectory, $secondExcluded)) {
        [void][IO.Directory]::CreateDirectory($directory)
    }
    $phrase = 'abandon amount liar amount expire adjust cage candy arch gather drum buyer'
    $includedFiles = @((Join-Path $firstRoot 'notes.txt'), (Join-Path $similarDirectory 'notes.txt'), (Join-Path $secondRoot 'notes.txt'))
    $excludedFiles = @((Join-Path $reportDirectory 'old-report.csv'), (Join-Path $secondExcluded 'notes.txt'))
    $sourceHashes = @{}
    foreach ($file in @($includedFiles) + @($excludedFiles)) {
        [IO.File]::WriteAllText($file, $phrase, [Text.UTF8Encoding]::new($false))
        $sourceHashes[$file] = (Get-FileHash -LiteralPath $file).Hash
    }
    $locations = @($firstRoot, $secondRoot)
    # Trailing separators and letter case must not change directory exclusions.
    $exclusions = @(($reportDirectory.ToUpperInvariant() + '\'), $secondExcluded)
    $csv = Join-Path $reportDirectory 'result.csv'
    $first = Invoke-ExclusionScan -Csv $csv -Locations $locations -Exclusions $exclusions
    Assert-Exclusion ($first.ExitCode -eq 0 -and $first.Summary.CpuCorePercent -eq 80) 'PowerShell 5.1 accepts multiple roots, exclusions and the requested CPU percentage'
    Assert-Exclusion ($first.Summary.FilesEnumerated -eq 3 -and $first.Summary.ContentAnalyzed -eq 3 -and $first.Summary.ExcludedDirectories -eq 2) 'All exclusions are preserved and neither excluded directory is read'
    Assert-Exclusion ($first.Summary.InventoryComplete -and $first.Summary.InventoryErrors -eq 0 -and $first.Summary.Incidents -eq 0) 'Inventory and scan finish without errors when reports are inside an excluded directory'
    $rows = @(Import-Csv -LiteralPath $csv)
    foreach ($file in $includedFiles) {
        Assert-Exclusion (@($rows | Where-Object { $_.Ubicacion -eq $file -and $_.Tipo -eq 'frase_bip39_checksum_valido' }).Count -eq 1) ('Included source is detected: ' + $file.Substring($testBase.Length))
    }
    Assert-Exclusion ($rows.Count -eq 3) 'Existing reports and excluded source evidence do not enter the findings'
    Assert-Exclusion (-not [IO.File]::ReadAllText($csv).Contains($phrase)) 'CSV contains locations and types without synthetic secret content'
    Assert-Exclusion (@($first.Progress | Where-Object { $_.Id -eq 1 -and $_.Percent -eq 100 }).Count -gt 0 -and @($first.Progress | Where-Object { $_.Id -eq 2 -and $_.Percent -eq 100 }).Count -gt 0) 'Global and location progress reach 100 percent'
    $outputHashes = @{}
    $outputTimes = @{}
    foreach ($file in Get-ChildItem -LiteralPath $reportDirectory -File | Where-Object { $_.FullName -ne $excludedFiles[0] }) {
        $outputHashes[$file.FullName] = (Get-FileHash -LiteralPath $file.FullName).Hash
        $outputTimes[$file.FullName] = $file.LastWriteTimeUtc.Ticks
    }
    $repeat = Invoke-ExclusionScan -Csv $csv -Locations $locations -Exclusions $exclusions -NoProgress
    Assert-Exclusion ($repeat.Summary.ContentAnalyzed -eq 0 -and $repeat.Summary.ContentReused -eq 3 -and $repeat.Summary.FilesEnumerated -eq 3) 'Repeated scan reuses source detections without reading generated reports'
    $unchanged = $true
    foreach ($file in $outputHashes.Keys) {
        if ((Get-FileHash -LiteralPath $file).Hash -ne $outputHashes[$file] -or (Get-Item -LiteralPath $file).LastWriteTimeUtc.Ticks -ne $outputTimes[$file]) { $unchanged = $false }
    }
    Assert-Exclusion $unchanged 'All reports and cache remain byte and timestamp identical on repetition'
    $noCacheCsv = Join-Path $reportDirectory 'no-cache.csv'
    $noCache = Invoke-ExclusionScan -Csv $noCacheCsv -Locations $locations -Exclusions $exclusions -NoCache
    Assert-Exclusion ($noCache.Summary.ContentAnalyzed -eq 3 -and -not (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($noCacheCsv, '.scanstate')))) 'Excluded output directories also work without cache'
    $changedExclusions = Invoke-ExclusionScan -Csv $csv -Locations $locations -Exclusions @($reportDirectory)
    Assert-Exclusion ($changedExclusions.Summary.AlgorithmFingerprint -ne $first.Summary.AlgorithmFingerprint -and $changedExclusions.Summary.ContentAnalyzed -eq 4 -and $changedExclusions.Summary.ContentReused -eq 0) 'Changing exclusions invalidates cache and detects newly included evidence'
    $forbiddenCsv = Join-Path $similarDirectory 'forbidden.csv'
    $prefixRejected = Invoke-ExclusionScan -Csv $forbiddenCsv -Locations $locations -Exclusions $exclusions -ExpectError
    Assert-Exclusion ($prefixRejected.ExitCode -ne 0 -and $prefixRejected.Summary.Error -match 'ExcludePath' -and -not (Test-Path -LiteralPath $forbiddenCsv)) 'A directory sharing only the excluded prefix cannot hold output'
    $wholeRootCsv = Join-Path $testBase 'whole-root.csv'
    $rootRejected = Invoke-ExclusionScan -Csv $wholeRootCsv -Locations $locations -Exclusions @($firstRoot + '\') -ExpectError
    Assert-Exclusion ($rootRejected.ExitCode -ne 0 -and $rootRejected.Summary.Error -match 'subcarpeta' -and -not (Test-Path -LiteralPath $wholeRootCsv)) 'Excluding an entire selected root is rejected before writing'
    $outsideRejected = Invoke-ExclusionScan -Csv (Join-Path $testBase 'outside.csv') -Locations @($firstRoot) -Exclusions @($secondExcluded) -ExpectError
    Assert-Exclusion ($outsideRejected.ExitCode -ne 0 -and $outsideRejected.Summary.Error -match 'dentro de una ubicaci' -and -not (Test-Path -LiteralPath (Join-Path $testBase 'outside.csv'))) 'An exclusion outside the selected roots is rejected'
    $blockedReportCsv = Join-Path $reportDirectory 'blocked-report.csv'
    [void][IO.Directory]::CreateDirectory([IO.Path]::ChangeExtension($blockedReportCsv, '.prioritarios.csv'))
    $blockedReport = Invoke-ExclusionScan -Csv $blockedReportCsv -Locations $locations -Exclusions $exclusions -ExpectError
    Assert-Exclusion ($blockedReport.ExitCode -ne 0 -and $blockedReport.Summary.Error -match 'salida apunta a una carpeta' -and -not (Test-Path -LiteralPath $blockedReportCsv)) 'Every derived report path is validated before scanning or writing'
    $unchangedSources = $true
    foreach ($file in $sourceHashes.Keys) {
        if ((Get-FileHash -LiteralPath $file).Hash -ne $sourceHashes[$file]) { $unchangedSources = $false }
    }
    Assert-Exclusion $unchangedSources 'All included and excluded source bytes are preserved'
    Write-Host ('ALL PASSED: {0} exclusion assertions; synthetic folders only.' -f $script:Passed)
}
finally {
    $cleanupPath = [IO.Path]::GetFullPath($testBase)
    if (-not $cleanupPath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($cleanupPath) -notmatch '^wallet-scanner-exclusions-[0-9a-f-]{36}$') { throw 'Unsafe exclusion fixture cleanup path.' }
    if (Test-Path -LiteralPath $cleanupPath) { Remove-Item -LiteralPath $cleanupPath -Recurse -Force }
}
