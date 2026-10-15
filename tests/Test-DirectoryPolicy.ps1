[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
[void][Reflection.Assembly]::LoadFile((Join-Path $repo 'CryptoMnemonicScanner-10.12.dll'))
$script:Passed = 0
function Assert-DirectoryPolicy([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAIL: ' + $Name) }
    $script:Passed++
    Write-Host ('PASS: ' + $Name)
}
$policyAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Scan-CryptoArtifacts.ps1'), [ref]$null, [ref]$null)
$systemNamesNode = $policyAst.Find({ param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$script:ExcludedDirectoryNames' }, $true)
Invoke-Expression $systemNamesNode.Extent.Text
Assert-DirectoryPolicy ($script:ExcludedDirectoryNames -notcontains 'Recovery') 'Recovery folders are scanned by default even when located at a volume root'
foreach ($case in @(
    @{ Path='C:\Recovery'; Expected=$true },
    @{ Path='X:\Windows\'; Expected=$true },
    @{ Path='C:\$Recycle.Bin'; Expected=$true },
    @{ Path='C:\'; Expected=$false },
    @{ Path='C:\Users\tester\Recovery'; Expected=$false },
    @{ Path='D:\backups\Windows'; Expected=$false },
    @{ Path='\\server\share\Recovery'; Expected=$true },
    @{ Path='\\server\share\backup\Recovery'; Expected=$false },
    @{ Path='\\?\D:\Recovery\'; Expected=$true },
    @{ Path='\\?\UNC\server\share\backup\Recovery'; Expected=$false }
)) {
    Assert-DirectoryPolicy ([CryptoWindowsIO]::IsVolumeRootChild($case.Path) -eq $case.Expected) ('System-directory boundary: ' + $case.Path)
}
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$testBase = Join-Path $tempRoot ('wallet-scanner-directory-policy-' + [guid]::NewGuid().ToString('D'))
$inputRoot = Join-Path $testBase 'input'
try {
    $phrase = 'abandon amount liar amount expire adjust cage candy arch gather drum buyer'
    $sourceHashes = @{}
    foreach ($name in @('Recovery', 'Windows', '$Recycle.Bin', 'System Volume Information')) {
        $directory = Join-Path $inputRoot $name
        [void][IO.Directory]::CreateDirectory($directory)
        $path = Join-Path $directory 'notes.txt'
        [IO.File]::WriteAllText($path, $phrase, [Text.UTF8Encoding]::new($false))
        $sourceHashes[$path] = (Get-FileHash -LiteralPath $path).Hash
    }
    $csv = Join-Path $testBase 'result.csv'
    $configPath = Join-Path $testBase 'config.json'
    $summaryPath = Join-Path $testBase 'summary.json'
    $progressPath = Join-Path $testBase 'progress.json'
    $config = @{ Scanner=(Join-Path $repo 'Scan-CryptoArtifacts.ps1'); Roots=@($inputRoot); Csv=$csv; Answers=@();
        NoProgress=$false; NoCache=$false; Rescan=$false; LockFile=''; MaxMB=256; RepeatInSession=$false;
        AlternateScanner=''; StopAfterFiles=0; CheckpointFiles=1; MaxDocumentMB=32; MaxExpandedMB=256; CpuCorePercent=80; Workers=1 }
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $null = & $windowsPowerShell -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath $progressPath
    if ($LASTEXITCODE -ne 0) { throw ('Directory policy fixture failed: ' + [IO.File]::ReadAllText($summaryPath)) }
    $first = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    Assert-DirectoryPolicy ($first.FilesEnumerated -eq 4 -and $first.ContentAnalyzed -eq 4 -and $first.ExcludedDirectories -eq 0) 'Personal folders sharing system names are enumerated and read'
    Assert-DirectoryPolicy ($first.InventoryComplete -and $first.InventoryErrors -eq 0 -and $first.Incidents -eq 0) 'Inventory follows the same directory policy as the scanner'
    $rows = @(Import-Csv -LiteralPath $csv)
    foreach ($path in $sourceHashes.Keys) {
        Assert-DirectoryPolicy (@($rows | Where-Object { $_.Ubicacion -eq $path -and $_.Tipo -eq 'frase_bip39_checksum_valido' }).Count -eq 1) ('Personal-folder evidence preserved: ' + [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($path)))
    }
    $firstCsvHash = (Get-FileHash -LiteralPath $csv).Hash
    $null = & $windowsPowerShell -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath $progressPath
    if ($LASTEXITCODE -ne 0) { throw 'Repeated directory policy fixture failed.' }
    $repeat = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    Assert-DirectoryPolicy ($repeat.ContentAnalyzed -eq 0 -and $repeat.ContentReused -eq 4 -and (Get-FileHash -LiteralPath $csv).Hash -eq $firstCsvHash) 'Repeated personal-folder scan is idempotent and reuses detections'
    $config.ExcludePaths = @((Join-Path $inputRoot 'Recovery'))
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $null = & $windowsPowerShell -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath $progressPath
    if ($LASTEXITCODE -ne 0) { throw 'Explicit directory exclusion fixture failed.' }
    $excluded = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    Assert-DirectoryPolicy ($excluded.FilesEnumerated -eq 3 -and $excluded.ExcludedDirectories -eq 1 -and $excluded.AlgorithmFingerprint -ne $first.AlgorithmFingerprint) 'Explicit user exclusions still omit nested personal folders and invalidate cache'
    $unchanged = $true
    foreach ($path in $sourceHashes.Keys) { if ((Get-FileHash -LiteralPath $path).Hash -ne $sourceHashes[$path]) { $unchanged = $false } }
    Assert-DirectoryPolicy $unchanged 'Directory policy changes preserve every source byte'
    Write-Host ('ALL PASSED: {0} directory policy assertions; synthetic folders only.' -f $script:Passed)
}
finally {
    $cleanupPath = [IO.Path]::GetFullPath($testBase)
    if (-not $cleanupPath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($cleanupPath) -notmatch '^wallet-scanner-directory-policy-[0-9a-f-]{36}$') { throw 'Unsafe directory policy fixture cleanup path.' }
    if (Test-Path -LiteralPath $cleanupPath) { Remove-Item -LiteralPath $cleanupPath -Recurse -Force }
}
