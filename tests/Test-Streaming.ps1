[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$base = Join-Path $tempRoot ('wallet-scanner-streaming-' + [guid]::NewGuid().ToString('D'))
$inputRoot = Join-Path $base 'input'
New-Item -ItemType Directory -Path $inputRoot -Force | Out-Null
$script:Passed = 0
function Assert-Streaming([bool]$Value, [string]$Name) {
    if (-not $Value) { throw ('FAIL: ' + $Name) }
    $script:Passed++; Write-Host ('PASS: ' + $Name)
}
try {
    $extract = Join-Path $base 'package'
    Expand-Archive -LiteralPath (Join-Path $repo 'dist\windows-crypto-artifact-scan.zip') -DestinationPath $extract
    $copy = Join-Path $extract 'windows-crypto-artifact-scan'
    # Gate only the isolated test copy's metadata worker until real content bytes are read.
    $sourcePath = Join-Path $copy 'src\CryptoScanInventory.cs'
    $source = [IO.File]::ReadAllText($sourcePath)
    $pattern = [regex]::new('private void Discover\(\)\s*\{')
    $newLine = [Environment]::NewLine
    $replacement = 'private void Discover() {' + $newLine + '        CryptoInventoryTestHooks.ContentStarted.WaitOne(10000);'
    $source = $pattern.Replace($source, $replacement, 1)
    $source += $newLine + 'public static class CryptoInventoryTestHooks { public static readonly System.Threading.ManualResetEvent ContentStarted = new System.Threading.ManualResetEvent(false); }' + $newLine
    [IO.File]::WriteAllText($sourcePath, $source)
    $variantDll = Join-Path $base 'variant.dll'
    & powershell.exe -NoProfile -File (Join-Path $repo 'tools/build/Compile-Scanner.ps1') -SourceDirectory $copy -OutputAssembly $variantDll
    if ($LASTEXITCODE -ne 0) { throw 'Streaming fixture compilation failed.' }
    Copy-Item -LiteralPath $variantDll -Destination (Join-Path $copy 'CryptoMnemonicScanner-10.12.dll') -Force
    $large = Join-Path $inputRoot 'sample.log'
    $stream = [IO.File]::Create($large)
    $buffer = [Text.Encoding]::ASCII.GetBytes('z' * 1MB)
    try { for ($i=0; $i -lt 64; $i++) { $stream.Write($buffer,0,$buffer.Length) } } finally { $stream.Dispose() }
    $small = Join-Path $inputRoot 'notes.txt'
    [IO.File]::WriteAllText($small,'ordinary neutral notes',[Text.UTF8Encoding]::new($false))
    $hash = (Get-FileHash -LiteralPath $large).Hash
    $csv = Join-Path $base 'result.csv'
    $config = @{ Scanner=(Join-Path $copy 'Scan-CryptoArtifacts.ps1'); Roots=@($inputRoot); Csv=$csv; Answers=@(); NoProgress=$false;
        NoCache=$false; Rescan=$false; LockFile=''; MaxMB=256; RepeatInSession=$false; AlternateScanner=''; StopAfterFiles=0;
        CheckpointFiles=1000; MaxDocumentMB=32; MaxExpandedMB=256; SignalInventory=$true }
    $configPath = Join-Path $base 'config.json'
    $summaryPath = Join-Path $base 'summary.json'
    $progressPath = Join-Path $base 'progress.json'
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $console = @(& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath $progressPath)
    if ($LASTEXITCODE -ne 0) { throw ('Streaming scan failed: ' + ($console -join ' ')) }
    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    $progress = @(Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json)
    $pendingRead = @($progress | Where-Object { $_.Id -eq 2 -and $_.Percent -eq -1 -and $_.Status -match 'leídos: [0-9.,]*[1-9][0-9.,]* MB' })
    Assert-Streaming ($pendingRead.Count -gt 0) 'Real source bytes are read before the gated inventory can finish'
    $numeric = @($progress | Where-Object { $_.Id -eq 2 -and $_.Percent -gt 0 -and $_.Percent -lt 100 })
    Assert-Streaming ($numeric.Count -gt 0 -and $summary.InventoryComplete) 'Discovery completion enables the percentage bar with prior work included'
    Assert-Streaming (@($progress | Where-Object { $_.Id -eq 1 -and $_.Status -match 'media: .*MB/s; reciente: .*MB/s' -and $_.Activity -match 'restante:' -and $_.CurrentOperation -match 'Inventario:' }).Count -gt 0) 'Both effective read rates and remaining-time state appear in the UI'
    Assert-Streaming ($summary.BytesRead -eq ((Get-Item -LiteralPath $large).Length + (Get-Item -LiteralPath $small).Length)) 'Progress callbacks count source bytes exactly once'
    Assert-Streaming ($summary.ContentAnalyzed -eq 2 -and $summary.Incidents -eq 0 -and $summary.Findings -eq 0 -and $summary.AverageReadMBps -gt 0) 'Concurrent scan completes with correct coverage and a measured read rate'
    Assert-Streaming ((Get-FileHash -LiteralPath $large).Hash -eq $hash) 'Concurrent inventory and content reading preserve source bytes'
    Assert-Streaming (@($progress | Where-Object { $_.Id -eq 1 -and $_.Percent -eq 100 }).Count -gt 0 -and @($progress | Where-Object { $_.Id -eq 2 -and $_.Percent -eq 100 }).Count -gt 0) 'Both bars finish at 100 percent'
    Write-Host ('ALL PASSED: {0} streaming assertions; synthetic files only.' -f $script:Passed)
} finally {
    $target = [IO.Path]::GetFullPath($base)
    if (-not $target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe streaming fixture cleanup path.' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
