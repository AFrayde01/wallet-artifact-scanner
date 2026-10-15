$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$base = Join-Path $tempRoot ('wallet-scanner-operational-' + [guid]::NewGuid().ToString('D'))
$inputRoot = Join-Path $base 'disconnect'
New-Item -ItemType Directory -Path $inputRoot -Force | Out-Null
$script:Passed = 0
function Assert-Operation([bool]$Value,[string]$Name) {
    if (-not $Value) { throw ('FAIL: ' + $Name) }
    $script:Passed++; Write-Host ('PASS: ' + $Name)
}
function Invoke-Operation([string]$Root,[string]$Csv,[string]$Scanner,[string]$DropRoot = '',[int]$ExpandedMB = 256) {
    $configPath = Join-Path $base 'config.json'
    $summaryPath = Join-Path $base 'summary.json'
    $config = @{ Scanner=$Scanner; Roots=@($Root); Csv=$Csv; Answers=@(); NoProgress=$false; NoCache=$false; Rescan=$false; LockFile=''; MaxMB=256;
        RepeatInSession=$false; AlternateScanner=''; StopAfterFiles=0; CheckpointFiles=1; MaxDocumentMB=32; MaxExpandedMB=$ExpandedMB; DropRoot=$DropRoot }
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $console = @(& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath (Join-Path $base 'progress.json'))
    if ($LASTEXITCODE -ne 0) { throw 'Operational fixture failed.' }
    return Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
}
try {
    $scanner = Join-Path $repo 'Scan-CryptoArtifacts.ps1'
    $text = 'z' * 1MB
    $hashes = @()
    $dataRoot = Join-Path $inputRoot '0000-data'
    New-Item -ItemType Directory -Path $dataRoot | Out-Null
    for ($i=0;$i -lt 20;$i++) { [IO.File]::WriteAllText((Join-Path $dataRoot ($i.ToString('D4') + '.txt')),'ordinary neutral data') }
    for ($i=0;$i -lt 20;$i++) {
        $path = Join-Path $inputRoot ($i.ToString('D4') + '.txt')
        [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))
        $hashes += (Get-FileHash -LiteralPath $path).Hash
    }
    $csv = Join-Path $base 'disconnect.csv'
    $disconnected = Invoke-Operation $inputRoot $csv $scanner $dataRoot
    $offline = Join-Path $base 'offline-0000-data'
    Assert-Operation ((Test-Path -LiteralPath $offline) -and $disconnected.Incidents -gt 0 -and $disconnected.Status -eq 'recorrido_con_incidencias') 'Location disappearance during reading is reported explicitly'
    $resolvedBase = [IO.Path]::GetFullPath($base).TrimEnd('\') + '\'
    if (-not [IO.Path]::GetFullPath($offline).StartsWith($resolvedBase,[StringComparison]::OrdinalIgnoreCase) -or -not [IO.Path]::GetFullPath($dataRoot).StartsWith($resolvedBase,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe reconnect fixture path.' }
    [IO.Directory]::Move($offline,$dataRoot)
    $reconnected = Invoke-Operation $inputRoot $csv $scanner
    Assert-Operation ($reconnected.Incidents -eq 0 -and $reconnected.ContentAnalyzed -gt 0 -and $reconnected.ContentReused -gt 0) 'Reconnected location retries missed files and reuses verified completed files'
    $unchanged = $true
    for ($i=0;$i -lt 20;$i++) { if ((Get-FileHash -LiteralPath (Join-Path $inputRoot ($i.ToString('D4') + '.txt'))).Hash -ne $hashes[$i]) { $unchanged=$false } }
    Assert-Operation $unchanged 'Disconnect/reconnect fixture preserves all source bytes'
    $copyParent = Join-Path $base 'bounded-parser-package'
    Expand-Archive -LiteralPath (Join-Path $repo 'dist\windows-crypto-artifact-scan.zip') -DestinationPath $copyParent
    $copy = Join-Path $copyParent 'windows-crypto-artifact-scan'
    # A parser emits a completed page, then stalls to test timeout and partial evidence.
    $stubWorker = @'
$reader=[IO.BinaryReader]::new([Console]::OpenStandardInput())
$size=$reader.ReadInt32()
[void]$reader.ReadBytes($size)
$writer=[IO.BinaryWriter]::new([Console]::OpenStandardOutput())
$text=[Text.Encoding]::UTF8.GetBytes('abandon amount liar amount expire adjust cage candy arch gather drum buyer')
$writer.Write([int]1)
$writer.Write([int]$text.Length)
$writer.Write([byte[]]$text)
$writer.Flush()
Start-Sleep -Seconds 100
'@
    [IO.File]::WriteAllText((Join-Path $copy 'scripts\Read-PdfWorker.ps1'),$stubWorker,[Text.UTF8Encoding]::new($true))
    $pdfRoot = Join-Path $base 'pdf'
    New-Item -ItemType Directory -Path $pdfRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $pdfRoot 'sample.pdf'),'%PDF-1.4 synthetic timeout payload')
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $timeout = Invoke-Operation $pdfRoot (Join-Path $base 'timeout.csv') (Join-Path $copy 'Scan-CryptoArtifacts.ps1')
    $timer.Stop()
    Assert-Operation ($timeout.IncompleteDocuments -eq 1 -and $timer.Elapsed.TotalSeconds -lt 65) 'Unresponsive PDF parser is terminated within the configured bound'
    Assert-Operation (@(Import-Csv -LiteralPath (Join-Path $base 'timeout.incidencias.csv') | Where-Object { $_.Tipo -eq 'documento_supera_limite_recursos' }).Count -eq 1) 'PDF timeout is represented as an incidence rather than a negative result'
    Assert-Operation ($timeout.MembersScanned -eq 1 -and @(Import-Csv -LiteralPath (Join-Path $base 'timeout.csv') | Where-Object { $_.Tipo -eq 'frase_bip39_checksum_valido' }).Count -eq 1) 'PDF timeout preserves evidence from a completed page'
    Write-Host ('ALL PASSED: {0} operational assertions; synthetic locations only.' -f $script:Passed)
}
finally {
    $target = [IO.Path]::GetFullPath($base)
    if (-not $target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected operational cleanup target.' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
