param([string]$ConfigPath, [string]$SummaryPath, [string]$ProgressPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$global:WalletScannerFixtureAnswers = New-Object 'Collections.Generic.Queue[string]'
foreach ($answer in $config.Answers) { $global:WalletScannerFixtureAnswers.Enqueue([string]$answer) }
$global:WalletScannerFixtureProgress = New-Object 'Collections.Generic.List[object]'
$global:WalletScannerFixtureStopAfterFiles = [int]$config.StopAfterFiles
$global:WalletScannerFixtureDropRoot = if ($config.PSObject.Properties['DropRoot']) { [string]$config.DropRoot } else { '' }
$global:WalletScannerSignalInventory = $config.PSObject.Properties['SignalInventory'] -and [bool]$config.SignalInventory
function global:Read-Host {
    param([string]$Prompt)
    if ($global:WalletScannerFixtureAnswers.Count -eq 0) { throw 'El fixture no tiene otra respuesta de menú.' }
    return $global:WalletScannerFixtureAnswers.Dequeue()
}
function global:Write-Progress {
    param([int]$Id, [int]$ParentId, [string]$Activity, [string]$Status, [string]$CurrentOperation, [int]$PercentComplete = -1, [switch]$Completed)
    $global:WalletScannerFixtureProgress.Add([pscustomobject]@{ Id = $Id; Percent = $PercentComplete; Completed = [bool]$Completed; Activity = $Activity; Status = $Status; CurrentOperation=$CurrentOperation })
    if ($global:WalletScannerSignalInventory -and $Id -eq 2 -and $Status -match 'leídos: [0-9.,]*[1-9][0-9.,]* MB') {
        [void][CryptoInventoryTestHooks]::ContentStarted.Set()
        $global:WalletScannerSignalInventory = $false
    }
    if ($global:WalletScannerFixtureDropRoot -and $Id -eq 2 -and $Status -match 'archivos: (\d+)/' -and [int]$Matches[1] -ge 2) {
        $source = [IO.Path]::GetFullPath($global:WalletScannerFixtureDropRoot)
        $fixtureBase = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($ConfigPath)).TrimEnd('\') + '\'
        $destination = Join-Path $fixtureBase ('offline-' + [IO.Path]::GetFileName($source))
        if (-not $source.StartsWith($fixtureBase,[StringComparison]::OrdinalIgnoreCase) -or -not $destination.StartsWith($fixtureBase,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe disconnect fixture path.' }
        [IO.Directory]::Move($source,$destination)
        $global:WalletScannerFixtureDropRoot = ''
    }
    if ($global:WalletScannerFixtureStopAfterFiles -gt 0 -and $Id -eq 2 -and $Status -match 'archivos: (\d+)/' -and [int]$Matches[1] -ge $global:WalletScannerFixtureStopAfterFiles) { [Environment]::Exit(73) }
}
$lock = $null
try {
    if ($config.LockFile) { $lock = [IO.File]::Open($config.LockFile, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    # The progress hooks below recognize Spanish status phrases. Set the fixture
    # language explicitly so the harness stays deterministic with English as the app default.
    $parameters = @{ CsvPath = $config.Csv; PassThru = $true; MaxContentMB = [int]$config.MaxMB; Language = 'es' }
    if ($config.Roots.Count -gt 0) { $parameters.Root = [string[]]$config.Roots }
    if ($config.NoProgress) { $parameters.NoProgress = $true }
    if ($config.NoCache) { $parameters.NoCache = $true }
    if ($config.Rescan) { $parameters.Rescan = $true }
    if ($config.PSObject.Properties['ExcludePaths']) { $parameters.ExcludePath = [string[]]$config.ExcludePaths }
    $parameters.CheckpointFiles = [int]$config.CheckpointFiles
    $parameters.MaxDocumentMB = [int]$config.MaxDocumentMB
    $parameters.MaxExpandedMB = [int]$config.MaxExpandedMB
    if ($config.PSObject.Properties['Workers']) { $parameters.Workers = [int]$config.Workers }
    if ($config.PSObject.Properties['CpuCorePercent']) { $parameters.CpuCorePercent = [int]$config.CpuCorePercent }
    $summary = & $config.Scanner @parameters
    if ($config.RepeatInSession) { $summary = & $config.Scanner @parameters }
    if ($config.AlternateScanner) { $summary = & $config.AlternateScanner @parameters }
    $summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
    ConvertTo-Json -InputObject @($global:WalletScannerFixtureProgress.ToArray()) -Depth 4 | Set-Content -LiteralPath $ProgressPath -Encoding UTF8
}
catch {
    [pscustomobject]@{ Error = $_.Exception.Message } | ConvertTo-Json | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
    exit 1
}
finally { if ($null -ne $lock) { $lock.Dispose() } }
