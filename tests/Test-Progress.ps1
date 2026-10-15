[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scanner = Join-Path (Split-Path $PSScriptRoot -Parent) 'Scan-CryptoArtifacts.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scanner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'Scanner contains parser errors.' }
$languageTable = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$script:EnglishConsoleText'
}, $true)
if ($null -eq $languageTable) { throw 'Console translation table not found.' }
Invoke-Expression $languageTable.Extent.Text
$languageFunction = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ScanText'
}, $true)
if ($null -eq $languageFunction) { throw 'Console translation function not found.' }
. ([scriptblock]::Create($languageFunction.Extent.Text))
$Language = 'es'
$function = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Update-ScanProgress'
}, $true)
if ($null -eq $function) { throw 'Progress function not found.' }
# Import only the production progress function; never run the scanner or enumerate disks.
. ([scriptblock]::Create($function.Extent.Text))
$script:Captured = New-Object 'Collections.Generic.List[object]'
function Write-Progress {
    param([int]$Id, [int]$ParentId, [string]$Activity, [string]$Status, [string]$CurrentOperation, [int]$PercentComplete, [switch]$Completed)
    $script:Captured.Add([pscustomobject]@{ Id=$Id; Percent=$PercentComplete; Status=$Status })
}
$NoProgress = $false
$resolvedRoots = @('synthetic-location')
$script:Timer = [Diagnostics.Stopwatch]::StartNew()
$script:ScanTimer = [Diagnostics.Stopwatch]::StartNew()
$script:LastProgressTime = [long]-1000
$script:RootIndex = 0
$script:ProgressLabel = 'synthetic-location'
$script:ContentAnalyzedCount = [long]0
$script:ContentReusedCount = [long]0
$script:RootFilesDone = [long]2147483648
$script:RootFilesTotal = [long]2147483649
$script:BytesReadTotal = [long]50954215978
$script:InventoryWorker = $null
$script:ScanPool = $null
$script:ActiveWorkers = 0
$script:WorkerCount = 4
$script:RootInventoryReady = $true
$script:AllInventoryReady = $true
$script:InventoryFiles = [long]0
$script:InventoryCandidates = [long]0
$script:RateSamples = New-Object 'Collections.Generic.Queue[object]'
$cases = @(
    @{ Name='Empty totals'; Total=[long]0; Done=[long]0; RootExpected=0; GlobalExpected=0 },
    @{ Name='Int32 upper boundary'; Total=[long]2147483647; Done=[long]0; RootExpected=0; GlobalExpected=0 },
    @{ Name='First value above Int32'; Total=[long]2147483648; Done=[long]1073741824; RootExpected=50; GlobalExpected=50 },
    @{ Name='Reported 50954215978-byte total'; Total=[long]50954215978; Done=[long]25477107989; RootExpected=50; GlobalExpected=50 },
    @{ Name='One TiB total'; Total=[long]1TB; Done=[long]512GB; RootExpected=50; GlobalExpected=50 },
    @{ Name='Multi-location total'; Total=[long]4GB; All=[long]8GB; Done=[long]1GB; Completed=[long]4GB; Read=[long]768MB; Weight=[long]1GB; RootExpected=43; GlobalExpected=71 },
    @{ Name='Multi-GiB file counters'; Total=[long]16GB; Done=[long]0; Read=[long]3GB; Weight=[long]4GB; RootExpected=18; GlobalExpected=18 },
    @{ Name='Percentages stay below 100 until location finishes'; Total=[long]1TB; Done=[long]1TB; RootExpected=99; GlobalExpected=99 },
    @{ Name='Progress remains monotonic'; Total=[long]1TB; Done=[long]512GB; LastRoot=70; LastGlobal=80; RootExpected=70; GlobalExpected=80 }
)
$passed = 0
foreach ($case in $cases) {
    $script:Captured.Clear()
    $script:RootWorkTotal = [long]$case.Total
    $script:AllWorkTotal = if ($case.ContainsKey('All')) { [long]$case.All } else { [long]$case.Total }
    $script:RootWorkDone = [long]$case.Done
    $script:CompletedRootWork = if ($case.ContainsKey('Completed')) { [long]$case.Completed } else { [long]0 }
    $script:CurrentFileBytes = if ($case.ContainsKey('Read')) { [long]$case.Read } else { [long]0 }
    $script:CurrentFileWeight = if ($case.ContainsKey('Weight')) { [long]$case.Weight } else { [long]0 }
    $script:LastRootPercent = if ($case.ContainsKey('LastRoot')) { [int]$case.LastRoot } else { 0 }
    $script:LastGlobalPercent = if ($case.ContainsKey('LastGlobal')) { [int]$case.LastGlobal } else { 0 }
    Update-ScanProgress -Force
    $root = @($script:Captured | Where-Object { $_.Id -eq 2 })
    $global = @($script:Captured | Where-Object { $_.Id -eq 1 })
    if ($root.Count -ne 1 -or $global.Count -ne 1 -or $root[0].Percent -ne $case.RootExpected -or $global[0].Percent -ne $case.GlobalExpected) { throw ('FAIL: ' + $case.Name) }
    $passed++
    Write-Host ('PASS: ' + $case.Name)
}
$script:ScanTimer = [pscustomobject]@{ ElapsedMilliseconds=[long]10000; Elapsed=[pscustomobject]@{ TotalSeconds=10.0 } }
$script:RootWorkDone = [long]1TB
$script:RootWorkTotal = [long]2TB
$script:AllWorkTotal = [long]2TB
$script:CompletedRootWork = [long]0
$script:CurrentFileBytes = [long]0
$script:CurrentFileWeight = [long]0
$script:LastRootPercent = 0
$script:LastGlobalPercent = 0
$script:BytesReadTotal = [long]10MB
$script:RateSamples.Clear()
$script:RateSamples.Enqueue([pscustomobject]@{ Milliseconds=[long]2000; Bytes=[long]2MB })
$script:RootInventoryReady = $false
$script:AllInventoryReady = $false
$script:Captured.Clear()
Update-ScanProgress -Force
if (@($script:Captured | Where-Object { $_.Percent -ne -1 }).Count -ne 0 -or $script:EstimatedRemaining -ne 'calculando total') { throw 'FAIL: Unknown totals must not show percentages or ETA.' }
$passed++; Write-Host 'PASS: Reading before inventory completion shows activity without a percentage or ETA'
if ([Math]::Abs($script:AverageReadMBps - 1.0) -gt 0.0001 -or [Math]::Abs($script:RecentReadMBps - 1.0) -gt 0.0001) { throw 'FAIL: Effective read rates.' }
$passed++; Write-Host 'PASS: Average and recent read rates use observed bytes without double counting'
$script:RootInventoryReady = $true
$script:Captured.Clear()
Update-ScanProgress -Force
if (@($script:Captured | Where-Object { $_.Id -eq 2 -and $_.Percent -eq 50 }).Count -ne 1 -or @($script:Captured | Where-Object { $_.Id -eq 1 -and $_.Percent -eq -1 }).Count -ne 1) { throw 'FAIL: Independent root/global inventory readiness.' }
$passed++; Write-Host 'PASS: A completed root inventory enables its bar while global discovery continues'
$script:AllInventoryReady = $true
$script:Captured.Clear()
Update-ScanProgress -Force
if (@($script:Captured | Where-Object { $_.Percent -eq 50 }).Count -ne 2 -or $script:EstimatedRemaining -notmatch '10s aprox') { throw 'FAIL: Percentage and ETA after inventory completion.' }
$passed++; Write-Host 'PASS: Known totals include work already completed and produce a bounded ETA'
$script:RootWorkDone = [long]0
$script:LastRootPercent = 0
$script:LastGlobalPercent = 0
Update-ScanProgress -Force
if ($script:EstimatedRemaining -ne 'calculando tasa') { throw 'FAIL: ETA before measured work.' }
$passed++; Write-Host 'PASS: ETA waits for a measured processing rate'
Write-Host ('ALL PASSED: {0} progress cases; synthetic counters only, no disks enumerated.' -f $passed)
