[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$base = Join-Path $tempRoot ('wallet-scanner-parallel-' + [guid]::NewGuid().ToString('D'))
$inputRoot = Join-Path $base 'input'
[void][IO.Directory]::CreateDirectory($inputRoot)
$script:Passed = 0
function Assert-Parallel([bool]$Value, [string]$Name) {
    if (-not $Value) { throw ('FAIL: ' + $Name) }
    $script:Passed++; Write-Host ('PASS: ' + $Name)
}
function Run-ParallelFixture([int]$Workers, [bool]$Rescan, [int]$CpuCorePercent = 50) {
    $config = @{ Scanner=(Join-Path $repo 'Scan-CryptoArtifacts.ps1'); Roots=@($inputRoot); Csv=(Join-Path $base 'result.csv');
        Answers=@(); NoProgress=$false; NoCache=$false; Rescan=$Rescan; LockFile=''; MaxMB=256; RepeatInSession=$false;
        AlternateScanner=''; StopAfterFiles=0; CheckpointFiles=1000; MaxDocumentMB=32; MaxExpandedMB=256; Workers=$Workers; CpuCorePercent=$CpuCorePercent }
    $configPath = Join-Path $base 'config.json'
    $summaryPath = Join-Path $base 'summary.json'
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $console = @(& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath (Join-Path $base 'progress.json'))
    if ($LASTEXITCODE -ne 0) { throw ('Parallel fixture failed: ' + ($console -join ' ')) }
    return Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
}
$budget = $null
$pool = $null
try {
    [void][Reflection.Assembly]::LoadFile((Join-Path $repo 'CryptoMnemonicScanner-10.12.dll'))
    $plan = [CryptoCpuBudget]::Select([uint64[]]@(3,12,48,192,768,3072,12288,49152), [uint64]65535)
    Assert-Parallel ($plan.SelectedPhysicalCores -eq 4 -and $plan.SelectedLogicalProcessors -eq 8 -and $plan.Mask -eq 255) 'Eight SMT cores select four physical cores and their eight logical processors'
    $odd = [CryptoCpuBudget]::Select([uint64[]]@(1,2,4,8,16),[uint64]31)
    Assert-Parallel ($odd.SelectedPhysicalCores -eq 2 -and $odd.Mask -eq 3) 'Odd core counts round down and remain below fifty percent'
    $subset = [CryptoCpuBudget]::Select([uint64[]]@(3,12,48,192,768,3072,12288,49152),[uint64]13107)
    Assert-Parallel ($subset.SelectedPhysicalCores -eq 2 -and ($subset.Mask -band [uint64]13107) -eq $subset.Mask) 'Existing affinity restrictions are respected'
    $one = [CryptoCpuBudget]::Select([uint64[]]@(3),[uint64]3,50)
    Assert-Parallel ($one.SelectedPhysicalCores -eq 1 -and $one.MinimumCoreApplied -and $one.EffectiveCorePercent -eq 100) 'A single-core machine reports the explicit minimum-one-core exception'
    foreach ($coreCount in @(1,2,3,5,8,16,32,64)) {
        $masks = [uint64[]]@(for ($i=0; $i -lt $coreCount; $i++) { [uint64]1 -shl $i })
        $allowed = [uint64]0
        foreach ($mask in $masks) { $allowed = $allowed -bor $mask }
        foreach ($percent in @(1,25,50,75,100)) {
            $expected = [Math]::Max(1,[int][Math]::Floor($coreCount * $percent / 100.0))
            $selection = [CryptoCpuBudget]::Select($masks,$allowed,$percent)
            Assert-Parallel ($selection.SelectedPhysicalCores -eq $expected -and $selection.RequestedCorePercent -eq $percent -and
                [Math]::Abs($selection.EffectiveCorePercent - (100.0 * $expected / $coreCount)) -lt 0.000001 -and
                $selection.MinimumCoreApplied -eq ($coreCount * $percent -lt 100) -and
                $selection.SelectedLogicalProcessors -eq $expected -and ($selection.Mask -band $allowed) -eq $selection.Mask -and
                $selection.GetWorkerCount(0) -eq [Math]::Min(32,$expected) -and $selection.GetWorkerCount(1) -eq 1) ('Percentage {0}% on {1} cores has the expected physical budget and bounded workers' -f $percent,$coreCount)
        }
    }
    foreach ($invalid in @(0,101)) {
        $rejected = $false
        try { [void][CryptoCpuBudget]::Select([uint64[]]@(3),[uint64]3,$invalid) } catch { $rejected = $true }
        Assert-Parallel $rejected ('Invalid CPU percentage is rejected: ' + $invalid)
    }
    $rejected = $false
    try { [void][CryptoCpuBudget]::Select([uint64[]]@(3),[uint64]0,50) } catch { $rejected = $true }
    Assert-Parallel $rejected 'An empty CPU allocation is rejected'
    $originalAffinity = [Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity.ToInt64()
    $budget = [CryptoCpuBudget]::new()
    $actualMask = [Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity.ToInt64()
    Assert-Parallel ($actualMask -eq [long]$budget.Plan.Mask -and $budget.Plan.SelectedPhysicalCores -eq [Math]::Max(1,[int][Math]::Floor($budget.Plan.AvailablePhysicalCores / 2.0))) 'Windows applies and verifies the physical-core limit to the whole process'
    $childScript = Join-Path $base 'Read-Affinity.ps1'
    $childText = 'param([string]$Output)' + [Environment]::NewLine +
        '[IO.File]::WriteAllText($Output,[Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity.ToInt64().ToString("X"))'
    [IO.File]::WriteAllText($childScript,$childText,[Text.UTF8Encoding]::new($true))
    $childOutput = Join-Path $base 'affinity.txt'
    & powershell.exe -NoProfile -File $childScript -Output $childOutput
    Assert-Parallel (([IO.File]::ReadAllText($childOutput)) -eq $budget.Plan.Mask.ToString('X')) 'An auxiliary PowerShell process inherits the same restricted CPU mask'
    $budget.Dispose(); $budget = $null
    Assert-Parallel ([Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity.ToInt64() -eq $originalAffinity) 'Original host affinity is restored after scanning'

    $unit = 'ordinary neutral notes 0123456789 ' + [Environment]::NewLine
    $text = ($unit * [int][Math]::Ceiling(2MB / $unit.Length)).Substring(0,2MB)
    $sourceHashes = @{}
    for ($i=0; $i -lt 8; $i++) {
        $path = Join-Path $inputRoot ('sample-' + $i + '.txt')
        [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))
        $sourceHashes[$path] = (Get-FileHash -LiteralPath $path).Hash
    }
    $positive = Join-Path $inputRoot 'notes.txt'
    [IO.File]::WriteAllText($positive,'bitcoin wallet private_key=' + ('e' * 64),[Text.UTF8Encoding]::new($false))
    $sourceHashes[$positive] = (Get-FileHash -LiteralPath $positive).Hash
    $csv = Join-Path $base 'result.csv'
    $state = [IO.Path]::ChangeExtension($csv,'.scanstate')
    $single = Run-ParallelFixture 1 $false
    $csvHash = (Get-FileHash -LiteralPath $csv).Hash
    $stateHash = (Get-FileHash -LiteralPath $state).Hash
    $csvTime = (Get-Item -LiteralPath $csv).LastWriteTimeUtc
    $stateTime = (Get-Item -LiteralPath $state).LastWriteTimeUtc
    $parallel = Run-ParallelFixture 32 $true
    Assert-Parallel ($single.ContentAnalyzed -eq 9 -and $parallel.ContentAnalyzed -eq 9 -and $parallel.Incidents -eq 0) 'Sequential and parallel analysis cover all synthetic files without errors'
    Assert-Parallel ($parallel.WorkerCount -eq $parallel.AllowedPhysicalCores -and $parallel.PeakWorkers -gt 1 -and $parallel.PeakWorkers -le $parallel.WorkerCount) 'Multiple files really overlap and an oversized worker request is capped'
    Assert-Parallel ($parallel.BytesRead -eq $single.BytesRead -and $parallel.BytesRead -eq ((8L * 2MB) + (Get-Item -LiteralPath $positive).Length)) 'Concurrent progress counts source bytes exactly once'
    Assert-Parallel ((Get-FileHash -LiteralPath $csv).Hash -eq $csvHash -and (Get-FileHash -LiteralPath $state).Hash -eq $stateHash) 'Parallel completion order preserves identical CSV and cache bytes'
    Assert-Parallel ((Get-Item -LiteralPath $csv).LastWriteTimeUtc -eq $csvTime -and (Get-Item -LiteralPath $state).LastWriteTimeUtc -eq $stateTime) 'Forced parallel analysis does not rewrite identical outputs'
    $secondaryCsv = [IO.Path]::ChangeExtension($csv, '.secundarios.csv')
    $secondaryRows = @(Import-Csv -LiteralPath $secondaryCsv)
    $header = '"Ubicacion","Tipo","FechaCreacionUtc","FechaModificacionUtc"'
    $unvalidatedKey = @($secondaryRows | Where-Object { $_.Ubicacion -eq $positive -and $_.Tipo -eq 'candidata_clave_hexadecimal_sin_validar' })
    Assert-Parallel (-not [IO.File]::ReadAllText($csv).Contains('e' * 64) -and
        -not [IO.File]::ReadAllText($secondaryCsv).Contains('e' * 64) -and
        [IO.File]::ReadAllLines($csv)[0] -eq $header -and
        [IO.File]::ReadAllLines($secondaryCsv)[0] -eq $header -and
        $unvalidatedKey.Count -eq 1 -and
        -not [string]::IsNullOrWhiteSpace($unvalidatedKey[0].FechaCreacionUtc) -and
        -not [string]::IsNullOrWhiteSpace($unvalidatedKey[0].FechaModificacionUtc)) 'Parallel output includes both file timestamps, keeps an unvalidated key secondary and never exports it'
    $repeat = Run-ParallelFixture 2 $false 25
    Assert-Parallel ($repeat.CpuCorePercent -eq 25 -and $repeat.AllowedPhysicalCores -eq [Math]::Max(1,[int][Math]::Floor($repeat.AvailablePhysicalCores / 4.0))) 'The CLI percentage selects the corresponding hardware budget'
    Assert-Parallel ($repeat.ContentAnalyzed -eq 0 -and $repeat.ContentReused -eq 9 -and -not $repeat.CsvWritten -and -not $repeat.StateWritten -and
        $repeat.AlgorithmFingerprint -eq $parallel.AlgorithmFingerprint) 'Changing core percentage and worker count preserves verified cache and idempotency'
    $more = Run-ParallelFixture 32 $false 75
    Assert-Parallel ($more.CpuCorePercent -eq 75 -and $more.AllowedPhysicalCores -eq [Math]::Max(1,[int][Math]::Floor($more.AvailablePhysicalCores * 0.75)) -and
        $more.WorkerCount -eq [Math]::Min(32,$more.AllowedPhysicalCores) -and $more.ContentReused -eq 9 -and -not $more.CsvWritten -and -not $more.StateWritten) 'Raising the percentage also caps workers and reuses identical results'
    foreach ($invalid in @(0,101)) {
        $rejected = $false
        try { [void](Run-ParallelFixture 2 $false $invalid) } catch { $rejected = $true }
        Assert-Parallel ($rejected -and (Get-FileHash -LiteralPath $csv).Hash -eq $csvHash -and
            (Get-FileHash -LiteralPath $state).Hash -eq $stateHash) ('The CLI rejects invalid percentage before changing scan output: ' + $invalid)
    }
    # Restore the successful run's progress capture after intentionally rejected CLI runs.
    [void](Run-ParallelFixture 2 $false 25)
    $progress = @(Get-Content -LiteralPath (Join-Path $base 'progress.json') -Raw | ConvertFrom-Json)
    Assert-Parallel (@($progress | Where-Object { $_.Id -eq 1 -and $_.CurrentOperation -match 'trabajadores:' }).Count -gt 0) 'Progress reports worker utilization'

    $wordListRoot=Join-Path $repo 'resources\wordlists'
    [CryptoMnemonicScanner]::Configure([IO.File]::ReadAllLines((Join-Path $wordListRoot 'bip39-english.txt')),
        [IO.File]::ReadAllLines((Join-Path $wordListRoot 'bip39-spanish.txt')), [IO.File]::ReadAllLines((Join-Path $wordListRoot 'monero-english.txt')),
        [IO.File]::ReadAllLines((Join-Path $wordListRoot 'monero-english-old.txt')), [IO.File]::ReadAllLines((Join-Path $wordListRoot 'monero-spanish.txt')),
        [IO.File]::ReadAllLines((Join-Path $wordListRoot 'slip39-english.txt')))
    [CryptoFileScanner]::Configure([string[]]@('cryptocurrency_terms'), [string[]]@('\bbitcoin\b'))
    $budget = [CryptoCpuBudget]::new()
    $pool = [CryptoParallelScanner]::new($budget.Plan.GetWorkerCount(0),256MB,$false)
    $info = [CryptoWindowsIO]::GetInfo((Join-Path $inputRoot 'sample-0.txt'))
    $limit = $pool.WorkerCount + $pool.QueueCapacity
    $timer = [Diagnostics.Stopwatch]::StartNew()
    for ($i=0; $i -lt $limit; $i++) {
        $work = [CryptoScanWorkItem]::new($info.FullName,('job-' + $i),$info,$null,$false,$false,[string[]]@())
        while (-not $pool.TrySubmit($work)) { if ($timer.Elapsed.TotalSeconds -gt 20) { throw 'Queue fixture timed out.' }; Start-Sleep -Milliseconds 10 }
    }
    $extra = [CryptoScanWorkItem]::new($info.FullName,'extra',$info,$null,$false,$false,[string[]]@())
    Assert-Parallel (-not $pool.TrySubmit($extra) -and $pool.GetSnapshot().Outstanding -eq $limit) 'Queued, active and completed-but-unconsumed files share one bounded capacity'
    $cancelTimer = [Diagnostics.Stopwatch]::StartNew()
    $pool.Cancel(); $pool.Dispose()
    $cancelTimer.Stop()
    Assert-Parallel ($pool.GetSnapshot().Active -eq 0 -and $cancelTimer.Elapsed.TotalSeconds -lt 10) 'Cancellation stops and joins every analysis worker promptly'
    $pool = $null; $budget.Dispose(); $budget = $null
    foreach ($path in $sourceHashes.Keys) { Assert-Parallel ((Get-FileHash -LiteralPath $path).Hash -eq $sourceHashes[$path]) ('Source bytes unchanged: ' + [IO.Path]::GetFileName($path)) }
    [pscustomobject]@{ SyntheticOnly=$true; DateUtc=[DateTime]::UtcNow.ToString('o'); Files=9; Bytes=$single.BytesRead;
        AllowedPhysicalCores=$parallel.AllowedPhysicalCores; AvailablePhysicalCores=$parallel.AvailablePhysicalCores; AllowedLogicalProcessors=$parallel.AllowedLogicalProcessors;
        WorkerCount=$parallel.WorkerCount; PeakWorkers=$parallel.PeakWorkers; SequentialSeconds=$single.ElapsedSeconds; ParallelSeconds=$parallel.ElapsedSeconds;
        Speedup=($single.ElapsedSeconds / $parallel.ElapsedSeconds); Assertions=$script:Passed } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'parallel-results.json') -Encoding UTF8
    Write-Host ('ALL PASSED: {0} parallel assertions; synthetic files only.' -f $script:Passed)
    Get-Content -LiteralPath (Join-Path $PSScriptRoot 'parallel-results.json')
}
finally {
    if ($null -ne $pool) { $pool.Dispose() }
    if ($null -ne $budget) { $budget.Dispose() }
    $target = [IO.Path]::GetFullPath($base)
    if (-not $target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($target) -notmatch '^wallet-scanner-parallel-[0-9a-f-]{36}$') { throw 'Unsafe parallel fixture cleanup.' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
