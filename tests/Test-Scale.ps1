[CmdletBinding()]
param(
    [ValidateRange(1000,1000000)][int]$FileCount = 20000,
    [ValidateRange(1,256)][int]$LargeFileMB = 240,
    [ValidateRange(1,100)][int]$CpuCorePercent = 50,
    [string]$ResultPath,
    [switch]$Progress
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ResultPath)) { $ResultPath = Join-Path $PSScriptRoot 'scale-results.json' }
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$base = Join-Path $tempRoot ('wallet-scanner-scale-' + [guid]::NewGuid().ToString('D'))
$inputRoot = Join-Path $base 'input'
New-Item -ItemType Directory -Path $inputRoot -Force | Out-Null
$encoding = [Text.UTF8Encoding]::new($false)
function Run-Scale([string]$Name) {
    $result = Join-Path $base ($Name + '.json')
    $runner = Join-Path $PSScriptRoot 'Invoke-ScaleScan.ps1'
    $csv = Join-Path $base 'result.csv'
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = [Diagnostics.ProcessStartInfo]::new()
    $process.StartInfo.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $process.StartInfo.Arguments = '-NoProfile -File "' + $runner + '" -InputRoot "' + $inputRoot + '" -Csv "' + $csv + '" -ResultJson "' + $result + '"'
    $process.StartInfo.Arguments += ' -CpuCorePercent ' + $CpuCorePercent
    if ($Progress) { $process.StartInfo.Arguments += ' -Progress' }
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    [void]$process.Start()
    $output = $process.StandardOutput.ReadToEndAsync()
    $errors = $process.StandardError.ReadToEndAsync()
    [long]$peak = 0
    try {
        while (-not $process.HasExited) {
            $process.Refresh()
            try { $peak = [Math]::Max($peak,$process.PeakWorkingSet64) } catch {}
            Start-Sleep -Milliseconds 250
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw ('Scale runner failed: ' + $errors.GetAwaiter().GetResult()) }
        $summary = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        if ($summary.FilesEnumerated -ne ($FileCount + 1) -or $summary.Incidents -ne 0 -or $summary.Findings -ne 0) { throw 'Unexpected scale scan result.' }
        return [pscustomobject]@{ Run=$Name; AlgorithmFingerprint=$summary.AlgorithmFingerprint; Seconds=$summary.ElapsedSeconds; PeakWorkingSetMB=[Math]::Round($peak/1MB,1);
            Files=$summary.FilesEnumerated; BytesRead=$summary.BytesRead; Analyzed=$summary.ContentAnalyzed; Reused=$summary.ContentReused; Checkpoints=$summary.Checkpoints;
            InventoryComplete=$summary.InventoryComplete; AverageReadMBps=$summary.AverageReadMBps;
            CpuCorePercent=$summary.CpuCorePercent; AllowedPhysicalCores=$summary.AllowedPhysicalCores; WorkerCount=$summary.WorkerCount }
    } finally { $process.Dispose() }
}
try {
    Write-Host ('Creando ' + $FileCount + ' archivos sintéticos y un archivo de ' + $LargeFileMB + ' MB.')
    for ($i=0;$i -lt $FileCount;$i++) {
        $directory = Join-Path $inputRoot ([int][Math]::Floor($i/1000)).ToString('D4')
        if ($i % 1000 -eq 0) { [void][IO.Directory]::CreateDirectory($directory) }
        [IO.File]::WriteAllText((Join-Path $directory ($i.ToString('D8') + '.txt')),'ordinary neutral notes 012345',$encoding)
    }
    $large = Join-Path $inputRoot 'large.log'
    $stream = [IO.File]::Create($large)
    $buffer = [Text.Encoding]::ASCII.GetBytes('z' * 1MB)
    try { for ($i=0;$i -lt $LargeFileMB;$i++) { $stream.Write($buffer,0,$buffer.Length) } } finally { $stream.Dispose() }
    $largeHash = (Get-FileHash -LiteralPath $large).Hash
    Write-Host 'Medición: análisis completo.'
    $first = Run-Scale 'full'
    Write-Host 'Medición: repetición con verificación SHA-256.'
    $repeat = Run-Scale 'repeat'
    if ($repeat.Analyzed -ne 0 -or $repeat.Reused -ne ($FileCount + 1)) { throw 'Scale cache regression.' }
    if ((Get-FileHash -LiteralPath $large).Hash -ne $largeHash) { throw 'Source bytes changed.' }
    [pscustomobject]@{ WindowsPowerShell=$PSVersionTable.PSVersion.ToString(); DateUtc=[DateTime]::UtcNow.ToString('o');
        SyntheticOnly=$true; ProgressEnabled=[bool]$Progress; CpuCorePercent=$CpuCorePercent; FileCount=($FileCount + 1); LargeFileMB=$LargeFileMB; Runs=@($first,$repeat) } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    Get-Content -LiteralPath $ResultPath
}
finally {
    $target = [IO.Path]::GetFullPath($base)
    if (-not $target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected scale cleanup target.' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
