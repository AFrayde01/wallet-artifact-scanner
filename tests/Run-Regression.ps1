[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ResultDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
[void][IO.Directory]::CreateDirectory($ResultDirectory)
$results=[Collections.Generic.List[object]]::new()
foreach ($name in @('Test-Scanner','Test-DetectionQuality','Test-ContextQuality','Test-DirectoryPolicy','Test-Exclusions','Test-JournalIsolation','Test-Progress','Test-Streaming','Test-Parallel','Test-Operational','Test-ConsoleSession','Test-ReviewReports')) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $previousPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $output=@(& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot ($name+'.ps1')) 2>&1)
        $code=$LASTEXITCODE
    } finally { $ErrorActionPreference=$previousPreference }
    $timer.Stop()
    $log=[string]::Join([Environment]::NewLine,[string[]]$output)+[Environment]::NewLine
    [IO.File]::WriteAllText((Join-Path $ResultDirectory ($name+'.log')),$log,[Text.UTF8Encoding]::new($true))
    $assertions=0
    foreach ($line in $output) { if ([string]$line -match '^ALL PASSED:\s+(\d+)') { $assertions=[int]$Matches[1] } }
    if ($code -ne 0 -or $assertions -eq 0) { throw ('Regression failed: '+$name+'; inspect its log.') }
    $results.Add([pscustomobject]@{Suite=$name;Assertions=$assertions;Seconds=$timer.Elapsed.TotalSeconds;ExitCode=$code})
    Write-Host ($name + ': ' + $assertions + ' assertions passed.')
}
$summary=[ordered]@{WindowsPowerShell=$PSVersionTable.PSVersion.ToString();DetectorSha256=(Get-FileHash -LiteralPath (Join-Path $repo 'CryptoMnemonicScanner-10.12.dll')).Hash;Assertions=($results|Measure-Object Assertions -Sum).Sum;Suites=$results.ToArray()}
$summary|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $ResultDirectory 'summary.json') -Encoding UTF8
Write-Host ('Total: ' + $summary.Assertions + ' assertions passed.')
