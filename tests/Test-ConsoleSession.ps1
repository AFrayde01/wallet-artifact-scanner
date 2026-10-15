[CmdletBinding()]
param([switch]$NativeChild,[string]$ResultPath,[string]$PreviousScannerPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
[void][Reflection.Assembly]::LoadFile((Join-Path $repo 'CryptoMnemonicScanner-10.12.dll'))
$tokens=$null; $errorsFound=$null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Scan-CryptoArtifacts.ps1'),[ref]$tokens,[ref]$errorsFound)
$function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-ScanConsoleSession' },$true)
if ($errorsFound.Count -or $null -eq $function) { throw 'No se pudo importar la función real de consola.' }
. ([scriptblock]::Create($function.Extent.Text))
$initialSession = Start-ScanConsoleSession
$initialSession.Dispose()
if ($NativeChild) {
    $session = $null
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ConsoleModeTest {
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int identifier);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetConsoleMode(IntPtr handle, out uint mode);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetConsoleMode(IntPtr handle, uint mode);
    public static uint Read() { uint mode; if (!GetConsoleMode(GetStdHandle(-10),out mode)) throw new InvalidOperationException("No hay consola propia para esta prueba."); return mode; }
    public static void Write(uint mode) { if (!SetConsoleMode(GetStdHandle(-10),mode)) throw new InvalidOperationException("No se pudo configurar la consola de prueba."); }
}
'@
    $original = [ConsoleModeTest]::Read()
    try {
        $before = $original -bor [uint32]0x00C0
        [ConsoleModeTest]::Write($before)
        $session = Start-ScanConsoleSession
        $during = [ConsoleModeTest]::Read()
        if (-not $session.IsConsole -or -not $session.Protected -or ($during -band 0x0040) -ne 0 -or $during -ne [CryptoConsoleInputSession]::ScanMode($before)) { throw 'La selección automática no se desactivó correctamente.' }
        $session.Dispose(); $session.Dispose(); $session = $null
        $after = [ConsoleModeTest]::Read()
        if ($after -ne $before) { throw 'No se restauró el modo original de la consola.' }
        try { $session = Start-ScanConsoleSession; throw 'interrupción sintética' } catch { } finally { $session.Dispose(); $session = $null }
        if ([ConsoleModeTest]::Read() -ne $before) { throw 'No se restauró la consola tras una excepción.' }
        [pscustomobject]@{ Passed=$true; Before=$before; During=$during; After=$after; ExceptionRestored=$true } | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    }
    finally {
        if ($null -ne $session) { $session.Dispose() }
        [ConsoleModeTest]::Write($original)
    }
    exit 0
}
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$base = Join-Path $tempRoot ('wallet-scanner-console-' + [guid]::NewGuid().ToString('D'))
[void][IO.Directory]::CreateDirectory($base)
$script:Passed=0
function Assert-Console([bool]$Value,[string]$Name) { if (-not $Value) { throw ('FAIL: ' + $Name) }; $script:Passed++; Write-Host ('PASS: ' + $Name) }
try {
    Assert-Console ($function.Extent.Text -notmatch '\bAdd-Type\b' -and [CryptoConsoleInputSession].Assembly -eq [CryptoWindowsIO].Assembly) 'Console protection comes from the precompiled scanner assembly'
    foreach ($mode in [uint32[]]@(0,0x40,0x80,0xC0,0x1F7,0x297)) {
        $scanMode=[CryptoConsoleInputSession]::ScanMode($mode)
        Assert-Console (($scanMode -band 0x40) -eq 0 -and ($scanMode -band 0x80) -ne 0 -and (($scanMode -bxor $mode) -band [Convert]::ToUInt32('FFFFFF3F',16)) -eq 0) ('Only QuickEdit and extended flags change: ' + $mode)
    }
    $nativeResult = Join-Path $base 'native.json'
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $child = Start-Process -FilePath $windowsPowerShell -ArgumentList ('-NoProfile -File "' + $PSCommandPath + '" -NativeChild -ResultPath "' + $nativeResult + '"') -WindowStyle Hidden -PassThru
    if (-not $child.WaitForExit(15000)) { Stop-Process -Id $child.Id; throw 'La prueba de consola excedió el tiempo permitido.' }
    $native = Get-Content -LiteralPath $nativeResult -Raw | ConvertFrom-Json
    Assert-Console ($native.Passed -and $native.Before -eq $native.After -and $native.ExceptionRestored) 'A separate hidden console applies and restores its mode, including exceptional completion'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $repo 'dist\windows-crypto-artifact-scan.zip'),$base)
    $runtime = Join-Path $base 'windows-crypto-artifact-scan'
    # A caller can supply the previous script to verify an actual upgrade.
    # Otherwise use a synthetic baseline with console protection disabled.
    if ($PreviousScannerPath) {
        Copy-Item -LiteralPath $PreviousScannerPath -Destination (Join-Path $runtime 'Scan-CryptoArtifacts.ps1') -Force
    } else {
        $baselineFunction = @'
function Start-ScanConsoleSession {
    $session = [pscustomobject]@{ IsConsole=$false; Protected=$false }
    $session | Add-Member ScriptMethod Dispose {} -PassThru
}
'@
        $baseline = [IO.File]::ReadAllText((Join-Path $repo 'Scan-CryptoArtifacts.ps1')).Replace($function.Extent.Text,$baselineFunction)
        [IO.File]::WriteAllText((Join-Path $runtime 'Scan-CryptoArtifacts.ps1'),$baseline,[Text.UTF8Encoding]::new($true))
    }
    $inputRoot=Join-Path $base 'input'; [void][IO.Directory]::CreateDirectory($inputRoot)
    [IO.File]::WriteAllText((Join-Path $inputRoot 'notes.txt'),'bitcoin wallet backup',[Text.UTF8Encoding]::new($false))
    $csv = Join-Path $base 'result.csv'; $state = [IO.Path]::ChangeExtension($csv,'.scanstate')
    $config = @{ Scanner=(Join-Path $runtime 'Scan-CryptoArtifacts.ps1'); Roots=@($inputRoot); Csv=$csv;
        Answers=@(); NoProgress=$false; NoCache=$false; Rescan=$false; LockFile=''; MaxMB=256; RepeatInSession=$false;
        AlternateScanner=''; StopAfterFiles=0; CheckpointFiles=1000; MaxDocumentMB=32; MaxExpandedMB=256; Workers=0; CpuCorePercent=80 }
    $configPath=Join-Path $base 'config.json'; $summaryPath=Join-Path $base 'summary.json'
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $argsList=@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1'),'-ConfigPath',$configPath,'-SummaryPath',$summaryPath,'-ProgressPath',(Join-Path $base 'progress.json'))
    $firstOutput=@(& $windowsPowerShell @argsList)
    if ($LASTEXITCODE -ne 0) { throw ($firstOutput -join ' ') }
    $first=Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    $csvHash=(Get-FileHash -LiteralPath $csv).Hash; $stateHash=(Get-FileHash -LiteralPath $state).Hash
    $csvTime=(Get-Item -LiteralPath $csv).LastWriteTimeUtc; $stateTime=(Get-Item -LiteralPath $state).LastWriteTimeUtc
    Copy-Item -LiteralPath (Join-Path $repo 'Scan-CryptoArtifacts.ps1') -Destination (Join-Path $runtime 'Scan-CryptoArtifacts.ps1') -Force
    $secondOutput=@(& $windowsPowerShell @argsList)
    if ($LASTEXITCODE -ne 0) { throw ($secondOutput -join ' ') }
    $second=Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    # Version 9 also fingerprints the exact runtime manifest used to recognize public copies.
    Assert-Console ($first.AlgorithmFingerprint -ne $second.AlgorithmFingerprint -and $second.ContentReused -eq 0 -and $second.ContentAnalyzed -eq 1) 'A changed runtime manifest invalidates its cached copy classifications'
    Assert-Console ((Get-FileHash -LiteralPath $csv).Hash -eq $csvHash -and (Get-Item -LiteralPath $csv).LastWriteTimeUtc -eq $csvTime -and
        (Get-FileHash -LiteralPath $state).Hash -ne $stateHash) 'Manifest update preserves identical CSV bytes and timestamp and updates cache identity'
    Assert-Console ($second.Incidents -eq 0 -and ($secondOutput -join ' ') -match 'Terminado en') 'The updated script returns its final summary and exits'
    $stateHash=(Get-FileHash -LiteralPath $state).Hash; $stateTime=(Get-Item -LiteralPath $state).LastWriteTimeUtc
    $thirdOutput=@(& $windowsPowerShell @argsList)
    if ($LASTEXITCODE -ne 0) { throw ($thirdOutput -join ' ') }
    $third=Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    Assert-Console ($third.AlgorithmFingerprint -eq $second.AlgorithmFingerprint -and $third.ContentReused -eq 1 -and $third.ContentAnalyzed -eq 0) 'An unchanged runtime manifest reuses the verified cache'
    Assert-Console ((Get-FileHash -LiteralPath $csv).Hash -eq $csvHash -and (Get-Item -LiteralPath $csv).LastWriteTimeUtc -eq $csvTime -and
        (Get-FileHash -LiteralPath $state).Hash -eq $stateHash -and (Get-Item -LiteralPath $state).LastWriteTimeUtc -eq $stateTime) 'Repeating the updated runtime preserves CSV and cache bytes and timestamps'
    Write-Host ('ALL PASSED: {0} console assertions; synthetic input and a separate hidden console only.' -f $script:Passed)
}
finally {
    $target=[IO.Path]::GetFullPath($base)
    if (-not $target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($target) -notmatch '^wallet-scanner-console-[0-9a-f-]{36}$') { throw 'Unsafe console fixture cleanup.' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
