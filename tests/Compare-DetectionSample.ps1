[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ScannerDirectory,
    [Parameter(Mandatory=$true)][string]$OriginalCsv,
    [Parameter(Mandatory=$true)][string]$SampleCsv,
    [Parameter(Mandatory=$true)][string]$OriginalRoot,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateRange(1,2147483647)][int]$MinimumCacheEntries = 1
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$originalHash=(Get-FileHash -LiteralPath $originalCsv).Hash
$statePath=[IO.Path]::ChangeExtension($originalCsv,'.scanstate')
$stateTicks=(Get-Item -LiteralPath $statePath).LastWriteTimeUtc.Ticks
[void][Reflection.Assembly]::LoadFile((Join-Path $ScannerDirectory 'CryptoMnemonicScanner-10.12.dll'))
$names=@('bip39-english.txt','bip39-spanish.txt','monero-english.txt','monero-english-old.txt','monero-spanish.txt','slip39-english.txt')
$wordListRoot=Join-Path $ScannerDirectory 'resources\wordlists'
$lists=[string[][]]::new(6)
for($i=0;$i -lt 6;$i++) { $lists[$i]=[IO.File]::ReadAllLines((Join-Path $wordListRoot $names[$i]),[Text.Encoding]::UTF8) }
[CryptoMnemonicScanner]::Configure($lists[0],$lists[1],$lists[2],$lists[3],$lists[4],$lists[5])
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $ScannerDirectory 'Scan-CryptoArtifacts.ps1'),[ref]$null,[ref]$null)
$rulesAst=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:TextRules'},$true)
$rules=@(& ([scriptblock]::Create($rulesAst.Right.Extent.Text)))
[CryptoFileScanner]::Configure([string[]]$rules.Evidence,[string[]]$rules.Pattern)
$categoryAst=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-FindingCategory'},$true)
if ($categoryAst) { Invoke-Expression $categoryAst.Extent.Text; [CryptoFileScanner]::ConfigurePublicDictionaries([string[]]@($names|ForEach-Object {(Get-FileHash -LiteralPath (Join-Path $ScannerDirectory $_)).Hash})) }
$reader=[IO.BinaryReader]::new([IO.File]::OpenRead($statePath))
try { $method=[CryptoScanCache].GetMethod('ReadField',[Reflection.BindingFlags]'Static,NonPublic'); $sig=$method.Invoke($null,@($reader)); $algorithm=$method.Invoke($null,@($reader)); $roots=$method.Invoke($null,@($reader)); $entryCount=$reader.ReadInt32() } finally {$reader.Dispose()}
$ids=[string[]](@($rules.Evidence)+@('possible_bip39_mnemonic_phrase','possible_monero_mnemonic_phrase','possible_slip39_share','possible_encrypted_ethereum_keystore','possible_solana_keypair_json','validated_bitcoin_private_key','validated_extended_private_key','bitcoin_core_wallet_filename','wallet_or_crypto_related_filename'))
$cache=[CryptoScanCache]::new($statePath,$algorithm,$roots,$ids,$false,'')
if ($cache.Status -ne 'verificación SHA-256' -or $entryCount -lt $MinimumCacheEntries) {throw 'Original scan cache failed validation.'}
$rootKey=[CryptoWindowsIO]::Identify($OriginalRoot).LocationKey
$sample=@(Import-Csv -LiteralPath $SampleCsv|Where-Object {$_.Estado -eq 'leido_solo_metadata' -and $_.CoincideHashEscaneo -eq 'True'})
if($sample.Count -eq 0) { throw 'The supplied sample CSV has no rows verified against the original scan.' }
$records=[Collections.Generic.List[object]]::new(); $skipped=[Collections.Generic.List[object]]::new(); $metadata=[Collections.Generic.List[object]]::new()
$timer=[Diagnostics.Stopwatch]::StartNew(); $bytes=[long]0; $verified=0
foreach ($row in $sample) {
    $path=$row.Ubicacion
    try {
        $info=[CryptoWindowsIO]::GetInfo($path)
        if ($info.Length -gt 8MB -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'outside_sample_limits'}
        $cached=$cache.Find([CryptoFileScanner]::TextHash($rootKey+'|'+$path.Substring(3).ToUpperInvariant()))
        if (-not $cached) {throw 'not_in_original_cache'}
        $ext=[IO.Path]::GetExtension($path)
        $hex=$ext -in @('.key','.privkey','.secret') -or $path -match '(?i)(?:^|[\\/._ -])(?:private[\s_-]*key|secret[\s_-]*key|privkey|secretkey|(?:clave|llave)[\s_-]*privada)(?:$|[\\/._ -])'
        $result=[CryptoFileScanner]::ReadFile($path,$true,($ext -eq '.json'),$hex,8MB,$true,$null)
        $after=[CryptoWindowsIO]::GetInfo($path)
        $bytes+=$result.BytesRead
        if ($result.Sha256 -ne $cached.Hash -or $info.Length -ne $after.Length -or $info.LastWriteTicks -ne $after.LastWriteTicks) {throw 'changed_since_original_scan'}
        $verified++
        $metadata.Add([pscustomobject]@{Ubicacion=$path;Bytes=$result.BytesRead;Sha256=$result.Sha256})
        foreach ($id in $result.Evidence) {
            $category=if ($categoryAst) {Get-FindingCategory $path $id $result.Evidence} else {'principal'}
            $records.Add([pscustomobject]@{Ubicacion=$path;Tipo=$id;Categoria=$category})
        }
    } catch { $skipped.Add([pscustomobject]@{Ubicacion=$path;Motivo=$_.Exception.Message}) }
}
$timer.Stop()
if ((Get-FileHash -LiteralPath $originalCsv).Hash -ne $originalHash -or (Get-Item -LiteralPath $statePath).LastWriteTimeUtc.Ticks -ne $stateTicks) {throw 'Original results changed.'}
[void][IO.Directory]::CreateDirectory($OutputDirectory)
# Source hashes are internal comparison metadata, separate from user-facing location/type CSVs.
$records|Export-Csv -LiteralPath (Join-Path $OutputDirectory 'sample-evidence.csv') -NoTypeInformation -Encoding UTF8
$metadata|Export-Csv -LiteralPath (Join-Path $OutputDirectory 'sample-identities.csv') -NoTypeInformation -Encoding UTF8
$skipped|Export-Csv -LiteralPath (Join-Path $OutputDirectory 'sample-skipped.csv') -NoTypeInformation -Encoding UTF8
$summary=[ordered]@{OriginalCsvSha256=$originalHash;DetectorSha256=(Get-FileHash -LiteralPath (Join-Path $ScannerDirectory 'CryptoMnemonicScanner-10.12.dll')).Hash;Selected=$sample.Count;VerifiedSameSource=$verified;Skipped=$skipped.Count;BytesRead=$bytes;Seconds=$timer.Elapsed.TotalSeconds;EvidenceRows=$records.Count;PrincipalRows=@($records|Where-Object Categoria -eq 'principal').Count;SecondaryRows=@($records|Where-Object Categoria -eq 'secundarios').Count;TypeCounts=@($records|Group-Object Tipo|Sort-Object Name|Select-Object @{n='Type';e={$_.Name}},Count)}
$summary|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding UTF8
[pscustomobject]$summary|Select-Object Selected,VerifiedSameSource,Skipped,BytesRead,Seconds,EvidenceRows,PrincipalRows,SecondaryRows|ConvertTo-Json -Compress
