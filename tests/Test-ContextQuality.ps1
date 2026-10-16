[CmdletBinding()]
param([string]$BaselineScannerPath)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$script:Passed=0
function Assert-Context([bool]$Condition,[string]$Name) { if (-not $Condition) { throw ('FAIL: '+$Name) }; $script:Passed++; Write-Host ('PASS: '+$Name) }
Add-Type -AssemblyName System.IO.Compression
[void][Reflection.Assembly]::LoadFile((Join-Path $repo 'CryptoMnemonicScanner-10.12.dll'))
Add-Type -Path (Join-Path $PSScriptRoot 'QualityVectors.cs')
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Scan-CryptoArtifacts.ps1'),[ref]$null,[ref]$null)
foreach ($variable in @('$script:TextRules','$script:FindingTypeLabels')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq $variable},$true)
    Invoke-Expression $node.Extent.Text
}
foreach ($function in @('Get-FindingCategory','Get-PathEvidence')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $function},$true)
    Invoke-Expression $node.Extent.Text
}
$lists=@('bip39-english.txt','bip39-spanish.txt','monero-english.txt','monero-english-old.txt','monero-spanish.txt','slip39-english.txt')
$wordListRoot=Join-Path $repo 'resources\wordlists'
$words=[string[][]]::new(6)
for($i=0;$i -lt 6;$i++) { $words[$i]=[IO.File]::ReadAllLines((Join-Path $wordListRoot $lists[$i]),[Text.Encoding]::UTF8) }
[CryptoMnemonicScanner]::Configure($words[0],$words[1],$words[2],$words[3],$words[4],$words[5])
[CryptoFileScanner]::Configure([string[]]$script:TextRules.Evidence,[string[]]$script:TextRules.Pattern)
[CryptoFileScanner]::ConfigurePublicDictionaries([string[]]@($lists|ForEach-Object {(Get-FileHash -LiteralPath (Join-Path $wordListRoot $_)).Hash}))
[CryptoDocumentScanner]::Configure((Join-Path $repo 'scripts\Read-PdfWorker.ps1'),32MB,256MB)
$dependencyLock=Get-Content -LiteralPath (Join-Path $repo 'dependencies\packages.lock.json') -Raw|ConvertFrom-Json
$runtimeNames=@(
    'README.md','README.es.md','LICENSE',
    'Scan-CryptoArtifacts.ps1','tools/review/Filter-RecoveryCandidates.ps1','tools/review/Export-ScanReviewReports.ps1','tools/review/Verify-Bip39Structure.ps1',
    'CryptoMnemonicScanner-10.12.dll','CryptoBip39Inspector.dll',
    'scripts/CsvOutputSafety.ps1','scripts/Read-PdfWorker.ps1',
    'src/CryptoBip39Inspector.cs','src/CryptoDocumentScanner.cs','src/CryptoEvidenceQuality.cs','src/CryptoFileScanner.cs',
    'src/CryptoKeyValidation.cs','src/CryptoMnemonicScanner.cs','src/CryptoParallelScanner.cs','src/CryptoScanInventory.cs','src/CryptoWindowsIO.cs',
    'docs/SECURITY.md','docs/THIRD-PARTY.md','docs/THIRD-PARTY.es.md'
)+@($lists|ForEach-Object {'resources/wordlists/'+$_})+@(
    'dependencies/Microsoft-LICENSE.txt','dependencies/Monero-WORDLIST-LICENSE.txt','dependencies/PdfPig-LICENSE.txt',
    'dependencies/Trezor-MIT-LICENSE.txt','dependencies/packages.lock.json'
)+@($dependencyLock|ForEach-Object { foreach($dependency in $_.Files) { 'dependencies/'+$dependency.File } })
$runtimeHashes=[string[]]@($runtimeNames|ForEach-Object {(Get-FileHash -LiteralPath (Join-Path $repo ($_.Replace('/', [IO.Path]::DirectorySeparatorChar)))).Hash})
[CryptoFileScanner]::ConfigureRuntimeFiles([string[]]$runtimeNames,$runtimeHashes)
$weakPaths=@(
    'C:\data\atomic', 'C:\data\Trust', 'C:\data\Wallet',
    'C:\sdk\include\c++\atomic', 'C:\data\.mono\certs\Trust',
    'C:\data\DiagnosticLogs\Wallet', 'C:\data\Edge Wallet\json\wallet',
    'C:\data\Edge Wallet\json\wallet\wallet-checkout-eligible-sites.json',
    'C:\data\Dashlane\9.0\ressources\passwordwallet.png',
    'C:\data\import_passwallet.png', 'C:\data\CryptoMnemonicScanner.cs',
    'C:\data\CryptoMnemonicScanner.dll', 'C:\data\wallet-scanner.zip',
    'C:\data\wallet.json', 'C:\data\wallet.txt'
)
$strong=@('validated_ethereum_keystore_structure','validated_bitcoin_private_key','validated_extended_private_key','validated_electrum_wallet_structure','validated_bitcoin_core_wallet_database','validated_solana_keypair_json','possible_bip39_mnemonic_phrase','possible_monero_mnemonic_phrase','possible_slip39_share')
foreach ($path in $weakPaths) {
    $evidence=[string[]]@(Get-PathEvidence $path (-not [IO.Path]::HasExtension($path)))
    Assert-Context ($evidence.Length -gt 0) ('Ambiguous name remains recorded: '+$path)
    foreach ($id in $evidence) {
        Assert-Context ((Get-FindingCategory $path $id $evidence) -eq 'secundarios') 'Ambiguous name alone stays secondary'
        foreach ($real in $strong) {
            Assert-Context ((Get-FindingCategory $path $real ([string[]]@($evidence+$real))) -eq 'principal') 'Strong private evidence is retained despite ambiguous name'
        }
    }
}
foreach ($path in @('C:\data\keystore.json','C:\data\UTC--backup','C:\data\my.wallet','C:\data\wallet.bak','C:\data\atomicwallet','C:\data\trust wallet','C:\data\Electrum')) {
    $evidence=[string[]]@(Get-PathEvidence $path ($path -match '(?:atomicwallet|trust wallet|Electrum)$'))
    Assert-Context ($evidence.Length -gt 0) 'Specific wallet name remains recorded'
    foreach($id in $evidence) { Assert-Context ((Get-FindingCategory $path $id $evidence) -eq 'secundarios') 'Specific wallet name or software path alone stays secondary' }
}
Assert-Context ((Get-FindingCategory 'C:\data\wallet.dat' 'bitcoin_core_wallet_filename' @('bitcoin_core_wallet_filename')) -eq 'secundarios') 'wallet.dat name alone stays secondary'
Assert-Context ((Get-FindingCategory 'C:\data\wallet.dat' 'validated_bitcoin_core_wallet_database' @('bitcoin_core_wallet_filename','validated_bitcoin_core_wallet_database')) -eq 'principal') 'Validated Bitcoin Core structure is primary'
Assert-Context ((Get-FindingCategory 'C:\Users\tester\Github\wallet-artifact-scanner\artifacts\result-validation\keystore-comparison.json' 'wallet_or_crypto_related_filename' @('wallet_or_crypto_related_filename')) -eq 'secundarios') 'Scanner validation artifacts do not promote a keystore-like filename'
Assert-Context ((Get-FindingCategory 'C:\Users\tester\Github\wallet-artifact-scanner\artifacts\result-validation\keystore.json' 'validated_ethereum_keystore_structure' @('validated_ethereum_keystore_structure')) -eq 'principal') 'Validated keystore structure stays primary in scanner artifacts'
Assert-Context ((Get-FindingCategory 'C:\Program Files\Example\Cache\wallet.json' 'validated_electrum_wallet_structure' @('validated_electrum_wallet_structure')) -eq 'principal') 'Electrum structure stays primary in software cache'
Assert-Context ((Get-FindingCategory 'C:\Program Files\Example\Cache\id.json' 'validated_solana_keypair_json' @('validated_solana_keypair_json')) -eq 'principal') 'Matching Solana secret/public pair stays primary in software cache'
Assert-Context ((Get-FindingCategory 'C:\data\accounts.txt' 'validated_evm_address' @('validated_evm_address')) -eq 'secundarios') 'EIP-55 EVM address remains secondary because it is public'
Assert-Context ((Get-FindingCategory 'C:\data\accounts.txt' 'validated_monero_address' @('validated_monero_address')) -eq 'secundarios') 'Monero address checksum remains secondary because it is public'
Assert-Context ((Get-FindingCategory 'C:\Users\tester\.codex\plugins\cache\sample.js' 'validated_bitcoin_private_key' @('validated_bitcoin_private_key')) -eq 'principal') 'Validated private key stays primary in source/cache context'
Assert-Context ((Get-FindingCategory 'C:\Program Files\Adobe\strings.js' 'possible_bip39_mnemonic_phrase' @('possible_bip39_mnemonic_phrase')) -eq 'secundarios') 'Checksum phrase in software source remains secondary for review'
Assert-Context ((Get-FindingCategory 'C:\data\notes.txt' 'validated_bitcoin_address' @('validated_bitcoin_address')) -eq 'secundarios') 'Public Bitcoin address remains secondary even with a valid checksum'
foreach ($marker in @('scanner_runtime_copy','public_mnemonic_dictionary')) {
    Assert-Context ((Get-FindingCategory 'C:\data\copy.txt' 'possible_bip39_mnemonic_phrase' @('possible_bip39_mnemonic_phrase',$marker)) -eq 'secundarios') 'Exact public content is secondary'
}
Assert-Context ((Get-FindingCategory 'C:\data\mixed.zip' 'validated_ethereum_keystore_structure' @('validated_ethereum_keystore_structure','container_public_mnemonic_dictionary')) -eq 'principal') 'Member dictionary marker never downgrades another member'
Assert-Context ((Get-FindingCategory 'C:\data\copy.zip' 'container_member_read_error' @('container_member_read_error','scanner_runtime_copy')) -eq 'incidencias') 'Coverage errors retain their separate output'

$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
$testBase=Join-Path $tempRoot ('wallet-scanner-context-'+[guid]::NewGuid().ToString('D'))
$inputRoot=Join-Path $testBase 'input'
[void][IO.Directory]::CreateDirectory($inputRoot)
function Write-ContextZip([string]$Path,[object[]]$Members) {
    $file=[IO.File]::Open($Path,[IO.FileMode]::Create)
    $archive=[IO.Compression.ZipArchive]::new($file,[IO.Compression.ZipArchiveMode]::Create,$false)
    try {
        foreach($member in $Members) {
            $entry=$archive.CreateEntry([string]$member.Name)
            $output=$entry.Open()
            try { $bytes=[byte[]]$member.Bytes; $output.Write($bytes,0,$bytes.Length) } finally { $output.Dispose() }
        }
    } finally { $archive.Dispose(); $file.Dispose() }
}
function Read-ContextFile([string]$Path,[bool]$Hash=$true) { return [CryptoFileScanner]::ReadFile($Path,$true,([IO.Path]::GetExtension($Path) -eq '.json'),$false,32MB,$Hash,$null) }
$phrase='abandon amount liar amount expire adjust cage candy arch gather drum buyer'
$wif=[QualityVectors]::Wif($true)
$key=@{version=3;crypto=@{cipher='aes-128-ctr';cipherparams=@{iv=('1'*32)};ciphertext=('2'*64);mac=('3'*64);kdf='scrypt';kdfparams=@{salt=('4'*64);dklen=32;n=4096;r=8;p=1}}}|ConvertTo-Json -Depth 6 -Compress
$utf8=[Text.UTF8Encoding]::new($false)
try {
    $dictionary=[IO.File]::ReadAllBytes((Join-Path $wordListRoot 'slip39-english.txt'))
    $slipMember=@{Name='slip39-english.txt';Bytes=$dictionary}
    $dictionaryZip=Join-Path $inputRoot 'dictionary.zip'
    Write-ContextZip $dictionaryZip @($slipMember)
    foreach($hash in @($true,$false)) {
        $result=Read-ContextFile $dictionaryZip $hash
        Assert-Context ($result.Evidence -contains 'container_public_mnemonic_dictionary') 'Public SLIP39 dictionary recognized inside ZIP with or without cache'
        Assert-Context ($result.Evidence -notcontains 'public_mnemonic_dictionary' -and @($result.Evidence|Where-Object {$_ -match '^possible_(?:bip39_mnemonic_phrase|monero_mnemonic_phrase|slip39_share)$'}).Count -eq 0) 'Dictionary checksum coincidences stay local to that member'
    }
    $nested=Join-Path $inputRoot 'nested.zip'
    Write-ContextZip $nested @(@{Name='inner.zip';Bytes=[IO.File]::ReadAllBytes($dictionaryZip)})
    $result=Read-ContextFile $nested
    Assert-Context ($result.Evidence -contains 'container_public_mnemonic_dictionary' -and $result.Evidence -notcontains 'possible_bip39_mnemonic_phrase') 'Nested public dictionary handled per member'
    $renamedDictionary=Join-Path $inputRoot 'renamed-dictionary.zip'
    Write-ContextZip $renamedDictionary @(@{Name='wallet.dat';Bytes=$dictionary})
    $result=Read-ContextFile $renamedDictionary
    Assert-Context ($result.Evidence -contains 'container_public_mnemonic_dictionary' -and $result.Evidence -notcontains 'bitcoin_core_wallet_filename') 'Canonical dictionary renamed wallet.dat is still recognized by bytes'
    $dictionaryAndBackup=Join-Path $inputRoot 'dictionary-with-backup.zip'
    Write-ContextZip $dictionaryAndBackup @($slipMember,@{Name='wallet.dat';Bytes=$utf8.GetBytes('opaque wallet backup')})
    Assert-Context ((Read-ContextFile $dictionaryAndBackup).Evidence -contains 'bitcoin_core_wallet_filename') 'Public dictionary never hides a wallet.dat in another member'
    foreach($case in @(@{Name='phrase';Text=$phrase;Id='possible_bip39_mnemonic_phrase'},@{Name='keystore';Text=$key;Id='validated_ethereum_keystore_structure'},@{Name='wif';Text=$wif;Id='validated_bitcoin_private_key'})) {
        $path=Join-Path $inputRoot ($case.Name+'-mixed.zip')
        Write-ContextZip $path @($slipMember,@{Name=($case.Name+'.txt');Bytes=$utf8.GetBytes($case.Text)})
        $result=Read-ContextFile $path
        Assert-Context ($result.Evidence -contains $case.Id -and $result.Evidence -contains 'container_public_mnemonic_dictionary') 'Mixed ZIP retains genuine private evidence beside public dictionary'
        Assert-Context ((Get-FindingCategory $path $case.Id $result.Evidence) -eq 'principal') 'Private member stays in primary output'
    }
    $modified=Join-Path $inputRoot 'modified-dictionary.zip'
    Write-ContextZip $modified @(@{Name='slip39-english.txt';Bytes=$utf8.GetBytes([Text.Encoding]::UTF8.GetString($dictionary)+"`n"+$phrase)})
    $result=Read-ContextFile $modified
    Assert-Context ($result.Evidence -contains 'possible_bip39_mnemonic_phrase' -and $result.Evidence -notcontains 'container_public_mnemonic_dictionary') 'Modified dictionary is scanned normally and added phrase is preserved'
    $runtimeCopy=Join-Path $inputRoot 'renamed-runtime.txt'
    Copy-Item -LiteralPath (Join-Path $repo 'Scan-CryptoArtifacts.ps1') -Destination $runtimeCopy
    Assert-Context ((Read-ContextFile $runtimeCopy).Evidence -contains 'scanner_runtime_copy') 'Renamed runtime source recognized by exact bytes'
    [IO.File]::AppendAllText($runtimeCopy,"`n"+$phrase,$utf8)
    $result=Read-ContextFile $runtimeCopy
    Assert-Context ($result.Evidence -notcontains 'scanner_runtime_copy' -and $result.Evidence -contains 'possible_bip39_mnemonic_phrase') 'Modified runtime copy retains added private evidence'
    $runtimeZip=Join-Path $inputRoot 'renamed-package.zip'
    Copy-Item -LiteralPath (Join-Path $repo 'dist\windows-crypto-artifact-scan.zip') -Destination $runtimeZip
    foreach($hash in @($true,$false)) {
        $result=Read-ContextFile $runtimeZip $hash
        Assert-Context ($result.Evidence -contains 'scanner_runtime_copy' -and -not $result.Incomplete -and $result.MembersScanned -eq $runtimeNames.Count) 'Renamed package verified against every member, including binaries'
    }
    $members=@($runtimeNames|ForEach-Object {@{Name=('windows-crypto-artifact-scan/'+$_);Bytes=[IO.File]::ReadAllBytes((Join-Path $repo ($_.Replace('/', [IO.Path]::DirectorySeparatorChar))))}})
    foreach($variant in @('extra','modified','duplicate','prefix','traversal')) {
        $variantMembers=@($members|ForEach-Object {@{Name=$_.Name;Bytes=$_.Bytes}})
        if($variant -eq 'extra' -or $variant -eq 'duplicate') {
            $name=if($variant -eq 'extra') {'windows-crypto-artifact-scan/personal.txt'} else {'windows-crypto-artifact-scan/README.md'}
            $variantMembers+=@(@{Name=$name;Bytes=$utf8.GetBytes($phrase)})
        } elseif($variant -eq 'modified') {
            ($variantMembers|Where-Object {$_.Name -eq 'windows-crypto-artifact-scan/README.md'}).Bytes=$utf8.GetBytes($phrase)
        } elseif($variant -eq 'prefix') {
            foreach($member in $variantMembers) { $member.Name=$member.Name.Replace('windows-crypto-artifact-scan/','other-folder/') }
            ($variantMembers|Where-Object {$_.Name -eq 'other-folder/README.md'}).Bytes=$utf8.GetBytes($phrase)
        } else {
            ($variantMembers|Where-Object {$_.Name -eq 'windows-crypto-artifact-scan/README.md'}).Name='windows-crypto-artifact-scan/../README.md'
            ($variantMembers|Where-Object {$_.Name.EndsWith('../README.md')}).Bytes=$utf8.GetBytes($phrase)
        }
        $path=Join-Path $inputRoot ('package-'+$variant+'.zip')
        Write-ContextZip $path $variantMembers
        $result=Read-ContextFile $path
        Assert-Context ($result.Evidence -notcontains 'scanner_runtime_copy' -and $result.Evidence -contains 'possible_bip39_mnemonic_phrase') 'Added, changed, duplicate, or renamed members prevent package suppression'
    }
    foreach($fixture in @(@{Name='wallet.json';Text='wallet crypto'},@{Name='keystore.json';Text=$key},@{Name='atomic\evidence.txt';Text=$phrase},@{Name='Edge Wallet\evidence.txt';Text=$wif},@{Name='Dashlane\9.0\ressources\passwordwallet.png';Text='synthetic icon'})) {
        $path=Join-Path $inputRoot $fixture.Name
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
        [IO.File]::WriteAllText($path,$fixture.Text,$utf8)
    }
    $sourceHashes=@{}; foreach($file in Get-ChildItem -LiteralPath $inputRoot -File -Recurse) { $sourceHashes[$file.FullName]=(Get-FileHash -LiteralPath $file.FullName).Hash }
    $csv=Join-Path $testBase 'result.csv'
    $config=@{Scanner=(Join-Path $repo 'Scan-CryptoArtifacts.ps1');Roots=@($inputRoot);Csv=$csv;Answers=@();NoProgress=$false;NoCache=$false;Rescan=$false;LockFile='';MaxMB=256;RepeatInSession=$false;AlternateScanner='';StopAfterFiles=0;CheckpointFiles=1;MaxDocumentMB=32;MaxExpandedMB=256;CpuCorePercent=80;Workers=0}
    $configPath=Join-Path $testBase 'config.json'
    $config|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $configPath -Encoding UTF8
    $paths=@($csv,[IO.Path]::ChangeExtension($csv,'.secundarios.csv'),[IO.Path]::ChangeExtension($csv,'.incidencias.csv'),[IO.Path]::ChangeExtension($csv,'.scanstate'),[IO.Path]::ChangeExtension($csv,'.revision.csv'),[IO.Path]::ChangeExtension($csv,'.secundarios-resumen.csv'))
    $baseline=$BaselineScannerPath
    if(-not [string]::IsNullOrWhiteSpace($baseline) -and -not (Test-Path -LiteralPath $baseline -PathType Leaf)) { throw 'The optional baseline scanner path does not exist.' }
    $previous=$null
    if(-not [string]::IsNullOrWhiteSpace($baseline) -and (Test-Path -LiteralPath $baseline -PathType Leaf)) {
        $oldConfigPath=Join-Path $testBase 'old-config.json'
        $oldConfig=$config.Clone(); $oldConfig.Scanner=$baseline
        $oldConfig|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $oldConfigPath -Encoding UTF8
        $null=& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $oldConfigPath -SummaryPath (Join-Path $testBase 'old-summary.json') -ProgressPath (Join-Path $testBase 'old-progress.json')
        if($LASTEXITCODE) { throw 'Baseline integration failed' }
        $previous=Get-Content -LiteralPath (Join-Path $testBase 'old-summary.json') -Raw|ConvertFrom-Json
    }
    $before=@{}
    foreach($run in @(1,2)) {
        $summaryPath=Join-Path $testBase 'summary.json'
        $null=& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath (Join-Path $testBase 'progress.json')
        if($LASTEXITCODE) { throw ('Context integration failed: '+[IO.File]::ReadAllText($summaryPath)) }
        $summary=Get-Content -LiteralPath $summaryPath -Raw|ConvertFrom-Json
        if($run -eq 1 -and $null -ne $previous) {
            Assert-Context ($summary.AlgorithmFingerprint -ne $previous.AlgorithmFingerprint -and $summary.ContentReused -eq 0) 'Algorithm changes invalidate cached detections automatically'
            Assert-Context ($summary.PrincipalFindings -lt $previous.PrincipalFindings) 'Paired synthetic scan reduces primary noise while retaining positive fixtures'
        }
        $main=@(Import-Csv -LiteralPath $csv); $secondary=@(Import-Csv -LiteralPath $paths[1])
        Assert-Context (@($main|Where-Object {$_.Ubicacion.EndsWith('\wallet.json') -or $_.Ubicacion.EndsWith('\dictionary.zip') -or $_.Ubicacion.EndsWith('\nested.zip') -or $_.Ubicacion.EndsWith('\renamed-package.zip') -or $_.Ubicacion.EndsWith('.png')}).Count -eq 0) 'Integration excludes ambiguous names and exact public copies from primary CSV'
        Assert-Context (@($main|Where-Object {$_.Ubicacion.EndsWith('keystore.json') -and $_.Tipo -eq 'keystore_ethereum_estructura_v3_valida'}).Count -eq 1) 'Integration retains structured keystore'
        Assert-Context (@($main|Where-Object {$_.Ubicacion.EndsWith('keystore.json') -and $_.Tipo -eq 'archivo_relacionado_billetera'}).Count -eq 0) 'Validated keystore suppresses redundant filename evidence'
        Assert-Context (@($main|Where-Object {$_.Ubicacion.EndsWith('Edge Wallet\evidence.txt') -and $_.Tipo -eq 'clave_privada_bitcoin_checksum_valido'}).Count -eq 1) 'Integration retains private evidence in ambiguous software folder'
        Assert-Context (@($secondary|Where-Object {$_.Ubicacion.EndsWith('renamed-package.zip') -and $_.Tipo -eq 'copia_verificada_del_escaner'}).Count -eq 1) 'Verified package marker survives CSV and cache'
        foreach($path in $paths) {
            $hash=(Get-FileHash -LiteralPath $path).Hash; $ticks=(Get-Item -LiteralPath $path).LastWriteTimeUtc.Ticks
            if($run -eq 1) { $before[$path]=@($hash,$ticks) } else { Assert-Context ($before[$path][0] -eq $hash -and $before[$path][1] -eq $ticks) 'New classifications preserve byte and timestamp idempotence' }
            $text=[IO.File]::ReadAllText($path)
            Assert-Context (-not $text.Contains($phrase) -and -not $text.Contains($wif) -and -not $text.Contains('2'*64)) 'Outputs and cache contain no synthetic private values'
        }
        foreach($path in $paths[0..2]) { Assert-Context ([IO.File]::ReadAllLines($path)[0] -eq '"Ubicacion","Tipo","FechaCreacionUtc","FechaModificacionUtc"') 'User CSV includes path, type, and file timestamp columns' }
        if($run -eq 2) { Assert-Context ($summary.ContentAnalyzed -eq 0 -and $summary.ContentReused -gt 0) 'All complete detections reuse cache on the second run' }
    }
    foreach($path in $sourceHashes.Keys) { Assert-Context ((Get-FileHash -LiteralPath $path).Hash -eq $sourceHashes[$path]) 'Synthetic source files remain unchanged' }
    Write-Host ('ALL PASSED: '+$script:Passed+' context quality assertions.')
} finally {
    [CryptoDocumentScanner]::StopWorker()
    $target=[IO.Path]::GetFullPath($testBase)
    if(-not $target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe cleanup target' }
    if(Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
