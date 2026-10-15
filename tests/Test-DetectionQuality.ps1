[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$script:Passed=0
function Assert-Quality([bool]$Condition,[string]$Name) { if (-not $Condition) { throw ('FAIL: '+$Name) }; $script:Passed++; Write-Host ('PASS: '+$Name) }
[void][Reflection.Assembly]::LoadFile((Join-Path $repo 'CryptoMnemonicScanner-10.12.dll'))
Add-Type -Path (Join-Path $PSScriptRoot 'QualityVectors.cs')
$lists=@('bip39-english.txt','bip39-spanish.txt','monero-english.txt','monero-english-old.txt','monero-spanish.txt','slip39-english.txt')
$wordListRoot=Join-Path $repo 'resources\wordlists'
$wordLists=New-Object 'Collections.Generic.List[string[]]'
foreach ($name in $lists) { $wordLists.Add([IO.File]::ReadAllLines((Join-Path $wordListRoot $name),[Text.Encoding]::UTF8)) }
[CryptoMnemonicScanner]::Configure($wordLists[0],$wordLists[1],$wordLists[2],$wordLists[3],$wordLists[4],$wordLists[5])
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'Scan-CryptoArtifacts.ps1'),[ref]$null,[ref]$null)
$ruleAst=$ast.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:TextRules'},$true)
Invoke-Expression $ruleAst.Extent.Text
[CryptoFileScanner]::Configure([string[]]$script:TextRules.Evidence,[string[]]$script:TextRules.Pattern)
$phrase='abandon amount liar amount expire adjust cage candy arch gather drum buyer'
$repeatedEntropyBits=('00000000001'*11)+'0000001'
$repeatedEntropy=New-Object byte[] 16
for($i=0;$i -lt 16;$i++) { $repeatedEntropy[$i]=[Convert]::ToByte($repeatedEntropyBits.Substring($i*8,8),2) }
$sha=[Security.Cryptography.SHA256]::Create()
try { $repeatedHash=$sha.ComputeHash($repeatedEntropy) } finally { $sha.Dispose() }
$repeatedLastIndex=(1 -shl 4) -bor ([int]$repeatedHash[0] -shr 4)
$repeatedWords=New-Object 'Collections.Generic.List[string]'
for($i=0;$i -lt 11;$i++) { $repeatedWords.Add([string]$wordLists[0][1]) }
$repeatedWords.Add([string]$wordLists[0][$repeatedLastIndex])
$repeated=$repeatedWords -join ' '
foreach ($variant in @($phrase,($phrase -replace ' ',[Environment]::NewLine),('['+('"'+($phrase -replace ' ','","')+'"')+']'),((1..12 | ForEach-Object { [string]$_+'. '+($phrase.Split(' ')[$_-1]) }) -join [Environment]::NewLine))) {
    Assert-Quality ([CryptoMnemonicScanner]::Scan($variant) -contains 'possible_bip39_mnemonic_phrase') 'Complete BIP39 survives supported formatting'
}
foreach ($separator in @('_','1;',' + ','<>')) {
    $ids=[CryptoMnemonicScanner]::Scan(($phrase -replace ' ',$separator))
    Assert-Quality ($ids -notcontains 'possible_bip39_mnemonic_phrase' -and $ids -contains 'mnemonic_bip39_fragmented_candidate') 'Fragmented mnemonic stays secondary'
    Assert-Quality ([CryptoMnemonicScanner]::Scan((($phrase -replace ' ',$separator)+' NONWORD '+$phrase)) -contains 'possible_bip39_mnemonic_phrase') 'Earlier fragment cannot hide a later complete phrase'
}
Assert-Quality ([CryptoMnemonicScanner]::Scan($repeated) -contains 'mnemonic_bip39_repetitive_candidate') 'Valid repetitive BIP39 phrase is retained with lower confidence'
Assert-Quality ([CryptoMnemonicScanner]::Scan($repeated+' NONWORD '+$phrase) -contains 'possible_bip39_mnemonic_phrase') 'Repetitive phrase cannot hide a later complete phrase'
$canonicalZeroEntropy='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
Assert-Quality ([CryptoMnemonicScanner]::Scan($canonicalZeroEntropy) -contains 'mnemonic_bip39_public_example_candidate') 'Canonical zero-entropy phrase remains marked as a public example'
$publicExample='ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic'
Assert-Quality ([CryptoMnemonicScanner]::Scan($publicExample) -contains 'mnemonic_bip39_public_example_candidate' -and [CryptoMnemonicScanner]::Scan($publicExample) -notcontains 'possible_bip39_mnemonic_phrase') 'Published Trezor example stays secondary'
Assert-Quality ([CryptoMnemonicScanner]::Scan($publicExample+' NONWORD '+$phrase) -contains 'possible_bip39_mnemonic_phrase') 'Public example cannot hide a later complete candidate'
for ($lang=0;$lang -lt 3;$lang++) {
    $prefix=if ($lang -eq 0) {3} else {4}
    foreach ($abbreviate in @($false,$true)) { Assert-Quality ([CryptoMnemonicScanner]::Scan([QualityVectors]::Monero($wordLists[$lang+2],$prefix,$abbreviate)) -contains 'possible_monero_mnemonic_phrase') 'Complete Monero checksum survives exact words and prefixes' }
    Assert-Quality ([CryptoMnemonicScanner]::Scan((@($wordLists[$lang+2][0])*25 -join ' ')) -contains 'mnemonic_monero_repetitive_candidate') 'Repeated Monero words retained as weaker evidence'
}
Assert-Quality ([CryptoEvidenceQuality]::BitcoinAddressValid('1BoatSLRHtKNngkdXEeobR76b53LETtpyT')) 'Base58Check valid address'
Assert-Quality (-not [CryptoEvidenceQuality]::BitcoinAddressValid('1BoatSLRHtKNngkdXEeobR76b53LETtpyU')) 'Base58Check mutation rejected'
$eip55='0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'
foreach ($address in @($eip55,'0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359','0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB','0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb')) {
    Assert-Quality ([CryptoEvidenceQuality]::EvmAddressChecksumValid($address)) 'Official EIP-55 mixed-case checksum accepted'
}
Assert-Quality (-not [CryptoEvidenceQuality]::EvmAddressChecksumValid('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD')) 'EIP-55 case mutation rejected'
Assert-Quality (-not [CryptoEvidenceQuality]::EvmAddressChecksumValid('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed')) 'Uniform-case EVM address stays unverified'
$evmEvidence=[CryptoFileScanner]::ScanText($eip55,$false,$false)
Assert-Quality ($evmEvidence -contains 'validated_evm_address' -and $evmEvidence -contains 'possible_evm_address') 'EIP-55 validation integrated while preserving candidate evidence'
$moneroAddress='888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H'
Assert-Quality ([CryptoEvidenceQuality]::MoneroAddressChecksumValid($moneroAddress)) 'Official Monero mainnet address checksum and network prefix accepted'
Assert-Quality (-not [CryptoEvidenceQuality]::MoneroAddressChecksumValid($moneroAddress.Substring(0,$moneroAddress.Length-1)+'1')) 'Monero address checksum mutation rejected'
$moneroEvidence=[CryptoFileScanner]::ScanText($moneroAddress,$false,$false)
Assert-Quality ($moneroEvidence -contains 'validated_monero_address' -and $moneroEvidence -contains 'possible_monero_address') 'Monero checksum validation integrated in content detection'
$solanaPair=[QualityVectors]::SolanaKeypairJson($false)
$solanaPairEvidence=[CryptoFileScanner]::ScanText($solanaPair,$true,$false)
Assert-Quality ($solanaPairEvidence -contains 'validated_solana_keypair_json') 'RFC 8032 Ed25519 seed/public pair is validated'
$mismatchedSolanaEvidence=[CryptoFileScanner]::ScanText([QualityVectors]::SolanaKeypairJson($true),$true,$false)
Assert-Quality ($mismatchedSolanaEvidence -contains 'possible_solana_keypair_json' -and $mismatchedSolanaEvidence -notcontains 'validated_solana_keypair_json') 'Mismatched Solana public key stays candidate only'
foreach ($compressed in @($false,$true)) { Assert-Quality ([CryptoFileScanner]::ScanText([QualityVectors]::Wif($compressed),$false,$false) -contains 'validated_bitcoin_private_key') 'Testnet WIF is detected and validated in both compression formats' }
$xpub=[QualityVectors]::ExtendedPublicKey()
Assert-Quality ([CryptoKeyValidation]::ExtendedPublicKeyValid($xpub)) 'BIP32 extended public key checksum and version accepted'
Assert-Quality (-not [CryptoKeyValidation]::ExtendedPublicKeyValid($xpub.Substring(0,$xpub.Length-1)+'1')) 'BIP32 extended public key mutation rejected'
Assert-Quality ([CryptoEvidenceQuality]::BitcoinAddressValid('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')) 'Official BIP173 witness vector accepted'
foreach ($address in @('bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y','BC1SW50QGDZ25J','bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs','bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0')) { Assert-Quality ([CryptoEvidenceQuality]::BitcoinAddressValid($address)) 'Official BIP350 witness vector accepted' }
foreach ($address in @('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd','bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh','bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf','tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j')) { Assert-Quality (-not [CryptoEvidenceQuality]::BitcoinAddressValid($address)) 'Official BIP350 invalid vector rejected' }
foreach ($suffix in @('_suffix','0','O')) { Assert-Quality ([CryptoFileScanner]::ScanText(('1BoatSLRHtKNngkdXEeobR76b53LETtpyT'+$suffix),$false,$false) -notcontains 'validated_bitcoin_address') 'Address embedded in an identifier stays unvalidated' }
foreach ($hrp in @('bc','tb','bcrt')) { foreach ($version in @(0,1,16)) {
    $address=[QualityVectors]::Witness($hrp,$version,32,$false,0)
    Assert-Quality ([CryptoEvidenceQuality]::BitcoinAddressValid($address) -and [CryptoEvidenceQuality]::BitcoinAddressValid($address.ToUpperInvariant())) 'Witness checksum and uniform case accepted'
    Assert-Quality (-not [CryptoEvidenceQuality]::BitcoinAddressValid($address.Substring(0,1).ToUpperInvariant()+$address.Substring(1))) 'Mixed case rejected'
    Assert-Quality (-not [CryptoEvidenceQuality]::BitcoinAddressValid([QualityVectors]::Witness($hrp,$version,32,$true,0))) 'Wrong witness checksum family rejected'
    Assert-Quality (-not [CryptoEvidenceQuality]::BitcoinAddressValid([QualityVectors]::Witness($hrp,$version,32,$false,2))) 'Excess padding rejected'
    Assert-Quality ([CryptoFileScanner]::ScanText($address,$false,$false) -contains 'validated_bitcoin_address') 'Address validator integrated in content detection'
} }
Assert-Quality (-not [CryptoEvidenceQuality]::BitcoinAddressValid([QualityVectors]::Witness('bc',0,24,$false,0))) 'Invalid v0 program length rejected'
Assert-Quality (-not [CryptoEvidenceQuality]::BitcoinAddressValid([QualityVectors]::Witness('bc',17,32,$false,0))) 'Unsupported witness version rejected'
$crypto=@{cipher='aes-128-ctr';cipherparams=@{iv=('1'*32)};ciphertext=('2'*64);mac=('3'*64);kdf='scrypt';kdfparams=@{salt=('4'*64);dklen=32;n=4096;r=8;p=1}}
$key=@{version=3;crypto=$crypto}
$json=$key | ConvertTo-Json -Depth 6 -Compress
Assert-Quality ([CryptoEvidenceQuality]::KeystoreV3Valid($json)) 'Structured keystore v3 accepted without decryption'
Assert-Quality ([CryptoFileScanner]::ScanText($json,$true,$false) -contains 'validated_ethereum_keystore_structure') 'Structured keystore integrated in content detection'
Assert-Quality ([CryptoEvidenceQuality]::ContainsKeystoreV3('['+$json+']')) 'Keystore embedded in array accepted'
foreach ($field in @('cipherparams','ciphertext','kdfparams','mac')) { $value=$crypto[$field]; $crypto.Remove($field); Assert-Quality (-not [CryptoEvidenceQuality]::KeystoreV3Valid(($key|ConvertTo-Json -Depth 6 -Compress))) 'Incomplete keystore rejected'; $crypto[$field]=$value }
$crypto.kdfparams.n=4095
Assert-Quality (-not [CryptoEvidenceQuality]::KeystoreV3Valid(($key|ConvertTo-Json -Depth 6 -Compress))) 'Invalid scrypt structure rejected'
$crypto.kdf='pbkdf2'; $crypto.kdfparams=@{salt=('4'*32);dklen=32;c=262144;prf='hmac-sha256'}
Assert-Quality ([CryptoEvidenceQuality]::KeystoreV3Valid(($key|ConvertTo-Json -Depth 6 -Compress))) 'PBKDF2 and variable length salt supported'
Assert-Quality (-not [CryptoEvidenceQuality]::ContainsKeystoreV3('{"crypto":{},"cipher":"aes","kdfparams":{}}')) 'Scattered field names do not confirm a keystore'
$electrum=@{wallet_type='standard';seed_version=73;keystore=@{type='bip32';xpub=$xpub}} | ConvertTo-Json -Depth 5 -Compress
Assert-Quality ([CryptoEvidenceQuality]::ElectrumWalletStructureValid($electrum)) 'Electrum wallet metadata and BIP32 keystore accepted'
Assert-Quality ([CryptoFileScanner]::ScanText($electrum,$true,$false) -contains 'validated_electrum_wallet_structure') 'Electrum structure integrated in JSON detection'
Assert-Quality (-not [CryptoEvidenceQuality]::ElectrumWalletStructureValid('{"wallet_type":"standard","seed_version":73,"keystore":{"type":"bip32","xpub":"xpub-not-valid"}}')) 'Electrum metadata without a valid extended key rejected'
Assert-Quality (-not [CryptoEvidenceQuality]::ElectrumWalletStructureValid('{"wallet_type":"standard","seed_version":74,"keystore":{"type":"bip32","xpub":"'+$xpub+'"}}')) 'Unsupported Electrum seed version rejected'
Assert-Quality (-not [CryptoEvidenceQuality]::ElectrumWalletStructureValid('{"wallet_type":"standard","seed_version":73,"keystore":{}')) 'Malformed Electrum JSON rejected'
$bdbHeader=New-Object byte[] 72; $bdbHeader[12]=0; $bdbHeader[13]=5; $bdbHeader[14]=0x31; $bdbHeader[15]=0x62
Assert-Quality (-not [CryptoFileScanner]::BitcoinCoreWalletDatabaseValid($bdbHeader,4096)) 'Generic Berkeley DB header cannot validate a Bitcoin wallet'
Assert-Quality ([CryptoFileScanner]::BitcoinCoreWalletDatabaseEvidence($bdbHeader,4096) -contains 'bitcoin_core_berkeley_db_candidate') 'Legacy Berkeley DB lead is preserved as an unvalidated candidate'
Assert-Quality (-not [CryptoFileScanner]::BitcoinCoreWalletDatabaseValid($bdbHeader,4095)) 'Undersized Berkeley DB header rejected'
Assert-Quality ([CryptoFileScanner]::BitcoinCoreWalletDatabaseEvidence($bdbHeader,4095).Length -eq 0) 'Undersized Berkeley DB cannot acquire candidate evidence'
[Array]::Reverse($bdbHeader,12,4)
Assert-Quality ([CryptoFileScanner]::BitcoinCoreWalletDatabaseEvidence($bdbHeader,4096) -contains 'bitcoin_core_berkeley_db_candidate') 'Opposite-endian Berkeley DB lead also stays a candidate'
$sqliteHeader=New-Object byte[] 72
$sqliteMagic=[Text.Encoding]::ASCII.GetBytes('SQLite format 3'); [Array]::Copy($sqliteMagic,0,$sqliteHeader,0,$sqliteMagic.Length); $sqliteHeader[15]=0
$mainMagic=[byte[]](0xf9,0xbe,0xb4,0xd9); [Array]::Copy($mainMagic,0,$sqliteHeader,68,4)
Assert-Quality ([CryptoFileScanner]::BitcoinCoreWalletDatabaseValid($sqliteHeader,512)) 'Bitcoin Core SQLite wallet header accepted'
$sqliteHeader[68]=0
Assert-Quality (-not [CryptoFileScanner]::BitcoinCoreWalletDatabaseValid($sqliteHeader,512)) 'SQLite database with another application/network id rejected'
$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
$testBase=Join-Path $tempRoot ('wallet-scanner-quality-'+[guid]::NewGuid().ToString('D'))
$inputRoot=Join-Path $testBase 'input'
[void][IO.Directory]::CreateDirectory($inputRoot)
try {
    $fixtures=@{'seed.txt'=$phrase; 'repeated.txt'=$repeated; 'fragment.txt'=($phrase -replace ' ','_'); 'bad-address.txt'='1BoatSLRHtKNngkdXEeobR76b53LETtpyU'; 'valid-address.txt'='1BoatSLRHtKNngkdXEeobR76b53LETtpyT'; 'mentions.txt'='bitcoin wallet crypto'; 'key.json'=$json; 'example.js'=$phrase; 'evm-checksum.txt'=$eip55; 'monero-checksum.txt'=$moneroAddress; 'solana-valid.json'=$solanaPair; 'solana-mismatch.json'=[QualityVectors]::SolanaKeypairJson($true)}
    foreach ($name in $fixtures.Keys) { [IO.File]::WriteAllText((Join-Path $inputRoot $name),$fixtures[$name],[Text.UTF8Encoding]::new($false)) }
    Copy-Item -LiteralPath (Join-Path $wordListRoot 'bip39-english.txt') -Destination (Join-Path $inputRoot 'dictionary.txt')
    [IO.File]::WriteAllText((Join-Path $inputRoot 'broken.pdf'),'%PDF-1.4 broken fixture')
    $boundary=Join-Path $inputRoot 'boundary.json'
    [IO.File]::WriteAllText($boundary,(('z'*(1MB-80))+' '+$json),[Text.UTF8Encoding]::new($false))
    Assert-Quality ([CryptoFileScanner]::ReadFile($boundary,$true,$true,$false,4MB,$true,$null).Evidence -contains 'validated_ethereum_keystore_structure') 'Complete keystore across a read boundary detected'
    $electrumLarge='{"wallet_type":"standard","seed_version":73,"padding":"'+('x'*(1MB+256))+'","keystore":{"type":"bip32","xpub":"'+$xpub+'"}}'
    [IO.File]::WriteAllText($boundary,$electrumLarge,[Text.UTF8Encoding]::new($false))
    Assert-Quality ([CryptoFileScanner]::ReadFile($boundary,$true,$true,$false,4MB,$true,$null).Evidence -contains 'validated_electrum_wallet_structure') 'Electrum wallet structure survives a read boundary'
    $lateCrypto='{"version":3,"note":"'+('x'*16000)+'","crypto":'+($key.crypto|ConvertTo-Json -Depth 5 -Compress)+'}'
    [IO.File]::WriteAllText($boundary,(('z'*(1MB-12000))+' '+$lateCrypto),[Text.UTF8Encoding]::new($false))
    Assert-Quality ([CryptoFileScanner]::ReadFile($boundary,$true,$false,$false,4MB,$true,$null).Evidence -contains 'validated_ethereum_keystore_structure') 'Keystore with late crypto fields survives a boundary without a JSON extension hint'
    $sourceHashes=@{}; foreach ($file in Get-ChildItem -LiteralPath $inputRoot -File) { $sourceHashes[$file.FullName]=(Get-FileHash -LiteralPath $file.FullName).Hash }
    $csv=Join-Path $testBase 'result.csv'
    $config=@{Scanner=(Join-Path $repo 'Scan-CryptoArtifacts.ps1');Roots=@($inputRoot);Csv=$csv;Answers=@();NoProgress=$false;NoCache=$false;Rescan=$false;LockFile='';MaxMB=256;RepeatInSession=$false;AlternateScanner='';StopAfterFiles=0;CheckpointFiles=1;MaxDocumentMB=32;MaxExpandedMB=256;CpuCorePercent=80;Workers=0}
    $configPath=Join-Path $testBase 'config.json'; $config|ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $outputPaths=@($csv,[IO.Path]::ChangeExtension($csv,'.secundarios.csv'),[IO.Path]::ChangeExtension($csv,'.incidencias.csv'),[IO.Path]::ChangeExtension($csv,'.scanstate'))
    $before=@{}
    foreach ($run in @(1,2)) {
        $summaryPath=Join-Path $testBase 'summary.json'
        $null=& powershell.exe -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath (Join-Path $testBase 'progress.json')
        if ($LASTEXITCODE) { throw ('Integration fixture failed: '+[IO.File]::ReadAllText($summaryPath)) }
        $summary=Get-Content -LiteralPath $summaryPath -Raw|ConvertFrom-Json
        $main=@(Import-Csv -LiteralPath $csv); $secondary=@(Import-Csv -LiteralPath $outputPaths[1]); $incidents=@(Import-Csv -LiteralPath $outputPaths[2])
        Assert-Quality (@($main|Where-Object {$_.Ubicacion.EndsWith('seed.txt') -and $_.Tipo -eq 'frase_bip39_checksum_valido'}).Count -eq 1) 'Complete candidate reaches primary CSV'
        Assert-Quality (@($main|Where-Object {$_.Ubicacion.EndsWith('solana-valid.json') -and $_.Tipo -eq 'keypair_solana_par_claves_validado'}).Count -eq 1) 'Validated Solana keypair reaches primary CSV'
        Assert-Quality (@($secondary|Where-Object {$_.Ubicacion.EndsWith('evm-checksum.txt') -and $_.Tipo -eq 'direccion_evm_checksum_eip55_valido'}).Count -eq 1) 'EIP-55 public address stays secondary with validated type'
        Assert-Quality (@($secondary|Where-Object {$_.Ubicacion.EndsWith('monero-checksum.txt') -and $_.Tipo -eq 'direccion_monero_checksum_valido'}).Count -eq 1) 'Monero public address stays secondary with checksum type'
        Assert-Quality (@($secondary|Where-Object {$_.Ubicacion.EndsWith('solana-mismatch.json') -and $_.Tipo -eq 'posible_keypair_solana_json'}).Count -eq 1) 'Mismatched Solana array stays secondary as candidate'
        Assert-Quality (@($main|Where-Object {$_.Ubicacion -match '(?:repeated|fragment|bad-address|mentions|dictionary|example)\.'}).Count -eq 0) 'Weak matches and source examples stay out of primary CSV'
        Assert-Quality (@($secondary|Where-Object {$_.Tipo -eq 'diccionario_publico_del_detector'}).Count -eq 1) 'Canonical dictionary recognized by whole file SHA256'
        Assert-Quality (@($incidents|Where-Object {$_.Ubicacion.EndsWith('broken.pdf')}).Count -gt 0) 'Unreviewable content preserved in incidence CSV'
        Assert-Quality ($summary.PrincipalFindings+$summary.SecondaryFindings+$summary.CoverageFindings -eq $summary.Findings) 'All evidence reconciles across three outputs'
        Assert-Quality ($summary.WorkerCount -le $summary.AllowedPhysicalCores -and $summary.CpuCorePercent -eq 80) 'CPU percentage and worker limits preserved'
        foreach ($out in $outputPaths) {
            $hash=(Get-FileHash -LiteralPath $out).Hash; $ticks=(Get-Item -LiteralPath $out).LastWriteTimeUtc.Ticks
            if ($run -eq 1) { $before[$out]=@($hash,$ticks) } else { Assert-Quality ($before[$out][0] -eq $hash -and $before[$out][1] -eq $ticks) 'Every output is byte and timestamp idempotent' }
            $text=[IO.File]::ReadAllText($out)
            Assert-Quality (-not $text.Contains($phrase) -and -not $text.Contains($repeated) -and -not $text.Contains('2'*64)) 'Outputs contain no synthetic phrase or key material'
        }
        foreach ($out in $outputPaths[0..2]) { $header=[IO.File]::ReadAllLines($out)[0]; Assert-Quality ($header -eq '"Ubicacion","Tipo","FechaCreacionUtc","FechaModificacionUtc"') 'CSV includes path, type, and file timestamps' }
        if ($run -eq 2) { Assert-Quality ($summary.ContentAnalyzed -eq 1 -and $summary.ContentReused -gt 0 -and -not $summary.SecondaryCsvWritten -and -not $summary.IncidentsCsvWritten) 'Second run reuses complete detections, retries broken PDF, and preserves outputs' }
    }
    foreach ($path in $sourceHashes.Keys) { Assert-Quality ((Get-FileHash -LiteralPath $path).Hash -eq $sourceHashes[$path]) 'Source bytes unchanged' }
    Write-Host ('ALL PASSED: '+$script:Passed+' detection quality assertions.')
}
finally {
    $target=[IO.Path]::GetFullPath($testBase)
    if (-not $target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe cleanup target' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
