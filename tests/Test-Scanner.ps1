[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$wordListRoot = Join-Path $repo 'resources\wordlists'
$scanner = Join-Path $repo 'Scan-CryptoArtifacts.ps1'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
# Dashed IDs cannot accidentally look like a long Base58 address in a finding path.
$testBase = Join-Path $tempRoot ('wallet-scanner-tests-' + [guid]::NewGuid().ToString('D'))
$inputRoot = Join-Path $testBase 'input'
New-Item -ItemType Directory -Path $inputRoot -Force | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
$script:Passed = 0
$script:RunNumber = 0
$secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$englishPhrase = 'abandon amount liar amount expire adjust cage candy arch gather drum buyer'
$expected = New-Object 'Collections.Generic.List[object]'

function Assert-Case([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw ('FAIL: ' + $Name) }
    $script:Passed++
    Write-Host ('PASS: ' + $Name)
}
function Write-Fixture([string]$Name, [string]$Text, [Text.Encoding]$Encoding = $utf8) {
    $path = Join-Path $inputRoot $Name
    $directory = [IO.Path]::GetDirectoryName($path)
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    [IO.File]::WriteAllText($path, $Text, $Encoding)
    return $path
}
function Expect-Fixture([string]$Name, [string]$Text, [string]$Type, [Text.Encoding]$Encoding = $utf8) {
    $path = Write-Fixture $Name $Text $Encoding
    $expected.Add([pscustomobject]@{ Path = $path; Type = $Type })
}
function Invoke-Fixture {
    param([string]$Csv, [string[]]$Roots = @($inputRoot), [string]$ScannerPath = $scanner,
        [string[]]$Answers = @(), [switch]$Progress, [switch]$NoCache, [switch]$Rescan,
        [string]$LockFile = '', [int]$MaxMB = 256, [switch]$ExpectError,
        [switch]$RepeatInSession, [string]$AlternateScanner = '', [int]$StopAfterFiles = 0,
        [int]$CheckpointFiles = 1000, [int]$MaxDocumentMB = 32, [int]$MaxExpandedMB = 256)
    $script:RunNumber++
    $configPath = Join-Path $testBase ('run-' + $script:RunNumber + '.json')
    $summaryPath = Join-Path $testBase ('summary-' + $script:RunNumber + '.json')
    $progressPath = Join-Path $testBase ('progress-' + $script:RunNumber + '.json')
    $config = @{ Scanner = $ScannerPath; Roots = @($Roots); Csv = $Csv; Answers = @($Answers); NoProgress = -not $Progress;
        NoCache = [bool]$NoCache; Rescan = [bool]$Rescan; LockFile = $LockFile; MaxMB = $MaxMB;
        RepeatInSession = [bool]$RepeatInSession; AlternateScanner = $AlternateScanner; StopAfterFiles = $StopAfterFiles;
        CheckpointFiles = $CheckpointFiles; MaxDocumentMB = $MaxDocumentMB; MaxExpandedMB = $MaxExpandedMB }
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $console = @(& $windowsPowerShell -NoProfile -File (Join-Path $PSScriptRoot 'Invoke-ScannerFixture.ps1') -ConfigPath $configPath -SummaryPath $summaryPath -ProgressPath $progressPath)
    $code = $LASTEXITCODE
    $summary = if (Test-Path -LiteralPath $summaryPath) { Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json } else { $null }
    if ($code -ne 0 -and -not $ExpectError) { throw ('Fixture process failed: ' + ($summary | ConvertTo-Json -Compress)) }
    return [pscustomobject]@{ Summary = $summary; Console = ($console -join "`n"); ExitCode = $code;
        Progress = if (Test-Path -LiteralPath $progressPath) { @(Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json) } else { @() } }
}
function New-Bip39([int]$EntropyLength, [string[]]$Words) {
    $entropy = New-Object byte[] $EntropyLength
    for ($i = 0; $i -lt $EntropyLength; $i++) { $entropy[$i] = [byte](($i * 17 + 13) % 256) }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($entropy) } finally { $sha.Dispose() }
    $bits = [string]::Concat(@($entropy | ForEach-Object { [Convert]::ToString([int]$_, 2).PadLeft(8, '0') })) + [Convert]::ToString([int]$hash[0], 2).PadLeft(8, '0').Substring(0, $EntropyLength / 4)
    $phrase = New-Object 'Collections.Generic.List[string]'
    for ($i = 0; $i -lt $bits.Length; $i += 11) { $phrase.Add($Words[[Convert]::ToInt32($bits.Substring($i, 11), 2)]) }
    return ($phrase -join ' ')
}

function Write-ZipFixture([string]$Destination, [hashtable]$Entries) {
    $stream = [IO.File]::Create($Destination)
    $zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$false)
    try {
        foreach ($name in $Entries.Keys) {
            $entry = $zip.CreateEntry($name)
            $output = $entry.Open()
            try {
                [byte[]]$bytes = @()
                if ($Entries[$name] -is [byte[]]) { $bytes = $Entries[$name] } else { $bytes = [Text.Encoding]::UTF8.GetBytes([string]$Entries[$name]) }
                $output.Write($bytes,0,$bytes.Length)
            } finally { $output.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
}
function Write-PdfFixture([string]$Destination, [string]$Text) {
    $content = 'BT /F1 10 Tf 10 700 Td (' + $Text.Replace('\','\\').Replace('(','\(').Replace(')','\)') + ') Tj ET'
    $objects = @('<< /Type /Catalog /Pages 2 0 R >>','<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',("<< /Length " + $content.Length + " >>" + [char]10 + "stream" + [char]10 + $content + [char]10 + "endstream"))
    $pdf = [Text.StringBuilder]::new("%PDF-1.4" + [char]10)
    $offsets = @(0)
    for ($i=0;$i -lt $objects.Count;$i++) { $offsets += $pdf.Length; [void]$pdf.Append(($i+1).ToString() + " 0 obj" + [char]10 + $objects[$i] + [char]10 + "endobj" + [char]10) }
    $xref = $pdf.Length
    [void]$pdf.Append("xref" + [char]10 + "0 6" + [char]10 + "0000000000 65535 f " + [char]10)
    foreach ($offset in $offsets[1..5]) { [void]$pdf.Append($offset.ToString('D10') + " 00000 n " + [char]10) }
    [void]$pdf.Append("trailer" + [char]10 + "<< /Size 6 /Root 1 0 R >>" + [char]10 + "startxref" + [char]10 + $xref + [char]10 + "%%EOF" + [char]10)
    [IO.File]::WriteAllBytes($Destination,[Text.Encoding]::ASCII.GetBytes($pdf.ToString()))
}
function New-Base58Check([byte[]]$Payload) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($sha.ComputeHash($Payload)) } finally { $sha.Dispose() }
    $bytes = [byte[]]($Payload + $digest[0..3]); [Array]::Reverse($bytes)
    $number = [Numerics.BigInteger]::new([byte[]]($bytes + @(0)))
    $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    $encoded = ''
    while ($number -gt 0) { $encoded = $alphabet[[int]($number % 58)] + $encoded; $number = [Numerics.BigInteger]::Divide($number,58) }
    foreach ($value in $Payload) { if ($value -ne 0) { break }; $encoded = '1' + $encoded }
    return $encoded
}

try {
    Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem,System.Numerics
    Add-Type -Path (Join-Path $PSScriptRoot 'QualityVectors.cs')
    foreach ($kind in @('docx','xlsx','pptx')) {
        $entry = switch ($kind) { 'docx' { 'word/document.xml' }; 'xlsx' { 'xl/sharedStrings.xml' }; 'pptx' { 'ppt/slides/slide1.xml' } }
        $xml = '<root><p><t>' + $englishPhrase + '</t></p></root>'
        Write-ZipFixture (Join-Path $inputRoot ('document.' + $kind)) @{ $entry = $xml }
        $expected.Add([pscustomobject]@{ Path=(Join-Path $inputRoot ('document.' + $kind)); Type='frase_bip39_checksum_valido' })
    }
    Write-ZipFixture (Join-Path $inputRoot 'backup.zip') @{ 'notes.txt'=$englishPhrase; 'ignored.exe'='not executed' }
    $expected.Add([pscustomobject]@{ Path=(Join-Path $inputRoot 'backup.zip'); Type='frase_bip39_checksum_valido' })
    Write-ZipFixture (Join-Path $inputRoot 'nested.zip') @{ 'inner.zip'=[IO.File]::ReadAllBytes((Join-Path $inputRoot 'backup.zip')) }
    $expected.Add([pscustomobject]@{ Path=(Join-Path $inputRoot 'nested.zip'); Type='frase_bip39_checksum_valido' })
    Write-PdfFixture (Join-Path $inputRoot 'document.pdf') $englishPhrase
    $expected.Add([pscustomobject]@{ Path=(Join-Path $inputRoot 'document.pdf'); Type='frase_bip39_checksum_valido' })
    $wif = New-Base58Check ([byte[]](@(128) + (@(0) * 31) + @(1)))
    Expect-Fixture 'valid-wif.txt' $wif 'clave_privada_bitcoin_checksum_valido'
    $extendedPayload = New-Object byte[] 78
    $extendedPayload[0]=4; $extendedPayload[1]=136; $extendedPayload[2]=173; $extendedPayload[3]=228; $extendedPayload[77]=1
    $xprv = New-Base58Check $extendedPayload
    Expect-Fixture 'valid-xprv.txt' $xprv 'clave_privada_extendida_checksum_valido'
    Expect-Fixture 'notas-áñ-钱包.txt' $englishPhrase 'frase_bip39_checksum_valido'
    foreach ($language in @('english','spanish')) {
        $words = [IO.File]::ReadAllLines((Join-Path $wordListRoot ('bip39-' + $language + '.txt')), [Text.Encoding]::UTF8)
        foreach ($length in @(16,20,24,28,32)) { Expect-Fixture ('bip-' + $language + '-' + $length + '.txt') (New-Bip39 $length $words) 'frase_bip39_checksum_valido' }
    }
    foreach ($language in @('english','english-old','spanish')) {
        $words = [IO.File]::ReadAllLines((Join-Path $wordListRoot ('monero-' + $language + '.txt')), [Text.Encoding]::UTF8)
        Expect-Fixture ('monero-' + $language + '.txt') ((@($words[0]) * 25) -join ' ') 'candidata_monero_repetitiva_checksum_valido'
        $prefixLength = if ($language -eq 'english') { 3 } else { 4 }
        Expect-Fixture ('monero-prefix-' + $language + '.txt') ((@($words[0].Substring(0,$prefixLength)) * 25) -join ' ') 'candidata_monero_repetitiva_checksum_valido'
    }
    [void](Write-Fixture 'monero-false-prefix.txt' ((@('abbeysuffix') * 25) -join ' '))
    Expect-Fixture 'slip20.txt' 'duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard' 'respaldo_slip39_checksum_valido'
    Expect-Fixture 'slip33.txt' 'impulse calcium academic academic alcohol sugar lyrics pajamas column facility finance tension extend space birthday rainbow swimming purple syndrome facility trial warn duration snapshot shadow hormone rhyme public spine counter easy hawk album' 'respaldo_slip39_checksum_valido'
    [void](Write-Fixture 'slip-invalid.txt' 'duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision academic')
    [void](Write-Fixture 'bip-invalid.txt' ((@('abandon') * 12) -join ' '))
    Expect-Fixture 'key.json' ('{"privateKey":"0x' + $secret + '"}') 'candidata_clave_hexadecimal_sin_validar'
    Expect-Fixture 'raw.key' $secret 'candidata_clave_hexadecimal_sin_validar'
    $secretName = 'privateKey_' + $secret + '.txt'
    [void](Write-Fixture $secretName $secret)
    [void](Write-Fixture 'unlabelled-hash.txt' $secret)
    Expect-Fixture 'solana.json' ('[' + ((0..63) -join ',') + ']') 'posible_keypair_solana_json'
    [void](Write-Fixture 'solana-65.json' ('[' + ((0..64) -join ',') + ']'))
    [void](Write-Fixture 'solana-256.json' ('[' + ((@((0..62)) + @(256)) -join ',') + ']'))
    Expect-Fixture 'wif.txt' ('K' + [string]::Concat(@('1' * 51))) 'candidata_formato_clave_privada_bitcoin'
    Expect-Fixture 'xprv.txt' ('xprv' + [string]::Concat(@('1' * 100))) 'candidata_formato_clave_extendida'
    Expect-Fixture 'evm.txt' ('0x' + [string]::Concat(@('a' * 40))) 'candidata_direccion_evm_sin_validar'
    Expect-Fixture 'btc.txt' '1BoatSLRHtKNngkdXEeobR76b53LETtpyT' 'direccion_bitcoin_checksum_valido'
    Expect-Fixture 'monero-address.txt' '888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H' 'direccion_monero_checksum_valido'
    [void](Write-Fixture 'monero-address-invalid.txt' ('4' + [string]::Concat(@('1' * 94))))
    Expect-Fixture 'wallet.dat' '' 'nombre_wallet_core_sin_validar'
    Expect-Fixture 'recovery_wallet.blob' $englishPhrase 'frase_bip39_checksum_valido'
    Expect-Fixture 'Google\Chrome\User Data\Default\Local Extension Settings\fixture\data.ldb' 'bitcoin wallet' 'almacenamiento_extension_cripto'
    Expect-Fixture '.env' ('private_key=' + $secret) 'candidata_clave_hexadecimal_sin_validar'
    Expect-Fixture 'clave.json' ('{"clave_privada":"' + $secret + '"}') 'candidata_clave_hexadecimal_sin_validar'
    Expect-Fixture 'notas.txt' 'respaldo de criptomonedas' 'terminos_criptomoneda'
    Expect-Fixture 'strong-with-terms.txt' ($wif + ' bitcoin wallet crypto mining') 'clave_privada_bitcoin_checksum_valido'
    $coreDirectory=Join-Path $inputRoot 'valid-core'
    [void][IO.Directory]::CreateDirectory($coreDirectory)
    $corePath=Join-Path $coreDirectory 'wallet.dat'
    $coreHeader=New-Object byte[] 4096; $coreHeader[12]=0; $coreHeader[13]=5; $coreHeader[14]=0x31; $coreHeader[15]=0x62
    [IO.File]::WriteAllBytes($corePath,$coreHeader)
    $expected.Add([pscustomobject]@{Path=$corePath;Type='candidata_wallet_core_berkeley_db'})
    $sqliteDirectory=Join-Path $inputRoot 'valid-sqlite'
    [void][IO.Directory]::CreateDirectory($sqliteDirectory)
    $sqlitePath=Join-Path $sqliteDirectory 'wallet.dat'
    $sqliteFile=New-Object byte[] 512; $sqliteMagic=[Text.Encoding]::ASCII.GetBytes('SQLite format 3')
    [Array]::Copy($sqliteMagic,0,$sqliteFile,0,$sqliteMagic.Length); $sqliteFile[15]=0
    [byte[]]$networkMagic=@(0xf9,0xbe,0xb4,0xd9); [Array]::Copy($networkMagic,0,$sqliteFile,68,4)
    [IO.File]::WriteAllBytes($sqlitePath,$sqliteFile)
    $expected.Add([pscustomobject]@{Path=$sqlitePath;Type='estructura_wallet_core_validada'})
    $sqliteBackupPath=Join-Path $sqliteDirectory 'wallet.dat.bak'
    [IO.File]::WriteAllBytes($sqliteBackupPath,$sqliteFile)
    $expected.Add([pscustomobject]@{Path=$sqliteBackupPath;Type='estructura_wallet_core_validada'})
    $electrumPath=Join-Path $inputRoot '.electrum\wallets\default_wallet'
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($electrumPath))
    $electrumJson=@{wallet_type='standard';seed_version=73;keystore=@{type='bip32';xpub=[QualityVectors]::ExtendedPublicKey()}} | ConvertTo-Json -Depth 5 -Compress
    [IO.File]::WriteAllText($electrumPath,$electrumJson,$utf8)
    $expected.Add([pscustomobject]@{Path=$electrumPath;Type='estructura_wallet_electrum_validada'})
    $zipStrong=Join-Path $inputRoot 'mixed-strong.zip'
    Write-ZipFixture $zipStrong @{ 'keys/wif.txt'=$wif; 'notes.txt'='bitcoin wallet crypto mining' }
    $expected.Add([pscustomobject]@{Path=$zipStrong;Type='clave_privada_bitcoin_checksum_valido'})
    $expected.Add([pscustomobject]@{Path=$zipStrong;Type='terminos_criptomoneda'})
    $expected.Add([pscustomobject]@{Path=$zipStrong;Type='terminos_billetera'})
    $expected.Add([pscustomobject]@{Path=$zipStrong;Type='terminos_mineria'})
    $pad = [string]::Concat(@('z' * (1MB - 2)))
    $spanishWords = [IO.File]::ReadAllLines((Join-Path $wordListRoot 'bip39-spanish.txt'), [Text.Encoding]::UTF8)
    $spanishPhrase = (New-Bip39 16 $spanishWords).Normalize([Text.NormalizationForm]::FormC)
    Expect-Fixture 'boundary-utf8.txt' ($pad + ' ' + $spanishPhrase) 'frase_bip39_checksum_valido'
    Expect-Fixture 'boundary-mnemonic.txt' ($pad + ' ' + $englishPhrase) 'frase_bip39_checksum_valido'
    foreach ($encodingName in @('unicode','bigendianunicode','utf32')) {
        $encoding = switch ($encodingName) { 'unicode' { [Text.Encoding]::Unicode }; 'bigendianunicode' { [Text.Encoding]::BigEndianUnicode }; 'utf32' { [Text.Encoding]::UTF32 } }
        Expect-Fixture ('encoding-' + $encodingName + '.txt') $englishPhrase ([string]'frase_bip39_checksum_valido') $encoding
    }
    Expect-Fixture 'encoding-utf32be.txt' $englishPhrase 'frase_bip39_checksum_valido' ([Text.UTF32Encoding]::new($true,$true))
    Expect-Fixture 'keystore-chunks.json' ('{"crypto":{},"padding":"' + $pad + 'zzzz","cipher":"aes","kdfparams":{}}') 'keystore_ethereum_cifrado'
    $label = ' privateKey=' + $secret
    [void](Write-Fixture 'boundary-hex-negative.txt' ([string]::Concat(@('z' * (1MB - $label.Length))) + $label + 'f'))
    $monoPrefix = ' ' + ((@('abbey') * 24) -join ' ') + ' abb'
    [void](Write-Fixture 'boundary-monero-negative.txt' ([string]::Concat(@('z' * (1MB - $monoPrefix.Length))) + $monoPrefix + 'eysuffix'))
    [void](Write-Fixture 'new-algorithm.txt' 'freshcoin')
    $inputHashes = @{}
    Get-ChildItem -LiteralPath $inputRoot -File -Recurse -Force | ForEach-Object { $inputHashes[$_.FullName] = (Get-FileHash -LiteralPath $_.FullName).Hash }
    $csv = Join-Path $testBase 'result.csv'
    $first = Invoke-Fixture $csv -Progress
    Assert-Case ($first.Summary.Incidents -eq 0) 'Initial scan has no read/enumeration errors'
    $rows = @(Import-Csv -LiteralPath $csv) + @(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($csv,'.secundarios.csv'))) + @(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($csv,'.incidencias.csv')))
    $primaryRows=@(Import-Csv -LiteralPath $csv)
    $secondaryRows=@(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($csv,'.secundarios.csv')))
    $reviewRows=@(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($csv,'.revision.csv')))
    $secondarySummary=@(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($csv,'.secundarios-resumen.csv')))
    $incidentRows=@(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($csv,'.incidencias.csv')))
    Assert-Case ($reviewRows.Count -eq ($primaryRows.Count + $secondaryRows.Count + $incidentRows.Count) -and $first.Summary.ReviewReportRows -eq $reviewRows.Count) 'Completed scan generates the review report automatically'
    Assert-Case ($secondarySummary.Count -gt 0 -and $first.Summary.SecondarySummaryFiles -eq $secondarySummary.Count) 'Completed scan generates the grouped secondary summary'
    Assert-Case (-not [IO.File]::ReadAllText([IO.Path]::ChangeExtension($csv,'.revision.csv')).Contains($secret)) 'Review report does not contain synthetic secret values'
    Assert-Case (@($secondaryRows|Where-Object {$_.Ubicacion -eq (Join-Path $inputRoot 'wallet.dat') -and $_.Tipo -eq 'nombre_wallet_core_sin_validar'}).Count -eq 1) 'Unverified wallet.dat name stays secondary'
    Assert-Case (@($primaryRows|Where-Object {$_.Tipo -eq 'estructura_wallet_core_validada'}).Count -eq 2) 'SQLite wallet headers and wallet.dat backups reach primary results'
    Assert-Case (@($primaryRows|Where-Object {$_.Ubicacion -eq $corePath}).Count -eq 0 -and @($secondaryRows|Where-Object {$_.Ubicacion -eq $corePath -and $_.Tipo -eq 'candidata_wallet_core_berkeley_db'}).Count -eq 1) 'Generic Berkeley DB header is retained only as a secondary candidate'
    Assert-Case (@($primaryRows|Where-Object {$_.Ubicacion -eq $electrumPath -and $_.Tipo -eq 'estructura_wallet_electrum_validada'}).Count -eq 1) 'Electrum structure in an extensionless default wallet is detected'
    Assert-Case (@($secondaryRows|Where-Object {$_.Ubicacion.EndsWith('btc.txt') -and $_.Tipo -eq 'direccion_bitcoin_checksum_valido'}).Count -eq 1) 'A valid public Bitcoin address remains secondary'
    foreach ($item in $expected) { Assert-Case (@($rows | Where-Object { $_.Ubicacion -eq $item.Path -and $_.Tipo -eq $item.Type }).Count -eq 1) ('Detector fixture: ' + [IO.Path]::GetFileName($item.Path)) }
    foreach ($negative in @(@('monero-false-prefix.txt','frase_monero_checksum_valido'),@('slip-invalid.txt','respaldo_slip39_checksum_valido'),@('bip-invalid.txt','frase_bip39_checksum_valido'),@('unlabelled-hash.txt','candidata_clave_hexadecimal_sin_validar'),@('solana-65.json','posible_keypair_solana_json'),@('solana-256.json','posible_keypair_solana_json'),@('boundary-hex-negative.txt','candidata_clave_hexadecimal_sin_validar'),@('boundary-monero-negative.txt','frase_monero_checksum_valido'))) {
        Assert-Case (@($rows | Where-Object { $_.Ubicacion -eq (Join-Path $inputRoot $negative[0]) -and $_.Tipo -eq $negative[1] }).Count -eq 0) ('Negative fixture: ' + $negative[0])
    }
    Assert-Case (@($rows | Where-Object { $_.Ubicacion.EndsWith('privateKey_[REDACTADO].txt') -and $_.Tipo -eq 'candidata_clave_hexadecimal_sin_validar' }).Count -eq 1) 'Secret in filename detected and redacted'
    Assert-Case (@($rows | Where-Object { $_.Ubicacion.EndsWith('monero-address-invalid.txt') -and $_.Tipo -eq 'candidata_direccion_monero_sin_validar' }).Count -eq 0) 'Invalid Monero address candidate is omitted by default'
    $strongRows=@($rows|Where-Object {$_.Ubicacion.EndsWith('strong-with-terms.txt')})
    Assert-Case (@($strongRows|Where-Object {$_.Tipo -eq 'clave_privada_bitcoin_checksum_valido'}).Count -eq 1 -and @($strongRows|Where-Object {$_.Tipo -match '^terminos_'}).Count -eq 0) 'Specific private-key evidence replaces generic terms at the same file location'
    $mixedRows=@($rows|Where-Object {$_.Ubicacion -eq $zipStrong})
    Assert-Case (@($mixedRows|Where-Object {$_.Tipo -match '^terminos_'}).Count -eq 3) 'Generic clues from a different ZIP member remain preserved'
    Assert-Case (-not [IO.File]::ReadAllText($csv).Contains($secret)) 'CSV never contains hex fixture secret'
    Assert-Case (-not [IO.File]::ReadAllText($csv).Contains($wif) -and -not [IO.File]::ReadAllText($csv).Contains($xprv)) 'CSV never contains validated private key fixtures'
    Assert-Case (@($rows | Where-Object { $_.Ubicacion.EndsWith('wif.txt') -and $_.Tipo -eq 'clave_privada_bitcoin_checksum_valido' }).Count -eq 1) 'Invalid WIF-shaped fixture is not upgraded to validated'
    Assert-Case ($first.Summary.MembersScanned -gt 0 -and $first.Summary.MembersSkipped -gt 0) 'Coverage counts supported and skipped container members'
    Assert-Case ($first.Summary.VolumeIds[0].Length -eq 64 -and $first.Summary.FileSystems[0].Length -gt 0) 'Volume identity and filesystem appear without raw volume identifiers'
    Assert-Case ((@($rows[0].PSObject.Properties.Name) -join ',') -eq 'Ubicacion,Tipo,FechaCreacionUtc,FechaModificacionUtc') 'CSV includes path, type, and file timestamps'
    $datedRow = @($rows | Where-Object { $_.Ubicacion -eq $expected[0].Path } | Select-Object -First 1)[0]
    $utcTimestampPattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$'
    Assert-Case ($null -ne $datedRow -and $datedRow.FechaCreacionUtc -match $utcTimestampPattern -and $datedRow.FechaModificacionUtc -match $utcTimestampPattern) 'CSV creation and modification timestamps use ISO 8601 UTC'
    foreach ($id in @(1,2)) {
        $records = @($first.Progress | Where-Object { $_.Id -eq $id -and $_.Percent -ge 0 -and -not $_.Completed })
        Assert-Case (@($records | Where-Object { $_.Percent -gt 0 -and $_.Percent -lt 100 }).Count -gt 0) ('Progress bar advances during reading: ' + $id)
        Assert-Case (@($records | Where-Object { $_.Percent -eq 100 }).Count -gt 0) ('Progress bar completes at 100: ' + $id)
        $previous = 0
        foreach ($record in $records) { if ($record.Percent -lt $previous) { throw 'Progress regressed.' }; $previous = $record.Percent }
    }
    $unchangedInputs = $true
    foreach ($path in $inputHashes.Keys) { if ((Get-FileHash -LiteralPath $path).Hash -ne $inputHashes[$path]) { $unchangedInputs = $false } }
    Assert-Case $unchangedInputs 'All input file hashes remain unchanged'
    $state = [IO.Path]::ChangeExtension($csv,'.scanstate')
    $stateText = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($state))
    Assert-Case (-not $stateText.Contains($secret) -and -not $stateText.Contains($englishPhrase) -and -not $stateText.Contains($inputRoot)) 'State contains hashes/types, no keys or raw paths'
    $csvHash = (Get-FileHash -LiteralPath $csv).Hash
    $stateHash = (Get-FileHash -LiteralPath $state).Hash
    $csvTime = (Get-Item -LiteralPath $csv).LastWriteTimeUtc.Ticks
    $stateTime = (Get-Item -LiteralPath $state).LastWriteTimeUtc.Ticks
    $second = Invoke-Fixture $csv
    Assert-Case ($second.Summary.ContentAnalyzed -eq 0 -and $second.Summary.ContentReused -eq $first.Summary.ContentAnalyzed) 'Same bytes reuse cached detections'
    Assert-Case (-not $second.Summary.CsvWritten -and -not $second.Summary.StateWritten) 'Unchanged outputs are not rewritten'
    Assert-Case ((Get-FileHash -LiteralPath $csv).Hash -eq $csvHash -and (Get-FileHash -LiteralPath $state).Hash -eq $stateHash) 'CSV and state are byte-identical on repetition'
    Assert-Case ((Get-Item -LiteralPath $csv).LastWriteTimeUtc.Ticks -eq $csvTime -and (Get-Item -LiteralPath $state).LastWriteTimeUtc.Ticks -eq $stateTime) 'Output timestamps remain unchanged'
    Assert-Case ($second.Summary.MembersScanned -eq $first.Summary.MembersScanned -and $second.Summary.MembersSkipped -eq $first.Summary.MembersSkipped) 'Cached document coverage is preserved'
    $interruptedCsv = Join-Path $testBase 'interrupted.csv'
    $interrupted = Invoke-Fixture $interruptedCsv -Progress -StopAfterFiles 1 -CheckpointFiles 1 -ExpectError
    $journal = [IO.Path]::ChangeExtension($interruptedCsv,'.scanjournal')
    Assert-Case ($interrupted.ExitCode -eq 73 -and (Test-Path -LiteralPath $journal) -and (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($interruptedCsv,'.partial.csv')))) 'Abrupt interruption leaves recoverable journal and partial CSV'
    Assert-Case (-not (Test-Path -LiteralPath $interruptedCsv)) 'Interrupted scan does not publish a completed CSV'
    $journalBytes = [IO.File]::ReadAllBytes($journal)
    $journalText = [Text.Encoding]::UTF8.GetString($journalBytes)
    Assert-Case (-not $journalText.Contains($inputRoot) -and -not $journalText.Contains($englishPhrase)) 'Recovery journal contains hashes and types only'
    [IO.File]::WriteAllBytes($journal,[byte[]]($journalBytes + @(255,255)))
    $recovered = Invoke-Fixture $interruptedCsv
    Assert-Case ($recovered.Summary.RecoveredEntries -ge 1 -and $recovered.Summary.ContentReused -ge 1) 'A truncated journal tail preserves complete checkpoints'
    Assert-Case (-not (Test-Path -LiteralPath $journal) -and -not (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($interruptedCsv,'.partial.csv')))) 'Successful recovery clears transient checkpoint outputs'
    $sameSession = Invoke-Fixture (Join-Path $testBase 'same-session.csv') -RepeatInSession
    Assert-Case ($sameSession.Summary.ContentAnalyzed -eq 0 -and $sameSession.Summary.ContentReused -eq $first.Summary.ContentAnalyzed) 'Repeated scans work in the same PowerShell session'
    $target = Join-Path $inputRoot 'new-algorithm.txt'
    $originalTime = (Get-Item -LiteralPath $target).LastWriteTimeUtc
    [IO.File]::WriteAllText($target,'ethereum!', $utf8)
    [IO.File]::SetLastWriteTimeUtc($target,$originalTime)
    $changed = Invoke-Fixture $csv
    Assert-Case ($changed.Summary.ContentAnalyzed -eq 1) 'Changed bytes with same length/date are reanalyzed'
    Assert-Case (@(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($csv,'.secundarios.csv')) | Where-Object { $_.Ubicacion -eq $target -and $_.Tipo -eq 'terminos_criptomoneda' }).Count -eq 1) 'Changed-content evidence reaches secondary CSV'
    $locked = Invoke-Fixture $csv -LockFile $target
    Assert-Case ($locked.Summary.Incidents -eq 1) 'Locked file becomes incidence, not silent negative'
    $retry = Invoke-Fixture $csv
    Assert-Case ($retry.Summary.ContentAnalyzed -eq 1 -and $retry.Summary.Incidents -eq 0) 'Read errors are retried rather than cached'
    Remove-Item -LiteralPath $target
    [void](Invoke-Fixture $csv)
    Assert-Case (@(Import-Csv -LiteralPath $csv | Where-Object { $_.Ubicacion -eq $target }).Count -eq 0) 'Deleted-file evidence is removed'
    [IO.File]::WriteAllBytes($state,[byte[]]@(255,255,255,255,255))
    $corrupt = Invoke-Fixture $csv
    Assert-Case ($corrupt.Summary.ContentReused -eq 0 -and $corrupt.Summary.ContentAnalyzed -gt 0) 'Corrupt cache triggers complete analysis'
    $forced = Invoke-Fixture $csv -Rescan
    Assert-Case ($forced.Summary.ContentReused -eq 0 -and $forced.Summary.ContentAnalyzed -gt 0) 'Rescan forces all detectors'
    $onlyCsv = Join-Path $testBase 'no-cache.csv'
    $uncached = Invoke-Fixture $onlyCsv -NoCache
    Assert-Case (-not (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($onlyCsv,'.scanstate'))) -and $uncached.Summary.ContentAnalyzed -gt 0) 'NoCache creates CSV only'
    $overlap = Invoke-Fixture (Join-Path $testBase 'overlap.csv') -Roots @($inputRoot,(Join-Path $inputRoot 'Google'),$inputRoot)
    Assert-Case ($overlap.Summary.FilesEnumerated -eq ($first.Summary.FilesEnumerated - 1)) 'Overlapping roots are scanned once'
    $rejected = Invoke-Fixture (Join-Path $inputRoot 'forbidden.csv') -ExpectError
    Assert-Case ($rejected.ExitCode -ne 0 -and -not (Test-Path -LiteralPath (Join-Path $inputRoot 'forbidden.csv'))) 'Output inside input is rejected before writing'
    $menuCsv = Join-Path $testBase 'menu.csv'
    $menu = Invoke-Fixture $menuCsv -Roots @() -Answers @('A','invalid','C',(Join-Path $testBase 'missing'),'C',$inputRoot,(Join-Path $inputRoot 'forbidden.csv'),'')
    Assert-Case ($menu.Summary.FilesEnumerated -eq ($first.Summary.FilesEnumerated - 1)) 'Menu chooses custom folder and retries invalid option'
    $cancelCsv = Join-Path $testBase 'cancel.csv'
    [void](Invoke-Fixture $cancelCsv -Roots @() -Answers @('0'))
    Assert-Case (-not (Test-Path -LiteralPath $cancelCsv)) 'Menu cancel writes no output'
    $empty = Join-Path $testBase 'empty'
    New-Item -ItemType Directory -Path $empty | Out-Null
    $emptyRun = Invoke-Fixture (Join-Path $testBase 'empty.csv') -Roots @($empty) -Progress
    Assert-Case ($emptyRun.Summary.FilesEnumerated -eq 0 -and @($emptyRun.Progress | Where-Object { $_.Percent -eq 100 }).Count -eq 2) 'Empty location completes both progress bars'
    $empty2 = Join-Path $testBase 'empty2'
    New-Item -ItemType Directory -Path $empty2 | Out-Null
    $twoEmpty = Invoke-Fixture (Join-Path $testBase 'empty2.csv') -Roots @($empty,$empty2) -Progress
    $previousPercent = 0
    foreach ($record in @($twoEmpty.Progress | Where-Object { $_.Id -eq 1 -and -not $_.Completed -and $_.Percent -ge 0 })) {
        Assert-Case ($record.Percent -ge $previousPercent) 'Global progress does not regress between empty locations'
        $previousPercent = $record.Percent
    }
    Assert-Case ($previousPercent -eq 100) 'Multiple empty locations finish at 100 percent'
    $documentCases = Join-Path $testBase 'document-cases'
    New-Item -ItemType Directory -Path $documentCases | Out-Null
    Write-PdfFixture (Join-Path $documentCases 'encrypted.pdf') '/Encrypt synthetic marker'
    [IO.File]::WriteAllText((Join-Path $documentCases 'broken.pdf'),'not a PDF')
    [IO.File]::WriteAllText((Join-Path $documentCases 'broken.docx'),'not a ZIP')
    Write-PdfFixture (Join-Path $documentCases 'empty.pdf') ''
    Write-ZipFixture (Join-Path $documentCases 'expanded.zip') @{ 'large.txt'=('z' * (2MB)) }
    Write-ZipFixture (Join-Path $documentCases 'wallet-backup.zip') @{ 'wallet.dat'=[byte[]]@(); 'recovery_wallet.blob'=$englishPhrase }
    $badDocs = Invoke-Fixture (Join-Path $testBase 'document-cases.csv') -Roots @($documentCases) -MaxExpandedMB 1
    $badRows = @(Import-Csv -LiteralPath (Join-Path $testBase 'document-cases.csv')) + @(Import-Csv -LiteralPath (Join-Path $testBase 'document-cases.secundarios.csv')) + @(Import-Csv -LiteralPath (Join-Path $testBase 'document-cases.incidencias.csv'))
    foreach ($type in @('documento_cifrado_sin_revisar','error_lectura_documento','documento_sin_texto_extraible','comprimido_supera_limite_expansion','nombre_wallet_core_sin_validar','frase_bip39_checksum_valido')) {
        Assert-Case (@($badRows | Where-Object { $_.Tipo -eq $type }).Count -gt 0) ('Document coverage fixture: ' + $type)
    }
    Assert-Case ($badDocs.Summary.IncompleteDocuments -eq 5 -and $badDocs.Summary.Status -eq 'recorrido_con_incidencias') 'Incomplete documents are explicit in final status'
    $badRepeat = Invoke-Fixture (Join-Path $testBase 'document-cases.csv') -Roots @($documentCases) -MaxExpandedMB 1
    Assert-Case ($badRepeat.Summary.ContentAnalyzed -eq 5) 'Partial document analyses are retried rather than cached'
    $longRoot = Join-Path $testBase 'long'
    $longDirectory = $longRoot + '\' + ((@('carpeta-abcdefghijklmnopqrst') * 10) -join '\')
    [void][IO.Directory]::CreateDirectory('\\?\' + $longDirectory)
    $longFile = $longDirectory + '\notas-á.txt'
    [IO.File]::WriteAllText('\\?\' + $longFile,$englishPhrase,$utf8)
    $longHash = [Convert]::ToBase64String([IO.File]::ReadAllBytes('\\?\' + $longFile))
    $longRun = Invoke-Fixture (Join-Path $testBase 'long.csv') -Roots @($longRoot)
    Assert-Case ($longFile.Length -gt 260 -and $longRun.Summary.Incidents -eq 0 -and $longRun.Summary.Findings -ge 1) 'Files below nested paths longer than 260 characters are analyzed'
    Assert-Case ([Convert]::ToBase64String([IO.File]::ReadAllBytes('\\?\' + $longFile)) -eq $longHash) 'Long-path source bytes are unchanged'
    $longSelected = Invoke-Fixture (Join-Path $testBase 'long-selected.csv') -Roots @($longDirectory)
    Assert-Case ($longSelected.Summary.Incidents -eq 0 -and $longSelected.Summary.FilesEnumerated -eq 1) 'A long folder can also be selected directly'
    $linked = Join-Path $inputRoot 'linked'
    New-Item -ItemType Junction -Path $linked -Target $empty | Out-Null
    $linkRun = Invoke-Fixture (Join-Path $testBase 'links.csv')
    Assert-Case ($linkRun.Summary.ReparsePointsSkipped -eq 1) 'Junctions inside a location are skipped'
    $linkRoot = Invoke-Fixture (Join-Path $testBase 'linked-root.csv') -Roots @($linked) -ExpectError
    Assert-Case ($linkRoot.ExitCode -ne 0) 'A junction cannot be selected as scan root'
    $outputLink = Join-Path $testBase 'output-link'
    New-Item -ItemType Junction -Path $outputLink -Target $empty | Out-Null
    $linkOutput = Invoke-Fixture (Join-Path $outputLink 'result.csv') -ExpectError
    Assert-Case ($linkOutput.ExitCode -ne 0) 'Output through a junction is rejected'
    $copyParent = Join-Path $testBase 'new-detector-package'
    Expand-Archive -LiteralPath (Join-Path $repo 'dist\windows-crypto-artifact-scan.zip') -DestinationPath $copyParent
    $copyFolder = Join-Path $copyParent 'windows-crypto-artifact-scan'
    $copiedScanner = Join-Path $copyFolder 'Scan-CryptoArtifacts.ps1'
    $newCode = [IO.File]::ReadAllText($copiedScanner).Replace('|crypto)\b','|crypto|freshcoin)\b')
    [IO.File]::WriteAllText($copiedScanner,$newCode,[Text.UTF8Encoding]::new($true))
    [void](Write-Fixture 'new-algorithm.txt' 'freshcoin')
    [void](Invoke-Fixture $csv)
    $newAlgorithm = Invoke-Fixture $csv -ScannerPath $copiedScanner
    Assert-Case ($newAlgorithm.Summary.AlgorithmFingerprint -ne $first.Summary.AlgorithmFingerprint -and $newAlgorithm.Summary.ContentReused -eq 0) 'Rule change automatically invalidates every cached detector result'
    Assert-Case (@(Import-Csv -LiteralPath ([IO.Path]::ChangeExtension($csv,'.secundarios.csv')) | Where-Object { $_.Ubicacion.EndsWith('new-algorithm.txt') -and $_.Tipo -eq 'terminos_criptomoneda' }).Count -eq 1) 'New algorithm finds previously undetected evidence'
    $variantDll = Join-Path $copyFolder 'CryptoMnemonicScanner-10.12.dll'
    $dllBytes = [IO.File]::ReadAllBytes($variantDll)
    [IO.File]::WriteAllBytes($variantDll, [byte[]]($dllBytes + @(0)))
    $staleSession = Invoke-Fixture $csv -AlternateScanner $copiedScanner -ExpectError
    Assert-Case ($staleSession.ExitCode -ne 0 -and $staleSession.Summary.Error -match 'nueva sesi') 'Changed DLL requires a fresh session before using stale loaded code'
    Assert-Case (@($staleSession.Console -split "`n" | Where-Object { $_ -match '^Terminado en ' }).Count -eq 1) 'Changed DLL is rejected before a second scan writes output'
    $limit = Invoke-Fixture (Join-Path $testBase 'limit.csv') -MaxMB 1
    Assert-Case ($limit.Summary.OversizeFiles -gt 0) 'Oversize candidates are reported'
    $raised = Invoke-Fixture (Join-Path $testBase 'limit.csv') -MaxMB 2
    Assert-Case ($raised.Summary.AlgorithmFingerprint -ne $limit.Summary.AlgorithmFingerprint -and $raised.Summary.ContentReused -eq 0) 'Content-limit change invalidates prior cache'
    $extract = Join-Path $testBase 'package'
    Expand-Archive -LiteralPath (Join-Path $repo 'dist\windows-crypto-artifact-scan.zip') -DestinationPath $extract
    $packagedScanner = Join-Path $extract 'windows-crypto-artifact-scan\Scan-CryptoArtifacts.ps1'
    Assert-Case ((Get-FileHash -LiteralPath $packagedScanner).Hash -eq (Get-FileHash -LiteralPath $scanner).Hash) 'ZIP has current scanner'
    $packageRun = Invoke-Fixture (Join-Path $testBase 'package.csv') -ScannerPath $packagedScanner -MaxMB 1
    Assert-Case ($packageRun.Summary.Incidents -eq 0) 'Extracted package runs in Windows PowerShell 5.1'
    Write-Host ('ALL PASSED: {0} assertions; only synthetic folders were scanned.' -f $script:Passed)
}
finally {
    $target = [IO.Path]::GetFullPath($testBase)
    if (-not $target.StartsWith($tempRoot.TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to clean outside the synthetic test folder.' }
    if (Get-Variable -Name longRoot -ErrorAction SilentlyContinue) {
        if (-not $longRoot.StartsWith($target + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected long-path fixture cleanup target.' }
        if ([IO.Directory]::Exists('\\?\' + $longRoot)) { [IO.Directory]::Delete('\\?\' + $longRoot,$true) }
    }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
