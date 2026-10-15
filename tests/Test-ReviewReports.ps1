[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Passed = 0
function Assert-Review([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw ('FAIL: ' + $Message) }
    $script:Passed++
}
function New-ReportSourceRow([string]$Location, [string]$Type) {
    [pscustomobject]@{
        Ubicacion = $Location
        Tipo = $Type
        FechaCreacionUtc = '2024-06-07T08:09:10.0000000Z'
        FechaModificacionUtc = '2025-01-02T03:04:05.0000000Z'
    }
}

$base = Join-Path ([IO.Path]::GetTempPath()) ('wallet-review-report-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($base)
try {
    $main = Join-Path $base 'scan.csv'
    $secondary = [IO.Path]::ChangeExtension($main, '.secundarios.csv')
    $incidents = [IO.Path]::ChangeExtension($main, '.incidencias.csv')
    @(
        (New-ReportSourceRow 'C:\Users\tester\AppData\Local\Golem\golem\default\rinkeby\keys\keystore.json' 'keystore_ethereum_estructura_v3_valida')
        (New-ReportSourceRow 'C:\Users\tester\Documents\secret.txt' 'clave_privada_bitcoin_checksum_valido')
        (New-ReportSourceRow 'C:\Users\tester\Documents\mixed.zip' 'clave_privada_bitcoin_checksum_valido')
    ) | Export-Csv -LiteralPath $main -NoTypeInformation -Encoding UTF8
    @(
        (New-ReportSourceRow 'C:\Program Files\Example\bundle.js' 'candidata_direccion_bitcoin_sin_checksum')
        (New-ReportSourceRow 'C:\Program Files\Example\bundle.js' 'terminos_criptomoneda')
        (New-ReportSourceRow 'C:\Users\tester\Documents\notes.txt' 'direccion_bitcoin_checksum_valido')
        (New-ReportSourceRow 'C:\Users\tester\Documents\public-runtime.cs' 'copia_verificada_del_escaner')
        (New-ReportSourceRow 'C:\Users\tester\Documents\public-runtime.cs' 'clave_privada_bitcoin_checksum_valido')
        (New-ReportSourceRow 'C:\Users\tester\Documents\wallet.dat' 'candidata_wallet_core_berkeley_db')
        (New-ReportSourceRow 'C:\Users\tester\.bitcoin\wallet.dat' 'candidata_wallet_core_berkeley_db')
        (New-ReportSourceRow 'C:\Users\tester\Documents\mixed.zip' 'diccionario_publico_en_comprimido')
    ) | Export-Csv -LiteralPath $secondary -NoTypeInformation -Encoding UTF8
    @(
        (New-ReportSourceRow 'C:\Users\tester\Documents\locked.pdf' 'documento_cifrado_sin_revisar')
    ) | Export-Csv -LiteralPath $incidents -NoTypeInformation -Encoding UTF8

    $result = & (Join-Path $PSScriptRoot '..\New-ScanReviewReports.ps1') -CsvPath $main
    $reviewPath = [IO.Path]::ChangeExtension($main, '.revision.csv')
    $summaryPath = [IO.Path]::ChangeExtension($main, '.secundarios-resumen.csv')
    $review = @(Import-Csv -LiteralPath $reviewPath)
    $summary = @(Import-Csv -LiteralPath $summaryPath)

    Assert-Review ($review.Count -eq 12) ('Review report includes all source rows (actual: ' + $review.Count + ', reported: ' + $result.RevisionRows + ')')
    Assert-Review ((@($review[0].PSObject.Properties.Name) -join ',') -eq 'Ubicacion,Categoria,Tipo,Confianza,Contexto,FechaCreacionUtc,FechaModificacionUtc') 'Review report includes locations, metadata and file timestamps without content'
    Assert-Review (@($review | Where-Object { $_.Tipo -eq 'keystore_ethereum_estructura_v3_valida' -and $_.FechaCreacionUtc -eq '2024-06-07T08:09:10.0000000Z' -and $_.FechaModificacionUtc -eq '2025-01-02T03:04:05.0000000Z' }).Count -eq 1) 'Review report preserves source file timestamps'
    Assert-Review (@($review | Where-Object { $_.Tipo -eq 'keystore_ethereum_estructura_v3_valida' -and $_.Confianza -eq 'Media' -and $_.Contexto -match 'Golem/Rinkeby' -and $_.Contexto -match 'red de pruebas' }).Count -eq 1) 'Golem/Rinkeby test-network data lowers confidence without suppressing the finding'
    $golemContext = [string](@($review | Where-Object { $_.Tipo -eq 'keystore_ethereum_estructura_v3_valida' }).Contexto | Select-Object -First 1)
    Assert-Review ($golemContext.Contains('posible dato de aplicación')) ('Review CSV preserves Spanish text in Windows PowerShell 5.1; context=' + $golemContext)
    Assert-Review (@($review | Where-Object { $_.Tipo -eq 'keystore_ethereum_estructura_v3_valida' -and $_.Contexto -match 'sin descifrar' }).Count -eq 1) 'Keystore context explicitly says it was not decrypted'
    Assert-Review (@($review | Where-Object { $_.Categoria -eq 'incidencias' -and $_.Confianza -eq 'No evaluable' }).Count -eq 1) 'Incidents are marked as unevaluable evidence'
    Assert-Review (@($summary | Where-Object { $_.Ubicacion -eq 'C:\Program Files\Example\bundle.js' -and $_.CantidadIndicadores -eq 2 -and $_.Tipos -match 'terminos_criptomoneda' -and $_.Tipos -match 'candidata_direccion_bitcoin_sin_checksum' }).Count -eq 1) 'Secondary summary groups distinct signals by file'
    Assert-Review ($summary.Count -eq 6) 'Secondary summary has one row per distinct location'
    $priority = @(Import-Csv -LiteralPath $result.PrioritizedCsv)
    Assert-Review (@($review | Where-Object { $_.Ubicacion -eq 'C:\Users\tester\Documents\public-runtime.cs' -and $_.Confianza -ne 'Baja' }).Count -eq 0) 'Every pattern in an exact public runtime copy has low confidence'
    Assert-Review (@($priority | Where-Object { $_.Ubicacion -eq 'C:\Users\tester\Documents\public-runtime.cs' }).Count -eq 0) 'Private-key patterns in public runtime copies cannot enter the priority report'
    Assert-Review (@($review | Where-Object { $_.Ubicacion -eq 'C:\Users\tester\Documents\wallet.dat' -and $_.Confianza -eq 'Baja' -and $_.Contexto -match 'Berkeley DB' }).Count -eq 1) 'A generic Berkeley DB header has low confidence with an explicit qualification'
    Assert-Review (@($priority | Where-Object { $_.Ubicacion -eq 'C:\Users\tester\.bitcoin\wallet.dat' -and $_.Confianza -eq 'Media' }).Count -eq 1) 'A Berkeley DB lead in a wallet software path remains available for priority review'
    Assert-Review (@($priority | Where-Object { $_.Ubicacion -eq 'C:\Users\tester\Documents\mixed.zip' -and $_.Tipo -eq 'clave_privada_bitcoin_checksum_valido' -and $_.Confianza -eq 'Alta' }).Count -eq 1) 'A public dictionary member cannot downgrade private evidence in another ZIP member'
    Assert-Review (@($review | Get-Member -MemberType NoteProperty -Name '*key*').Count -eq 0) 'Review report contains no key-content column'

    $reviewBefore = [IO.File]::ReadAllBytes($reviewPath)
    $summaryBefore = [IO.File]::ReadAllBytes($summaryPath)
    $reviewTime = [IO.File]::GetLastWriteTimeUtc($reviewPath)
    $summaryTime = [IO.File]::GetLastWriteTimeUtc($summaryPath)
    Start-Sleep -Milliseconds 1100
    $repeat = & (Join-Path $PSScriptRoot '..\New-ScanReviewReports.ps1') -CsvPath $main
    Assert-Review (-not $repeat.RevisionChanged -and -not $repeat.SecondarySummaryChanged) 'Unchanged inputs do not rewrite reports'
    Assert-Review ([IO.File]::GetLastWriteTimeUtc($reviewPath) -eq $reviewTime -and [IO.File]::GetLastWriteTimeUtc($summaryPath) -eq $summaryTime) 'Idempotent report timestamps remain unchanged'
    Assert-Review ([Linq.Enumerable]::SequenceEqual([byte[]]$reviewBefore, [byte[]][IO.File]::ReadAllBytes($reviewPath))) 'Review report bytes remain stable'
    Assert-Review ([Linq.Enumerable]::SequenceEqual([byte[]]$summaryBefore, [byte[]][IO.File]::ReadAllBytes($summaryPath))) 'Secondary summary bytes remain stable'

    $unrelatedSource = Join-Path $base 'unrelated-source.txt'
    [IO.File]::WriteAllText($unrelatedSource, 'ordinary source bytes', [Text.UTF8Encoding]::new($false))
    $unrelatedHash = (Get-FileHash -LiteralPath $unrelatedSource).Hash
    $unrelatedTime = [IO.File]::GetLastWriteTimeUtc($unrelatedSource)
    Remove-Item -LiteralPath $result.PrioritizedCsv
    [void](New-Item -ItemType HardLink -Path $result.PrioritizedCsv -Target $unrelatedSource)
    $linkedReport = & (Join-Path $PSScriptRoot '..\New-ScanReviewReports.ps1') -CsvPath $main
    Assert-Review ((Get-FileHash -LiteralPath $unrelatedSource).Hash -eq $unrelatedHash -and [IO.File]::GetLastWriteTimeUtc($unrelatedSource) -eq $unrelatedTime) 'Replacing an existing report hard link cannot modify its source bytes or timestamp'
    Assert-Review ([IO.File]::ReadAllLines($linkedReport.PrioritizedCsv)[0] -eq '"Ubicacion","Categoria","Tipo","Confianza","Contexto","FechaCreacionUtc","FechaModificacionUtc"') 'Replacing a report hard link still generates the expected report'

    Write-Host ('ALL PASSED: ' + $script:Passed + ' comprobaciones.')
}
finally {
    $cleanupPath = [IO.Path]::GetFullPath($base)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $cleanupPath.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($cleanupPath) -notmatch '^wallet-review-report-[0-9a-f]{32}$') { throw 'Unsafe report fixture cleanup path.' }
    if (Test-Path -LiteralPath $cleanupPath) { Remove-Item -LiteralPath $cleanupPath -Recurse -Force }
}
