[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    [ValidateSet('en', 'es')][string]$Language = 'en'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\CsvOutputSafety.ps1')
function Get-ReviewText {
    param([string]$English, [string]$Spanish)
    if ($Language -eq 'es') { return $Spanish }
    return $English
}
$script:HighConfidenceTypes = [Collections.Generic.HashSet[string]]::new([string[]]@(
    'frase_bip39_checksum_valido', 'frase_monero_checksum_valido', 'respaldo_slip39_checksum_valido',
    'clave_privada_bitcoin_checksum_valido', 'clave_privada_extendida_checksum_valido',
    'keystore_ethereum_estructura_v3_valida', 'estructura_wallet_core_validada',
    'estructura_wallet_electrum_validada', 'keypair_solana_par_claves_validado'
), [StringComparer]::OrdinalIgnoreCase)
$script:MediumConfidenceTypes = [Collections.Generic.HashSet[string]]::new([string[]]@(
    'keystore_ethereum_cifrado', 'posible_keypair_solana_json',
    'candidata_clave_hexadecimal_sin_validar'
), [StringComparer]::OrdinalIgnoreCase)
$script:PathContextCache = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:FileDatesByLocation = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)

$mainPath = [IO.Path]::GetFullPath($CsvPath)
if (-not (Test-Path -LiteralPath $mainPath -PathType Leaf)) {
    throw ((Get-ReviewText 'Primary CSV not found: ' 'No se encontró el CSV principal: ') + $mainPath)
}

$sourcePaths = [ordered]@{
    principal = $mainPath
    secundarios = [IO.Path]::ChangeExtension($mainPath, '.secundarios.csv')
    incidencias = [IO.Path]::ChangeExtension($mainPath, '.incidencias.csv')
}

function Read-ScanRows {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Category
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ((Get-ReviewText 'Missing CSV for ' 'Falta el CSV de ') + $Category + ': ' + $Path)
    }

    $reader = [IO.StreamReader]::new($Path, [Text.Encoding]::UTF8, $true)
    try { $header = $reader.ReadLine() } finally { $reader.Dispose() }
    $hasDates = $header -eq '"Ubicacion","Tipo","FechaCreacionUtc","FechaModificacionUtc"'
    if (-not $hasDates -and $header -ne '"Ubicacion","Tipo"') {
        throw ((Get-ReviewText 'Unexpected CSV schema for category: ' 'Esquema de CSV inesperado para la categoría: ') + $Category)
    }

    $rows = @(Import-Csv -LiteralPath $Path)
    $seenLocations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $lastLocation = $null
    foreach ($row in $rows) {
        if (-not $hasDates) {
            # Legacy reports have no historical metadata. Do not invent dates or reread sources.
            $row | Add-Member -NotePropertyName FechaCreacionUtc -NotePropertyValue ''
            $row | Add-Member -NotePropertyName FechaModificacionUtc -NotePropertyValue ''
        }
        if ([string]::IsNullOrWhiteSpace([string]$row.Ubicacion) -or
            [string]::IsNullOrWhiteSpace([string]$row.Tipo)) {
            throw ((Get-ReviewText 'CSV contains an empty location or type in category: ' 'El CSV contiene una ubicación o tipo vacío en la categoría: ') + $Category)
        }
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($lastLocation, [string]$row.Ubicacion)) {
            if (-not $seenLocations.Add([string]$row.Ubicacion)) {
                throw ((Get-ReviewText 'CSV rows for each location must be adjacent. Category: ' 'Las filas del CSV de cada ubicación deben estar juntas. Categoría: ') + $Category)
            }
            $lastLocation = [string]$row.Ubicacion
        }
    }
    return $rows
}

function Get-EvidenceConfidence {
    param([string]$Type, [string]$Category, [string]$PathContext, [bool]$PublicReference = $false)
    if ($Category -eq 'incidencias') { return 'No evaluable' }
    if ($Type -eq 'indicador_criptografico_candidato_por_ocr') { return 'Baja' }
    if ($PublicReference) { return 'Baja' }
    if ($Type -eq 'candidata_wallet_core_berkeley_db') {
        if ($PathContext -eq 'Ruta asociada a software o datos de wallet') { return 'Media' }
        return 'Baja'
    }
    # Application/test-network data and session logs can contain valid examples or quoted text.
    # Keep the evidence visible, but lower confidence because the path is weak ownership context.
    if ($PathContext -in @('Golem/Rinkeby: posible dato de aplicación o red de pruebas', 'Registro local de sesión de usuario')) {
        if ($script:HighConfidenceTypes.Contains($Type)) { return 'Media' }
        if ($script:MediumConfidenceTypes.Contains($Type)) { return 'Baja' }
    }
    # Findings in this scanner's tests and artifacts are fixtures, not user wallet evidence.
    if ($PathContext -eq 'Prueba o artefacto del escáner' -and
        ($script:HighConfidenceTypes.Contains($Type) -or $script:MediumConfidenceTypes.Contains($Type))) { return 'Baja' }
    # A valid mnemonic in a software bundle can be a sample, test vector, or incidental word sequence.
    if ($PathContext -eq 'Software instalado, dependencia o caché' -and
        $Type -in @('frase_bip39_checksum_valido', 'frase_monero_checksum_valido', 'respaldo_slip39_checksum_valido')) { return 'Media' }
    if ($script:HighConfidenceTypes.Contains($Type)) { return 'Alta' }
    if ($script:MediumConfidenceTypes.Contains($Type)) { return 'Media' }
    return 'Baja'
}

function Get-PathContext {
    param([string]$Path)

    if ($Path -match '(?i)[\\/]golem[\\/]golem[\\/]default[\\/]rinkeby(?:[\\/]|$)') {
        return 'Golem/Rinkeby: posible dato de aplicación o red de pruebas'
    }
    if ($Path -match '(?i)[\\/]wallet-artifact-scanner[\\/](?:tests|artifacts)(?:[\\/]|$)') {
        return 'Prueba o artefacto del escáner'
    }
    if ($Path -match '(?i)[\\/]\.codex[\\/]sessions(?:[\\/]|$)') {
        return 'Registro local de sesión de usuario'
    }
    if ($Path -match '(?i)[\\/](?:Program Files(?: \(x86\))?|WindowsApps|node_modules|site-packages|vendor|\.git)(?:[\\/]|$)|[\\/]AppData[\\/]Local[\\/]Programs(?:[\\/]|$)|[\\/](?:Extensions|Cache|Cache_Data|Code Cache|GPUCache|component_crx_cache|BrowserMetrics)(?:[\\/]|$)|[\\/]\.codex[\\/](?:plugins|\.tmp)(?:[\\/]|$)') {
        return 'Software instalado, dependencia o caché'
    }
    if ($Path -match '(?i)(?:^|[\\/])(?:wallets?|\.?bitcoin|\.?litecoin|\.?dogecoin|dashcore|\.?monero|\.?ethereum|\.?electrum|armory|multibit(?:\s*hd)?|sparrow|wasabi|exodus|atomicwallet|coinbase(?: wallet)?|trust wallet|coinomi|guarda|mycelium|ledger(?: live)?|trezor|phantom|metamask|solflare|rabby|keplr|imtoken|jaxx)(?:[\\/]|$)') {
        return 'Ruta asociada a software o datos de wallet'
    }
    return 'Sin contexto conocido por la ruta'
}

function Get-FindingContext {
    param(
        [string]$PathContext,
        [string]$Type,
        [string]$Category,
        [bool]$PublicReference = $false,
        [bool]$HasValidatedBitcoinPrivateKey = $false
    )

    if ($Category -eq 'incidencias') {
        return 'Cobertura incompleta: el tipo de incidencia indica que el contenido no quedó confirmado.'
    }

    if ($PublicReference -and $Type -match '^(?:frase_bip39_|frase_monero_|respaldo_slip39|candidata_(?:bip39|monero|slip39)(?:_|$))') {
        return ($PathContext + '; coincidencia de palabras dentro de un recurso público del detector; no se interpreta como frase de recuperación.')
    }
    if ($PublicReference) {
        return ($PathContext + '; recurso público reconocido por igualdad completa de bytes; sus patrones de claves o wallets no se priorizan como evidencia personal.')
    }
    if ($Type -eq 'candidata_wallet_core_berkeley_db') {
        return ($PathContext + '; cabecera Berkeley DB reconocida. Este formato también se usa en otras bases de datos; no confirma una estructura de wallet Bitcoin.')
    }
    if ($PathContext -eq 'Prueba o artefacto del escáner' -and $script:HighConfidenceTypes.Contains($Type)) {
        return ($PathContext + '; fixture de prueba: el checksum confirma el formato, pero no evidencia una wallet personal.')
    }
    if ($PathContext -eq 'Software instalado, dependencia o caché' -and
        $Type -in @('frase_bip39_checksum_valido', 'frase_monero_checksum_valido', 'respaldo_slip39_checksum_valido')) {
        return ($PathContext + '; frase con checksum válido dentro de software; puede ser ejemplo o dato incidental, no confirma una wallet personal.')
    }
    if ($Type -eq 'candidata_formato_clave_privada_bitcoin') {
        $wifContext = if ($HasValidatedBitcoinPrivateKey) {
            'Patrón compatible con WIF; el mismo archivo también contiene al menos una clave Bitcoin validada por checksum.'
        } else {
            'Patrón compatible con WIF, pero sin resultado de checksum validado en este archivo; no se considera una clave confirmada.'
        }
        return ($PathContext + '; ' + $wifContext)
    }
    if ($Type -eq 'indicador_criptografico_candidato_por_ocr') {
        return ($PathContext + '; el texto impreso se reconoció por OCR. Puede haber confusión de caracteres; revisar el PDF original. El texto reconocido no se guarda en el reporte.')
    }

    $pathQualification = if ($PathContext -eq 'Golem/Rinkeby: posible dato de aplicación o red de pruebas') {
        'La ruta se asocia con datos de aplicación o una red de pruebas; puede contener ejemplos y no confirma una wallet personal.'
    } elseif ($PathContext -eq 'Registro local de sesión de usuario') {
        'Un registro de sesión puede incluir texto citado o de ejemplo; revisar el archivo original antes de tratarlo como evidencia de una wallet.'
    } else {
        $null
    }
    $typeContext = if ($Type -eq 'keystore_ethereum_estructura_v3_valida') {
        'Estructura Ethereum V3 reconocida, sin descifrar ni comprobar contraseña.'
    } elseif ($Type -match '^(?:clave_privada_|frase_|respaldo_slip39|keypair_solana_par_claves|estructura_wallet_)') {
        'Formato o checksum validado; no confirma titularidad, acceso ni saldo.'
    } elseif ($Type -match '^direccion_') {
        'Es un identificador público; no confirma control de una wallet.'
    } elseif ($Type -match '^(?:terminos_|candidata_|ruta_|archivo_relacionado|almacenamiento_|nombre_wallet_)') {
        'Mención, nombre o candidato parcial; requiere revisión de contexto.'
    } else {
        'La confianza describe el patrón detectado, no titularidad ni saldo.'
    }
    if ($pathQualification) { return ($PathContext + '; ' + $pathQualification + ' ' + $typeContext) }
    return ($pathContext + '; ' + $typeContext)
}

function Get-CoverageClassification {
    param([string]$Type)

    switch ($Type) {
        { $_ -in @('error_lectura_archivo', 'error_acceso_directorio', 'error_revision_elemento', 'error_lectura_contenido_comprimido') } {
            return [pscustomobject]@{
                Clase = 'Reintentable tras resolver la causa'
                Interpretacion = 'Falló el acceso o la lectura; el resultado no equivale a contenido limpio.'
                SiguientePaso = 'Revisar permisos, conexión, bloqueo o disponibilidad del archivo; repetir cuando se resuelva.'
            }
        }
        { $_ -in @('error_lectura_documento', 'error_analisis_archivo', 'error_ocr_pdf') } {
            return [pscustomobject]@{
                Clase = 'Error de extracción o análisis'
                Interpretacion = 'El lector no pudo procesar el formato o el contenido; no confirma ausencia de indicios.'
                SiguientePaso = 'Revisar si el archivo está dañado o si falló una herramienta OCR local; corregir la causa y reintentar.'
            }
        }
        { $_ -in @('archivo_supera_limite', 'documento_supera_limite', 'documento_supera_limite_recursos', 'limite_paginas_ocr_pdf', 'comprimido_supera_limite_expansion', 'comprimido_supera_limite_entradas', 'comprimido_supera_limite_anidacion') } {
            return [pscustomobject]@{
                Clase = 'Límite de tamaño o recursos'
                Interpretacion = 'La lectura se detuvo por un límite operativo; el contenido quedó incompleto.'
                SiguientePaso = 'Revisar el límite indicado; aumentarlo solo si hay memoria, espacio y tiempo suficientes.'
            }
        }
        'documento_cifrado_sin_revisar' {
            return [pscustomobject]@{
                Clase = 'Contenido no extraíble automáticamente'
                Interpretacion = 'El documento está cifrado y el escáner no lo descifró.'
                SiguientePaso = 'Si es necesario, desbloquearlo por un procedimiento autorizado y analizar una copia accesible.'
            }
        }
        'documento_sin_texto_extraible' {
            return [pscustomobject]@{
                Clase = 'Contenido no extraíble automáticamente'
                Interpretacion = 'No se obtuvo texto; puede ser una imagen escaneada, contenido vacío o un formato no compatible.'
                SiguientePaso = 'Si contiene texto impreso en una imagen, volver a analizar con -PdfOcr y las herramientas locales configuradas; no se revisa escritura a mano.'
            }
        }
        default {
            return [pscustomobject]@{
                Clase = 'Incidencia sin clasificar'
                Interpretacion = 'Esta etiqueta todavía no tiene una regla de cobertura en el generador de reportes.'
                SiguientePaso = 'Revisar la etiqueta en el CSV de incidencias antes de interpretar la cobertura.'
            }
        }
    }
}

function Assert-ReportOutputPath {
    param([string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if (((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw (Get-ReviewText 'The report output passes through a link or junction.' 'La salida del reporte pasa por un enlace o junction.')
            }
        }
        $parent = [IO.Directory]::GetParent($current)
        $current = if ($null -eq $parent) { $null } else { $parent.FullName }
    }
}

function Write-CsvIfChanged {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Columns
    )

    $selected = @(Protect-SpreadsheetCsvRows -Rows $Rows -Columns $Columns)
    if ($selected.Count -gt 0) {
        $lines = @($selected | ConvertTo-Csv -NoTypeInformation)
    } else {
        $emptyRow = [ordered]@{}
        foreach ($column in $Columns) { $emptyRow[$column] = '' }
        $lines = @(([pscustomobject]$emptyRow | ConvertTo-Csv -NoTypeInformation)[0])
    }
    $content = [string]::Join([Environment]::NewLine, [string[]]$lines) + [Environment]::NewLine
    $encoding = [Text.UTF8Encoding]::new($true)
    Assert-ReportOutputPath $Path

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        if ([IO.File]::ReadAllText($Path, $encoding) -ceq $content) { return $false }
    }
    # Replace the directory entry, so a pre-existing hard link cannot write into another source file.
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, $content, $encoding)
        Assert-ReportOutputPath $Path
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $backup = $Path + '.' + [guid]::NewGuid().ToString('N') + '.backup.tmp'
            [IO.File]::Move($Path, $backup)
            try { [IO.File]::Move($temporary, $Path) }
            catch {
                if (-not [IO.File]::Exists($Path)) { [IO.File]::Move($backup, $Path) }
                throw
            }
            [IO.File]::Delete($backup)
        }
        else { [IO.File]::Move($temporary, $Path) }
    }
    finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    return $true
}

$rowsByCategory = [ordered]@{}
foreach ($category in $sourcePaths.Keys) {
    $rowsByCategory[$category] = @(Read-ScanRows -Path $sourcePaths[$category] -Category $category)
}

$publicReferenceLocations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($row in $rowsByCategory.secundarios) {
    if ([string]$row.Tipo -in @('diccionario_publico_del_detector', 'copia_verificada_del_escaner')) {
        [void]$publicReferenceLocations.Add([string]$row.Ubicacion)
    }
}
$validatedBitcoinPrivateKeyLocations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($category in @('principal', 'secundarios')) {
    foreach ($row in $rowsByCategory[$category]) {
        if ([string]$row.Tipo -eq 'clave_privada_bitcoin_checksum_valido') {
            [void]$validatedBitcoinPrivateKeyLocations.Add([string]$row.Ubicacion)
        }
    }
}

$reviewRows = [Collections.Generic.List[object]]::new()
foreach ($category in $sourcePaths.Keys) {
    foreach ($row in $rowsByCategory[$category]) {
        $path = [string]$row.Ubicacion
        if (-not $script:FileDatesByLocation.ContainsKey($path)) {
            $script:FileDatesByLocation[$path] = $row
        }
        if (-not $script:PathContextCache.ContainsKey($path)) {
            $script:PathContextCache[$path] = Get-PathContext $path
        }
        $isPublicReference = $publicReferenceLocations.Contains($path)
        $pathContext = if ($isPublicReference) { 'Diccionario o copia pública del detector' } else { $script:PathContextCache[$path] }
        $hasValidatedBitcoinPrivateKey = $validatedBitcoinPrivateKeyLocations.Contains($path)
        $reviewRows.Add([pscustomobject]@{
            Ubicacion = $path
            Categoria = $category
            Tipo = $row.Tipo
            FechaCreacionUtc = $row.FechaCreacionUtc
            FechaModificacionUtc = $row.FechaModificacionUtc
            Confianza = (Get-EvidenceConfidence -Type $row.Tipo -Category $category -PathContext $pathContext -PublicReference $isPublicReference)
            Contexto = (Get-FindingContext -PathContext $pathContext -Type $row.Tipo -Category $category -PublicReference $isPublicReference -HasValidatedBitcoinPrivateKey $hasValidatedBitcoinPrivateKey)
        })
    }
}

$priorityRows = @($reviewRows | Where-Object { $_.Categoria -in @('principal', 'secundarios') -and $_.Confianza -in @('Alta', 'Media') })

$secondarySummary = [Collections.Generic.List[object]]::new()
function Add-SecondarySummaryRow {
    param([string]$Path, [int]$Count, [int]$MaxRank, [Collections.Generic.List[string]]$Types)
    $maxConfidence = switch ($MaxRank) { 3 { 'Alta' }; 2 { 'Media' }; default { 'Baja' } }
    if (-not $script:PathContextCache.ContainsKey($path)) { $script:PathContextCache[$path] = Get-PathContext $path }
    $pathContext = if ($publicReferenceLocations.Contains($path)) { 'Diccionario o copia pública del detector' } else { $script:PathContextCache[$path] }
    $secondarySummary.Add([pscustomobject]@{
        Ubicacion = $path
        FechaCreacionUtc = $script:FileDatesByLocation[$path].FechaCreacionUtc
        FechaModificacionUtc = $script:FileDatesByLocation[$path].FechaModificacionUtc
        CantidadIndicadores = $Count
        ConfianzaMaxima = $maxConfidence
        Contexto = $pathContext
        Tipos = [string]::Join('; ', $Types.ToArray())
    })
}

$currentPath = $null
$currentCount = 0
$currentMaxRank = 0
$currentTypes = [Collections.Generic.List[string]]::new()
$currentTypeSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($row in $rowsByCategory.secundarios) {
    $path = [string]$row.Ubicacion
    if ($null -ne $currentPath -and -not [StringComparer]::OrdinalIgnoreCase.Equals($currentPath, $path)) {
        Add-SecondarySummaryRow -Path $currentPath -Count $currentCount -MaxRank $currentMaxRank -Types $currentTypes
        $currentCount = 0
        $currentMaxRank = 0
        $currentTypes = [Collections.Generic.List[string]]::new()
        $currentTypeSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    $currentPath = $path
    $currentCount++
    if ($currentTypeSet.Add([string]$row.Tipo)) { $currentTypes.Add([string]$row.Tipo) }
    $rowPathContext = if ($publicReferenceLocations.Contains($path)) { 'Diccionario o copia pública del detector' } else { $script:PathContextCache[$path] }
    $rank = switch (Get-EvidenceConfidence -Type $row.Tipo -Category 'secundarios' -PathContext $rowPathContext -PublicReference ($publicReferenceLocations.Contains($path))) {
        'Alta' { 3 }
        'Media' { 2 }
        'Baja' { 1 }
        default { 0 }
    }
    if ($rank -gt $currentMaxRank) { $currentMaxRank = $rank }
}
if ($null -ne $currentPath) {
    Add-SecondarySummaryRow -Path $currentPath -Count $currentCount -MaxRank $currentMaxRank -Types $currentTypes
}

$indicatorStats = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
foreach ($row in $reviewRows) {
    if ($row.Categoria -ne 'secundarios') { continue }
    $pathContext = ([string]$row.Contexto).Split(';')[0].Trim()
    $key = [string]::Join("`t", @([string]$row.Confianza, $pathContext, [string]$row.Tipo))
    if (-not $indicatorStats.ContainsKey($key)) {
        $indicatorStats.Add($key, [pscustomobject]@{
            Confidence = [string]$row.Confianza
            PathContext = $pathContext
            Type = [string]$row.Tipo
            Locations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        })
    }
    [void]$indicatorStats[$key].Locations.Add([string]$row.Ubicacion)
}
$secondaryIndicatorSummary = [Collections.Generic.List[object]]::new()
$indicatorKeys = [string[]]@($indicatorStats.Keys)
[Array]::Sort($indicatorKeys, [StringComparer]::Ordinal)
foreach ($key in $indicatorKeys) {
    $stats = $indicatorStats[$key]
    $secondaryIndicatorSummary.Add([pscustomobject]@{
        Confianza = $stats.Confidence
        ContextoRuta = $stats.PathContext
        Tipo = $stats.Type
        CantidadUbicaciones = $stats.Locations.Count
    })
}

$coverageSummary = [Collections.Generic.List[object]]::new()
$incidentStats = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
$uniqueIncidentLocations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($row in $rowsByCategory.incidencias) {
    $type = [string]$row.Tipo
    if (-not $incidentStats.ContainsKey($type)) {
        $incidentStats.Add($type, [pscustomobject]@{
            Incidencias = [long]0
            Ubicaciones = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        })
    }
    $incidentStats[$type].Incidencias++
    [void]$incidentStats[$type].Ubicaciones.Add([string]$row.Ubicacion)
    [void]$uniqueIncidentLocations.Add([string]$row.Ubicacion)
}

$coverageSummary.Add([pscustomobject]@{
    TipoIncidencia = 'TOTAL'
    ClaseCobertura = 'Resumen'
    CantidadIncidencias = $rowsByCategory.incidencias.Count
    UbicacionesUnicas = $uniqueIncidentLocations.Count
    Interpretacion = 'Las ubicaciones únicas cuentan rutas distintas; los conteos por tipo pueden solaparse.'
    SiguientePaso = 'Consulta el CSV de incidencias para las ubicaciones y etiquetas individuales.'
})
foreach ($type in ($incidentStats.Keys | Sort-Object)) {
    $classification = Get-CoverageClassification -Type $type
    $stats = $incidentStats[$type]
    $coverageSummary.Add([pscustomobject]@{
        TipoIncidencia = $type
        ClaseCobertura = $classification.Clase
        CantidadIncidencias = $stats.Incidencias
        UbicacionesUnicas = $stats.Ubicaciones.Count
        Interpretacion = $classification.Interpretacion
        SiguientePaso = $classification.SiguientePaso
    })
}

$reviewPath = [IO.Path]::ChangeExtension($mainPath, '.revision.csv')
$priorityPath = [IO.Path]::ChangeExtension($mainPath, '.prioritarios.csv')
$secondarySummaryPath = [IO.Path]::ChangeExtension($mainPath, '.secundarios-resumen.csv')
$secondaryIndicatorSummaryPath = [IO.Path]::ChangeExtension($mainPath, '.secundarios-indicadores-resumen.csv')
$coverageSummaryPath = [IO.Path]::ChangeExtension($mainPath, '.cobertura-resumen.csv')
$reviewWritten = Write-CsvIfChanged -Path $reviewPath -Rows $reviewRows.ToArray() -Columns @('Ubicacion', 'Categoria', 'Tipo', 'Confianza', 'Contexto', 'FechaCreacionUtc', 'FechaModificacionUtc')
$priorityWritten = Write-CsvIfChanged -Path $priorityPath -Rows $priorityRows -Columns @('Ubicacion', 'Categoria', 'Tipo', 'Confianza', 'Contexto', 'FechaCreacionUtc', 'FechaModificacionUtc')
$summaryWritten = Write-CsvIfChanged -Path $secondarySummaryPath -Rows $secondarySummary.ToArray() -Columns @('Ubicacion', 'CantidadIndicadores', 'ConfianzaMaxima', 'Contexto', 'Tipos', 'FechaCreacionUtc', 'FechaModificacionUtc')
$indicatorSummaryWritten = Write-CsvIfChanged -Path $secondaryIndicatorSummaryPath -Rows $secondaryIndicatorSummary.ToArray() -Columns @('Confianza', 'ContextoRuta', 'Tipo', 'CantidadUbicaciones')
$coverageWritten = Write-CsvIfChanged -Path $coverageSummaryPath -Rows $coverageSummary.ToArray() -Columns @('TipoIncidencia', 'ClaseCobertura', 'CantidadIncidencias', 'UbicacionesUnicas', 'Interpretacion', 'SiguientePaso')

Write-Host ((Get-ReviewText 'High or medium confidence findings to review first: ' 'Hallazgos de confianza alta o media para revisar primero: ') + $priorityPath)
Write-Host ((Get-ReviewText 'Secondary summary by confidence, context and type: ' 'Resumen secundario por confianza, contexto y tipo: ') + $secondaryIndicatorSummaryPath)

[pscustomobject]@{
    RevisionCsv = $reviewPath
    PrioritizedCsv = $priorityPath
    SecondarySummaryCsv = $secondarySummaryPath
    SecondaryIndicatorSummaryCsv = $secondaryIndicatorSummaryPath
    CoverageSummaryCsv = $coverageSummaryPath
    RevisionRows = $reviewRows.Count
    PriorityRows = $priorityRows.Count
    SecondaryFiles = $secondarySummary.Count
    SecondaryIndicatorSummaryRows = $secondaryIndicatorSummary.Count
    CoverageSummaryRows = $coverageSummary.Count
    CoverageIncidents = $rowsByCategory.incidencias.Count
    CoverageUniqueLocations = $uniqueIncidentLocations.Count
    RevisionChanged = $reviewWritten
    PriorityChanged = $priorityWritten
    SecondarySummaryChanged = $summaryWritten
    SecondaryIndicatorSummaryChanged = $indicatorSummaryWritten
    CoverageSummaryChanged = $coverageWritten
}
