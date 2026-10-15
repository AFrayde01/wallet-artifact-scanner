[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'File')][string]$CsvPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Folder')][string]$ReportDirectory,
    [string]$OutputPath,
    [ValidateSet('en', 'es')][string]$Language = 'en',
    [ValidateSet('Bip39', 'AllReported')][string]$VerificationScope = 'Bip39',
    [switch]$ReportOnly,
    [ValidateRange(1, 1024)][int]$MaxContentMB = 256,
    [ValidateRange(1, 256)][int]$MaxDocumentMB = 32,
    [ValidateRange(1, 2048)][int]$MaxExpandedMB = 256,
    [ValidateRange(1, 100)][int]$CpuCorePercent = 50
)

# Reads CSVs, deduplicates locations, then rechecks only the reported local files.
# Never exports matched content or decrypts wallets. -ReportOnly skips source rechecks.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\CsvOutputSafety.ps1')
function Get-FilterText {
    param([string]$English, [string]$Spanish)
    if ($Language -eq 'es') { return $Spanish }
    return $English
}
function Get-OptionalField {
    param([object]$Row, [string]$Name)
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property) { return '' }
    return [string]$property.Value
}
function Assert-SafeOutput {
    param([string]$Path)
    $current = $Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw (Get-FilterText 'Output paths cannot pass through links or junctions.' 'La salida no puede pasar por enlaces o junctions.')
            }
        }
        $parent = [IO.Directory]::GetParent($current)
        $current = if ($null -eq $parent) { $null } else { $parent.FullName }
    }
}

function Get-LocationKey {
    param([string]$Path)
    try {
        if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    } catch { }
    return $Path
}

function Initialize-Verification {
    $assemblyPath = Join-Path $PSScriptRoot 'CryptoMnemonicScanner-10.12.dll'
    $assembly = [Reflection.Assembly]::LoadFile([IO.Path]::GetFullPath($assemblyPath))
    if ([CryptoFileScanner].Assembly.ManifestModule.ModuleVersionId -ne $assembly.ManifestModule.ModuleVersionId) {
        throw (Get-FilterText 'Open a fresh PowerShell session to use the current detector.' 'Abre otra sesión de PowerShell para usar el detector actual.')
    }
    $lists = @{}
    $wordListRoot = Join-Path $PSScriptRoot 'resources\wordlists'
    foreach ($name in @('bip39-english.txt', 'bip39-spanish.txt', 'monero-english.txt', 'monero-english-old.txt', 'monero-spanish.txt', 'slip39-english.txt')) {
        $lists[$name] = [IO.File]::ReadAllLines((Join-Path $wordListRoot $name), [Text.Encoding]::UTF8)
    }
    [CryptoMnemonicScanner]::Configure($lists['bip39-english.txt'], $lists['bip39-spanish.txt'], $lists['monero-english.txt'], $lists['monero-english-old.txt'], $lists['monero-spanish.txt'], $lists['slip39-english.txt'])
    [CryptoFileScanner]::Configure([string[]]@(), [string[]]@())
    [CryptoMnemonicScanner]::Bip39Only = $true
    [CryptoFileScanner]::Bip39Only = $true
    $dictionaryHashes = @($lists.Keys | ForEach-Object { (Get-FileHash -LiteralPath (Join-Path $wordListRoot $_) -Algorithm SHA256).Hash })
    [CryptoFileScanner]::ConfigurePublicDictionaries([string[]]$dictionaryHashes)
    # OCR is intentionally disabled. Extract existing PDF text and supported ZIP/Office content.
    [CryptoDocumentScanner]::Configure((Join-Path $PSScriptRoot 'scripts\Read-PdfWorker.ps1'), ([long]$MaxDocumentMB * 1MB), ([long]$MaxExpandedMB * 1MB))
}

function Read-ReportedCandidate {
    param([string]$Path)
    $result = [pscustomobject]@{ State = 'unreadable'; Evidence = [string[]]@(); Created = ''; Modified = ''; BytesRead = [long]0 }
    # CSV paths are data, never commands. Do not follow UNC/network paths or redacted names.
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '\[(?:REDACTADO|RUTA SENSIBLE REDACTADA)\]') {
        $result.State = 'unresolvable_report_path'; return $result
    }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $result.State = 'missing_or_unavailable'; return $result }
        $sourceItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        # Reparse ancestors are skipped to avoid reading a different physical location.
        $ancestor = $sourceItem
        while ($null -ne $ancestor) {
            if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $result.State = 'reparse_path_skipped'; return $result }
            $parent = [IO.Directory]::GetParent($ancestor.FullName)
            $ancestor = if ($null -eq $parent) { $null } else { Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop }
        }
        $result.Created = $sourceItem.CreationTimeUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $result.Modified = $sourceItem.LastWriteTimeUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        $read = [CryptoFileScanner]::ReadFile($Path, $true, $false, $false, ([long]$MaxContentMB * 1MB), $false, $null)
        $readIncomplete = $read.Incomplete -or $sourceItem.Length -gt ([long]$MaxContentMB * 1MB)
        $result.Evidence = [string[]]$read.Evidence
        $result.BytesRead = $read.BytesRead
        $after = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($sourceItem.Length -ne $after.Length -or $sourceItem.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) {
            $result.State = 'changed_during_read'; return $result
        }
        if ($result.Evidence -contains 'public_mnemonic_dictionary' -or $result.Evidence -contains 'scanner_runtime_copy') {
            $result.State = 'public_reference'
        } elseif ($result.Evidence -contains 'possible_bip39_mnemonic_phrase') {
            $result.State = if ($readIncomplete) { 'bip39_detected_incomplete_read' } else { 'bip39_detected' }
        } elseif ($result.Evidence -contains 'mnemonic_bip39_public_example_candidate') {
            $result.State = if ($readIncomplete) { 'public_example_detected_incomplete_read' } else { 'public_example_detected' }
        } elseif (@($result.Evidence | Where-Object { $_ -like 'mnemonic_bip39_*_candidate' }).Count -gt 0) {
            $result.State = if ($readIncomplete) { 'weak_bip39_candidate_incomplete_read' } else { 'weak_bip39_candidate' }
        } elseif ($readIncomplete) {
            $result.State = 'incomplete_read'
        } elseif ([IO.Path]::GetExtension($Path).ToLowerInvariant() -in @('.rar', '.7z', '.doc', '.xls', '.ppt', '.odt', '.ods', '.odp', '.docm', '.xlsm', '.pptm')) {
            $result.State = 'unsupported_container_or_document'
        } else { $result.State = 'no_complete_bip39_detected' }
    } catch [Management.Automation.PipelineStoppedException] { throw }
    catch { $result.State = 'read_error' }
    return $result
}

$sources = @()
if ($PSCmdlet.ParameterSetName -eq 'Folder') {
    $folder = [IO.Path]::GetFullPath($ReportDirectory)
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
        throw (Get-FilterText 'The reports folder does not exist.' 'La carpeta de reportes no existe.')
    }
    $sources = @(Get-ChildItem -LiteralPath $folder -File -Filter '*.csv' | Sort-Object Name | Select-Object -ExpandProperty FullName)
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $folder 'recuperacion-bip39-unicos.csv' }
} else {
    $source = [IO.Path]::GetFullPath($CsvPath)
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw (Get-FilterText 'The source CSV does not exist.' 'El CSV de origen no existe.')
    }
    $sources = @($source)
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $sourceName = [IO.Path]::GetFileNameWithoutExtension($source) -replace '\.(revision|prioritarios|secundarios)$', ''
        $OutputPath = Join-Path ([IO.Path]::GetDirectoryName($source)) ($sourceName + '.recuperacion-bip39.csv')
    }
}

$destination = [IO.Path]::GetFullPath($OutputPath)
if ($PSCmdlet.ParameterSetName -eq 'File' -and [StringComparer]::OrdinalIgnoreCase.Equals($sources[0], $destination)) {
    throw (Get-FilterText 'The output must be different from the source CSV.' 'La salida debe ser distinta del CSV de origen.')
}
if ([IO.Path]::GetExtension($destination) -ine '.csv' -or
    -not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($destination)) -PathType Container) -or
    (Test-Path -LiteralPath $destination -PathType Container)) {
    throw (Get-FilterText 'Choose a .csv output in an existing folder.' 'Elige una salida .csv en una carpeta existente.')
}
Assert-SafeOutput $destination
$verificationPath = [IO.Path]::ChangeExtension($destination, '.verificacion.csv')
$verificationPartialPath = [IO.Path]::ChangeExtension($destination, '.verificacion.partial.csv')
if (-not $ReportOnly) { Assert-SafeOutput $verificationPath }
if (-not $ReportOnly) { Assert-SafeOutput $verificationPartialPath }
if ($PSCmdlet.ParameterSetName -eq 'File' -and -not $ReportOnly -and
    ([StringComparer]::OrdinalIgnoreCase.Equals($sources[0], $verificationPath) -or [StringComparer]::OrdinalIgnoreCase.Equals($sources[0], $verificationPartialPath))) {
    throw (Get-FilterText 'Verification output must not replace the source CSV.' 'La salida de verificacion no debe reemplazar el CSV de origen.')
}

$publicLocations = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$byLocation = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
$filesInspected = 0
$filesWithLocations = 0
$aggregateFiles = 0
$candidateOccurrences = 0
foreach ($source in $sources) {
    # Do not ingest this run's output: keeps repeated folder filtering stable.
    if ([StringComparer]::OrdinalIgnoreCase.Equals($source, $destination) -or
        [StringComparer]::OrdinalIgnoreCase.Equals($source, $verificationPath) -or
        [StringComparer]::OrdinalIgnoreCase.Equals($source, $verificationPartialPath)) { continue }
    $filesInspected++
    Write-Host ((Get-FilterText 'Consolidating CSV: {0}' 'Consolidando CSV: {0}') -f [IO.Path]::GetFileName($source))
    $reader = [IO.StreamReader]::new($source, [Text.Encoding]::UTF8, $true)
    try { $header = $reader.ReadLine() } finally { $reader.Dispose() }
    if ([string]::IsNullOrWhiteSpace($header)) {
        throw ((Get-FilterText 'CSV has no header: ' 'CSV sin cabecera: ') + [IO.Path]::GetFileName($source))
    }
    $headerRow = @($header, '"schema"') | ConvertFrom-Csv | Select-Object -First 1
    $typeColumn = $null
    if ($null -ne $headerRow) {
        foreach ($column in @('Tipo', 'Indicadores', 'Tipos')) {
            if ($null -ne $headerRow.PSObject.Properties[$column]) { $typeColumn = $column; break }
        }
    }
    if ($null -eq $headerRow -or $null -eq $headerRow.PSObject.Properties['Ubicacion'] -or $null -eq $typeColumn) {
        $aggregateFiles++
        Write-Host ((Get-FilterText 'No individual locations to filter: {0}' 'Sin ubicaciones individuales para filtrar: {0}') -f [IO.Path]::GetFileName($source))
        continue
    }
    $filesWithLocations++
    Import-Csv -LiteralPath $source | ForEach-Object {
        $row = $_
        $location = Get-OptionalField $row 'Ubicacion'
        $key = Get-LocationKey $location
        $types = @((Get-OptionalField $row $typeColumn) -split '[;|]' | ForEach-Object { $_.Trim() })
        $context = Get-OptionalField $row 'Contexto'
        if (@($types | Where-Object { $_ -in @('diccionario_publico_del_detector', 'diccionario_publico_en_comprimido', 'copia_verificada_del_escaner') }).Count -gt 0 -or
            $context -match '(?:^|\s\|\s)(Diccionario o copia pública del detector|Prueba o artefacto del escáner)(;|$)') {
            if (-not [string]::IsNullOrWhiteSpace($key)) { [void]$publicLocations.Add($key) }
        }
        $eligible = if ($ReportOnly) { $types -contains 'frase_bip39_checksum_valido' }
            elseif ($VerificationScope -eq 'AllReported') { $true }
            else { @($types | Where-Object { $_ -match 'bip39' }).Count -gt 0 }
        if ($eligible -and -not [string]::IsNullOrWhiteSpace($location)) {
            if ([string]::IsNullOrWhiteSpace($location)) { throw (Get-FilterText 'A candidate has an empty location.' 'Un candidato tiene una ubicación vacía.') }
            $candidateOccurrences++
            if (-not $byLocation.ContainsKey($key)) {
                $byLocation[$key] = [pscustomobject]@{
                    Ubicacion = $location
                    Contexts = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
                    Confidence = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
                    Reports = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
                    Created = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
                    Modified = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
                    Types = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
                }
            }
            $item = $byLocation[$key]
            foreach ($type in $types) { if ($type) { [void]$item.Types.Add($type) } }
            if ($context) { [void]$item.Contexts.Add($context) }
            $confidence = Get-OptionalField $row 'Confianza'
            if (-not $confidence) { $confidence = Get-OptionalField $row 'ConfianzaDetector' }
            if ($confidence) { [void]$item.Confidence.Add($confidence) }
            [void]$item.Reports.Add([IO.Path]::GetFileName($source))
            foreach ($dateField in @('FechaCreacionUtc', 'FechaModificacionUtc')) {
                $value = Get-OptionalField $row $dateField
                if ($value) {
                    if ($dateField -eq 'FechaCreacionUtc') { [void]$item.Created.Add($value) }
                    else { [void]$item.Modified.Add($value) }
                }
            }
        }
    }
}
$candidates = [Collections.Generic.List[object]]::new()
$verificationRows = [Collections.Generic.List[object]]::new()
$cpuBudget = $null
$processed = 0
$verificationInitialized = $false
$auditWriter = $null
$lastProgressMilliseconds = [long]-1000
$verificationTimer = [Diagnostics.Stopwatch]::StartNew()
Write-Host ((Get-FilterText 'Consolidation complete: {0} CSVs inspected; source reading starts only after this phase.' 'Consolidacion terminada: {0} CSV revisados; la lectura de fuentes empieza solo despues de esta fase.') -f $filesInspected)
Write-Host ((Get-FilterText 'Unique reported locations selected: {0}; scope: {1}.' 'Ubicaciones reportadas unicas seleccionadas: {0}; alcance: {1}.') -f $byLocation.Count, $VerificationScope)
try {
if (-not $ReportOnly) {
    Initialize-Verification
    $verificationInitialized = $true
    $cpuBudget = [CryptoCpuBudget]::new($CpuCorePercent)
    # Replace any old partial entry before appending, including empty hard links.
    # Keep one writer open so checkpoints do not serialize the entire audit repeatedly.
    $partialTemporary = $verificationPartialPath + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($partialTemporary, '"Ubicacion","EstadoVerificacion","VersionDetector","IndicadoresReportados","IndicadoresActuales","BytesLeidos","FechaCreacionUtc","FechaModificacionUtc"' + [Environment]::NewLine, [Text.UTF8Encoding]::new($true))
        Assert-SafeOutput $verificationPartialPath
        [void][CryptoFileScanner]::CommitOutput($partialTemporary, $verificationPartialPath, $true)
    } finally { if ([IO.File]::Exists($partialTemporary)) { [IO.File]::Delete($partialTemporary) } }
    $auditWriter = [IO.StreamWriter]::new($verificationPartialPath, $true, [Text.UTF8Encoding]::new($false))
}
foreach ($key in @($byLocation.Keys | Sort-Object)) {
    $processed++
    if ($ReportOnly -and $publicLocations.Contains($key)) { continue }
    $row = $byLocation[$key]
    if (-not $ReportOnly) {
        if ($verificationTimer.ElapsedMilliseconds - $lastProgressMilliseconds -ge 250) {
            Write-Progress -Activity (Get-FilterText 'Rechecking reported files' 'Releyendo archivos reportados') -Status ('{0}/{1}' -f $processed, $byLocation.Count) -PercentComplete ([int](100.0 * $processed / [Math]::Max(1, $byLocation.Count)))
            $lastProgressMilliseconds = $verificationTimer.ElapsedMilliseconds
        }
        $verification = Read-ReportedCandidate $key
        if ($publicLocations.Contains($key) -and $verification.State -in @('bip39_detected', 'bip39_detected_incomplete_read')) {
            # Preserve the current detection in the audit; historical public context is
            # a reason to review separately, not proof that the file never had a wallet.
            $verification.State = if ($verification.State -eq 'bip39_detected_incomplete_read') { 'bip39_in_public_context_incomplete_read' } else { 'bip39_in_public_context' }
        }
        $auditRow = [pscustomobject][ordered]@{
            Ubicacion = $row.Ubicacion
            EstadoVerificacion = $verification.State
            VersionDetector = '10.11'
            IndicadoresReportados = [string]::Join(' | ', [string[]]@($row.Types))
            IndicadoresActuales = [string]::Join(' | ', [string[]]@($verification.Evidence))
            BytesLeidos = $verification.BytesRead
            FechaCreacionUtc = $verification.Created
            FechaModificacionUtc = $verification.Modified
        }
        $verificationRows.Add($auditRow)
        $protectedAuditRow = Protect-SpreadsheetCsvRows -Rows @($auditRow) -Columns @(
            'Ubicacion','EstadoVerificacion','VersionDetector','IndicadoresReportados','IndicadoresActuales','BytesLeidos','FechaCreacionUtc','FechaModificacionUtc'
        )
        $auditWriter.WriteLine(@($protectedAuditRow | ConvertTo-Csv -NoTypeInformation)[1])
        if ($verificationRows.Count % 250 -eq 0) {
            $auditWriter.Flush()
            Write-Host ((Get-FilterText 'Rechecked {0}/{1}; current BIP39 candidates: {2}; elapsed: {3:N0} s.' 'Releidos {0}/{1}; candidatos BIP39 actuales: {2}; transcurrido: {3:N0} s.') -f $processed, $byLocation.Count, $candidates.Count, $verificationTimer.Elapsed.TotalSeconds)
        }
        if ($verification.State -notin @('bip39_detected', 'bip39_detected_incomplete_read')) { continue }
        $row.Created.Clear(); $row.Modified.Clear()
        if ($verification.Created) { [void]$row.Created.Add($verification.Created) }
        if ($verification.Modified) { [void]$row.Modified.Add($verification.Modified) }
    }
    $context = [string]::Join(' | ', [string[]]@($row.Contexts))
    $software = $context -match 'Software instalado, dependencia o caché|Registro local de sesión de usuario' -or
        $row.Ubicacion -match '(?i)(?:^|[\\/])(?:ScriptCache|CacheStorage|GPUCache|node_modules|Extensions|site-packages)(?:[\\/]|$)'
    $candidates.Add([pscustomobject][ordered]@{
        Ubicacion = [string]$row.Ubicacion
        Tipo = 'frase_bip39_checksum_valido'
        VersionDetector = if ($ReportOnly) { 'historico_sin_relectura' } else { '10.11' }
        GrupoRevision = if ($software) { 'Software o cache; posible ejemplo' } else { 'Procedencia por revisar' }
        ConfianzaDetector = [string]::Join(' | ', [string[]]@($row.Confidence))
        Contexto = $context
        FechaCreacionUtc = [string]::Join(' | ', [string[]]@($row.Created))
        FechaModificacionUtc = [string]::Join(' | ', [string[]]@($row.Modified))
        CantidadReportes = $row.Reports.Count
        ReportesOrigen = [string]::Join(' | ', [string[]]@($row.Reports))
        Limitacion = if ($ReportOnly) { 'Formato BIP39 validado por el reporte; no confirma titularidad, acceso ni saldo. No se ha releido el archivo.' }
            else { 'Formato BIP39 detectado al releer el archivo; no confirma titularidad, acceso ni saldo. Consultar el reporte de verificacion para limites o lectura incompleta.' }
    })
}
} finally {
    if ($null -ne $auditWriter) { $auditWriter.Dispose() }
    if ($verificationInitialized) {
        [CryptoDocumentScanner]::StopWorker()
        [CryptoMnemonicScanner]::Bip39Only = $false
        [CryptoFileScanner]::Bip39Only = $false
    }
    if ($null -ne $cpuBudget) { $cpuBudget.Dispose() }
    Write-Progress -Activity (Get-FilterText 'Rechecking reported files' 'Releyendo archivos reportados') -Completed
}
$sorted = @($candidates | Sort-Object GrupoRevision, Ubicacion)
$candidateColumns = @('Ubicacion','Tipo','VersionDetector','GrupoRevision','ConfianzaDetector','Contexto','FechaCreacionUtc','FechaModificacionUtc','CantidadReportes','ReportesOrigen','Limitacion')
$protectedCandidates = @(Protect-SpreadsheetCsvRows -Rows $sorted -Columns $candidateColumns)
$lines = if ($protectedCandidates.Count -gt 0) { @($protectedCandidates | ConvertTo-Csv -NoTypeInformation) }
    else { @('"Ubicacion","Tipo","VersionDetector","GrupoRevision","ConfianzaDetector","Contexto","FechaCreacionUtc","FechaModificacionUtc","CantidadReportes","ReportesOrigen","Limitacion"') }
$content = [string]::Join([Environment]::NewLine, [string[]]$lines) + [Environment]::NewLine
$encoding = [Text.UTF8Encoding]::new($true)
$changed = $true
if ((Test-Path -LiteralPath $destination -PathType Leaf) -and [IO.File]::ReadAllText($destination, $encoding) -ceq $content) {
    $changed = $false
} else {
    # Replacing the directory entry preserves unrelated source files even if an old
    # destination was a hard link. Keep identical reports unchanged for idempotence.
    $temporary = $destination + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, $content, $encoding)
        Assert-SafeOutput $destination
        if ([IO.File]::Exists($destination)) { [IO.File]::Replace($temporary, $destination, $null) }
        else { [IO.File]::Move($temporary, $destination) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}
Write-Host ((Get-FilterText 'BIP39 candidate locations: {0}. Output: {1}' 'Ubicaciones candidatas BIP39: {0}. Salida: {1}') -f $sorted.Count, $destination)
Write-Host ((Get-FilterText 'CSV files inspected: {0}; with individual locations: {1}; aggregates: {2}.' 'CSV revisados: {0}; con ubicaciones individuales: {1}; agregados: {2}.') -f $filesInspected, $filesWithLocations, $aggregateFiles)
if (-not $ReportOnly) {
    Assert-SafeOutput $verificationPath
    $verificationColumns = @('Ubicacion','EstadoVerificacion','VersionDetector','IndicadoresReportados','IndicadoresActuales','BytesLeidos','FechaCreacionUtc','FechaModificacionUtc')
    $protectedVerificationRows = @(Protect-SpreadsheetCsvRows -Rows $verificationRows.ToArray() -Columns $verificationColumns)
    $auditLines = if ($protectedVerificationRows.Count -gt 0) { @($protectedVerificationRows | ConvertTo-Csv -NoTypeInformation) }
        else { @('"Ubicacion","EstadoVerificacion","VersionDetector","IndicadoresReportados","IndicadoresActuales","BytesLeidos","FechaCreacionUtc","FechaModificacionUtc"') }
    $auditContent = [string]::Join([Environment]::NewLine, [string[]]$auditLines) + [Environment]::NewLine
    [void][CryptoFileScanner]::WriteTextIfChanged($verificationPath, $auditContent)
    if ([IO.File]::Exists($verificationPartialPath)) { [IO.File]::Delete($verificationPartialPath) }
    Write-Host ((Get-FilterText 'Verification report: {0}' 'Reporte de verificacion: {0}') -f $verificationPath)
}
Write-Host (Get-FilterText 'No phrases were exported. Checksums do not prove ownership or funds.' 'No se exportaron frases. Los checksums no prueban titularidad ni fondos.')
[pscustomobject]@{ CsvPath = $destination; CandidateLocations = $sorted.Count; Written = $changed; CsvFilesInspected = $filesInspected; CsvFilesWithLocations = $filesWithLocations; AggregateCsvFiles = $aggregateFiles; CandidateOccurrences = $candidateOccurrences }
