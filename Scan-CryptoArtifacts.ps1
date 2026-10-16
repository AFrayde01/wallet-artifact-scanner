[CmdletBinding()]
param(
    [string[]]$Root,
    [string]$CsvPath,
    [string[]]$ExcludePath = @(),
    [ValidateRange(1, 1024)][int]$MaxContentMB = 256,
    [ValidateRange(1, 256)][int]$MaxDocumentMB = 32,
    [ValidateRange(1, 2048)][int]$MaxExpandedMB = 256,
    [ValidateRange(1, 3600)][int]$CheckpointSeconds = 60,
    [ValidateRange(1, 100000)][int]$CheckpointFiles = 1000,
    [ValidateRange(1, 100)][int]$CpuCorePercent = 50,
    [ValidateRange(0, 32)][int]$Workers = 0,
    [switch]$PdfOcr,
    [string]$PdfToCairoPath,
    [string]$TesseractPath,
    [ValidateRange(72, 300)][int]$PdfOcrDpi = 150,
    [ValidateRange(1, 500)][int]$PdfOcrMaxPages = 100,
    [ValidateRange(15, 3600)][int]$PdfOcrTimeoutSeconds = 180,
    [switch]$NoProgress,
    [switch]$AllDrives,
    [switch]$RecoveryPhraseSearch,
    [switch]$Rescan,
    [switch]$NoCache,
    [switch]$IncludeUnvalidatedAddressCandidates,
    [switch]$PassThru,
    [ValidateSet('en', 'es')][string]$Language = 'en'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'scripts\CsvOutputSafety.ps1')
$script:EnglishConsoleText = @{
    'Escáner de indicios de criptomonedas — lectura de archivos' = 'Cryptocurrency artifact scanner — file reading'
    'Modo normal de análisis de criptomonedas' = 'Standard cryptocurrency artifact scan'
    'Búsqueda directa de frases de recuperación BIP39' = 'Direct BIP39 recovery phrase search'
    'Selecciona modo: A (análisis normal) o R (búsqueda directa BIP39)' = 'Choose mode: A (standard scan) or R (direct BIP39 recovery phrase search)'
    'Opción no válida. Elige A, R o 0.' = 'Invalid selection. Choose A, R or 0.'
    'La búsqueda directa de frases no utiliza OCR; quita -PdfOcr para continuar.' = 'Direct recovery phrase search does not use OCR; remove -PdfOcr to continue.'
    'Busca frases BIP39 en archivos compatibles de las ubicaciones seleccionadas. El checksum no confirma titularidad ni fondos.' = 'Search supported files in selected locations for BIP39 phrases. A checksum does not establish ownership or funds.'
    'sin etiqueta' = 'unlabeled'
    '{0} {1}; {2:N1} GB totales, {3:N1} GB libres' = '{0} {1}; {2:N1} GB total, {3:N1} GB free'
    '[C] Elegir carpeta o ubicación' = '[C] Choose a folder or location'
    '[A] Análisis amplio de indicios' = '[A] Broad artifact scan'
    '[R] Búsqueda directa de frases BIP39' = '[R] Direct BIP39 phrase search'
    '[T] Todas las unidades detectadas' = '[T] All detected drives'
    '[0] Salir' = '[0] Exit'
    'Selecciona una opción' = 'Select an option'
    'Cancelado.' = 'Cancelled.'
    'Ruta de la carpeta (vacío para volver)' = 'Folder path (leave empty to go back)'
    'Selección no válida. Elige un número, C, T o 0.' = 'Invalid selection. Choose a number, C, T or 0.'
    'Ruta del CSV (ENTER: ' = 'CSV path (ENTER: '
    '; 0: salir)' = '; 0: exit)'
    'calculando total' = 'calculating total'
    'calculando tasa' = 'calculating rate'
    '> 365 días' = '> 365 days'
    '{0}d {1:00}h {2:00}m {3:00}s aprox.' = '{0}d {1:00}h {2:00}m {3:00}s approx.'
    'Calculando total mientras se analiza' = 'Calculating total while analyzing'
    'Escaneo global — restante: ' = 'Overall scan — remaining: '
    'media: {0:N1} MB/s; reciente: {1:N1} MB/s; {2}' = 'average: {0:N1} MB/s; recent: {1:N1} MB/s; {2}'
    'Inventario: {0} archivos/{1} candidatos; ubicación {2}/{3}; trabajadores: {4}/{5}' = 'Inventory: {0} files/{1} candidates; location {2}/{3}; workers: {4}/{5}'
    'Escaneando ' = 'Scanning '
    'archivos: {0}/{1}; analizados: {2}; caché: {3}; leídos: {4:N1} MB' = 'files: {0}/{1}; analyzed: {2}; cached: {3}; read: {4:N1} MB'
    'Ubicación terminada: 100%' = 'Location complete: 100%'
    'Escaneo global' = 'Overall scan'
    '{0}/{1} ubicaciones terminadas' = '{0}/{1} locations complete'
    'Escaneo por ubicación' = 'Scan by location'
    'Ubicaciones: ' = 'Locations: '
    'Resultado: ' = 'Output: '
    'Categorías: ' = 'Categories: '
    'Cobertura directa: ' = 'Direct search coverage: '
    'Detectores {0}; caché: {1}' = 'Detectors {0}; cache: {1}'
    'OCR PDF local activado: texto impreso ({0}); límite {1} páginas y {2} s por PDF' = 'Local PDF OCR enabled: printed text ({0}); limit {1} pages and {2} s per PDF'
    'OCR PDF: desactivado (opcional: -PdfOcr; requiere Tesseract y Poppler locales)' = 'PDF OCR: disabled (optional: -PdfOcr; requires local Tesseract and Poppler)'
    'CPU: solicitado {0}% de núcleos; asignado {1:N1}% ({2}/{3} físicos); {4}/{5} procesadores lógicos; trabajadores: {6}' = 'CPU: requested {0}% of cores; allocated {1:N1}% ({2}/{3} physical); {4}/{5} logical processors; workers: {6}'
    'El porcentaje solicitado equivale a menos de un núcleo; se asignó el mínimo de un núcleo físico.' = 'The requested percentage is less than one core; the minimum of one physical core was allocated.'
    'No se pudo desactivar la selección automática de consola. Si queda en modo Seleccionar, pulsa Esc.' = 'Console QuickEdit could not be disabled. If the console enters selection mode, press Esc.'
    'No se pudo guardar un avance en la carpeta de salida. El escaneo continúa; revisa el resumen final.' = 'A checkpoint could not be saved in the output folder. Scanning continues; check the final summary.'
    'No se pudo guardar el último avance; se conserva el último checkpoint disponible.' = 'The latest progress could not be saved; the last available checkpoint is preserved.'
    'El escaneo terminó; generando contexto, resumen secundario y reporte de cobertura...' = 'Scan complete; generating context, secondary summary and coverage report...'
    'El escaneo terminó, pero no se pudieron generar las vistas de revisión: ' = 'Scan complete, but review reports could not be generated: '
    'Terminado en {0:N2} s; archivos: {1}; analizados: {2}; reutilizados: {3}' = 'Completed in {0:N2} s; files: {1}; analyzed: {2}; reused: {3}'
    'Indicios: {0}; incidencias: {1}; sobre el límite: {2}; enlaces omitidos: {3}; leídos: {4:N1} MB' = 'Findings: {0}; incidents: {1}; over limit: {2}; links skipped: {3}; read: {4:N1} MB'
    'Indicios secundarios: ' = 'Secondary indicators: '
    'Lecturas pendientes e incidencias: ' = 'Incomplete reads and incidents: '
    'Revisión con contexto: ' = 'Review with context: '
    'Resumen secundario por archivo: ' = 'Secondary summary by file: '
    'Resumen de cobertura: ' = 'Coverage summary: '
    'Registros principales: {0}; secundarios: {1}; incidencias: {2}' = 'Primary records: {0}; secondary: {1}; incidents: {2}'
    'Cobertura: omitidos por formato/nombre: {0}; carpetas excluidas: {1}; contenido interno analizado: {2}; contenido interno omitido: {3}' = 'Coverage: skipped by format/name: {0}; excluded folders: {1}; inner content analyzed: {2}; inner content skipped: {3}'
    'Lectura media efectiva: {0:N1} MB/s; incidencias del inventario: {1}' = 'Effective average read rate: {0:N1} MB/s; inventory incidents: {1}'
    '100% corresponde al recorrido terminado; revisa los archivos omitidos, límites e incidencias del resumen.' = '100% means traversal is complete; review skipped files, limits and incidents in the summary.'
    'Hay ubicaciones sin revisar por errores. Consulta las incidencias del CSV y vuelve a ejecutar después de resolver el acceso.' = 'Some locations could not be reviewed due to errors. Check CSV incidents and run again after resolving access.'
    'No se encontró el ejecutable indicado para OCR: ' = 'The specified OCR executable was not found: '
    'No se encontró ' = 'Not found: '
    '. Instala una versión local de Poppler/Tesseract o indica la ruta con -' = '. Install a local version of Poppler/Tesseract or specify the path with -'
    'Para usar rutas OCR debes activar también -PdfOcr.' = 'Using OCR executable paths also requires -PdfOcr.'
    'Poppler pdftocairo no pudo iniciarse correctamente.' = 'Poppler pdftocairo could not start correctly.'
    'Tesseract no pudo iniciarse correctamente.' = 'Tesseract could not start correctly.'
    'No se pudieron consultar los modelos locales de Tesseract.' = 'Local Tesseract language models could not be queried.'
    'Tesseract debe tener instalado el modelo de idioma eng o spa.' = 'Tesseract requires the eng or spa language model.'
    'No se encontró el archivo de modelo OCR usado por Tesseract; no se puede fijar su huella de caché.' = 'The OCR model used by Tesseract was not found; its cache fingerprint cannot be determined.'
    'Lista de palabras inválida: ' = 'Invalid word list: '
    'Falta CryptoMnemonicScanner-10.12.dll; extrae todos los archivos del paquete actualizado.' = 'CryptoMnemonicScanner-10.12.dll is missing; extract all files from the updated package.'
    'Hay otro detector cargado en esta sesión. Abre una nueva sesión de PowerShell para usar el paquete actualizado.' = 'Another detector is loaded in this session. Open a new PowerShell session to use the updated package.'
    'El componente del detector es anterior al script. Extrae el paquete completo actualizado.' = 'The detector component is older than the script. Extract the complete updated package.'
    'La ubicación pasa por un enlace o junction. Selecciona su ruta física.' = 'The location passes through a link or junction. Select its physical path.'
    'La ubicación seleccionada no es una carpeta.' = 'The selected location is not a folder.'
    'La ruta del resultado debe terminar en .csv.' = 'The output path must end in .csv.'
    'La carpeta del CSV debe existir. Si está dentro de una ubicación analizada, exclúyela con -ExcludePath.' = 'The CSV folder must exist. If it is inside a scanned location, exclude it with -ExcludePath.'
    'La salida apunta a una carpeta.' = 'The output points to a folder.'
    'El CSV y sus archivos auxiliares dentro de una ubicación analizada deben quedar bajo una carpeta indicada en -ExcludePath.' = 'CSV and auxiliary files inside a scanned location must be under a folder specified in -ExcludePath.'
    'Usa -Root o -AllDrives, no ambos.' = 'Use either -Root or -AllDrives.'
    'No se seleccionó ninguna ubicación disponible.' = 'No available location was selected.'
    '-ExcludePath no puede estar vacío.' = '-ExcludePath cannot be empty.'
    '-ExcludePath debe indicar una subcarpeta, no la ubicación completa que se escanea.' = '-ExcludePath must specify a subfolder rather than the entire scanned location.'
    'La ruta excluida debe estar dentro de una ubicación escaneada: ' = 'The excluded path must be inside a scanned location: '
    '-CsvPath no puede estar vacío.' = '-CsvPath cannot be empty.'
    'Falta tools/review/Export-ScanReviewReports.ps1 en el paquete.' = 'tools/review/Export-ScanReviewReports.ps1 is missing from the package.'
    'desactivada' = 'disabled'
    'nueva' = 'new'
    'reescaneo solicitado' = 'rescan requested'
    'formato anterior' = 'legacy format'
    'detectores o configuración cambiaron' = 'detectors or configuration changed'
    'ubicaciones cambiaron' = 'locations changed'
    'verificación SHA-256' = 'SHA-256 verification'
    'caché ilegible: reescaneo' = 'unreadable cache: rescan'
    'avances recuperados: verificación SHA-256' = 'recovered checkpoints: SHA-256 verification'
}

function Get-ScanText {
    param([string]$Text)
    if ($Language -eq 'es') { return $Text }
    if ($script:EnglishConsoleText.ContainsKey($Text)) { return $script:EnglishConsoleText[$Text] }
    return $Text
}

$script:AlgorithmVersion = '10.12'
$script:RecoveryPhraseSearch = [bool]$RecoveryPhraseSearch
$script:Timer = [Diagnostics.Stopwatch]::StartNew()
$script:Findings = New-Object 'System.Collections.Generic.List[object]'
$script:FindingKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:FileCount = [long]0
$script:DirectoryCount = [long]0
$script:ContentAnalyzedCount = [long]0
$script:ContentReusedCount = [long]0
$script:OversizeCount = [long]0
$script:ExcludedDirectoryCount = [long]0
$script:ExcludedDirectoryPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:ReparsePointCount = [long]0
$script:EnumerationErrorCount = [long]0
$script:ContentReadErrorCount = [long]0
$script:BytesReadTotal = [long]0
$script:SkippedFormatCount = [long]0
$script:DocumentIncompleteCount = [long]0
$script:MembersScanned = [long]0
$script:MembersSkipped = [long]0
$script:CheckpointCount = 0
$script:CheckpointErrors = 0
$script:MaxContentBytes = [long]$MaxContentMB * 1MB
$csvPathWasProvided = $PSBoundParameters.ContainsKey('CsvPath')

function Resolve-PdfOcrExecutable {
    param([string]$RequestedPath, [string]$CommandName, [string[]]$FallbackPaths)
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidate = [IO.Path]::GetFullPath($RequestedPath)
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw ((Get-ScanText 'No se encontró el ejecutable indicado para OCR: ') + $CommandName) }
        return $candidate
    }
    $command = Get-Command -Name $CommandName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) { return [IO.Path]::GetFullPath($command.Source) }
    foreach ($candidate in $FallbackPaths) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return [IO.Path]::GetFullPath($candidate) }
    }
    $parameterName = if ($CommandName -eq 'pdftocairo.exe') { 'PdfToCairoPath' } else { 'TesseractPath' }
    throw ((Get-ScanText 'No se encontró ') + $CommandName + (Get-ScanText '. Instala una versión local de Poppler/Tesseract o indica la ruta con -') + $parameterName + '.')
}

function Get-PdfOcrRuntime {
    param([bool]$Enabled, [string]$RendererPath, [string]$EnginePath)
    if (-not $Enabled) {
        if (-not [string]::IsNullOrWhiteSpace($RendererPath) -or -not [string]::IsNullOrWhiteSpace($EnginePath)) {
            throw (Get-ScanText 'Para usar rutas OCR debes activar también -PdfOcr.')
        }
        return [pscustomobject]@{ Enabled = $false; PdfToCairoPath = ''; TesseractPath = ''; Languages = ''; TessdataPath = ''; Fingerprint = 'disabled' }
    }

    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $rendererFallbacks = @(
        (Join-Path $PSScriptRoot 'dependencies\ocr\Library\bin\pdftocairo.exe'),
        (Join-Path $programFiles 'poppler\Library\bin\pdftocairo.exe'),
        (Join-Path $programFilesX86 'poppler\Library\bin\pdftocairo.exe')
    )
    $engineFallbacks = @(
        (Join-Path $PSScriptRoot 'dependencies\ocr\Library\bin\tesseract.exe'),
        (Join-Path $programFiles 'Tesseract-OCR\tesseract.exe'),
        (Join-Path $programFilesX86 'Tesseract-OCR\tesseract.exe')
    )
    $renderer = Resolve-PdfOcrExecutable $RendererPath 'pdftocairo.exe' $rendererFallbacks
    $engine = Resolve-PdfOcrExecutable $EnginePath 'tesseract.exe' $engineFallbacks

    # Locate common Tesseract layouts, including conda-forge's prefix\Library\bin + prefix\share\tessdata.
    # Tesseract needs TESSDATA_PREFIX before --list-langs and before the isolated PDF worker starts.
    $engineDirectory = [IO.Path]::GetDirectoryName($engine)
    $tessdataCandidates = New-Object 'Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($env:TESSDATA_PREFIX)) {
        $tessdataCandidates.Add($env:TESSDATA_PREFIX.TrimEnd('\\', '/'))
        $tessdataCandidates.Add((Join-Path $env:TESSDATA_PREFIX 'tessdata'))
    }
    $ancestor = [IO.DirectoryInfo]::new($engineDirectory)
    for ($depth = 0; $depth -lt 5 -and $null -ne $ancestor; $depth++) {
        $tessdataCandidates.Add((Join-Path $ancestor.FullName 'tessdata'))
        $tessdataCandidates.Add((Join-Path $ancestor.FullName 'share\tessdata'))
        $ancestor = $ancestor.Parent
    }
    $tessdataHint = $null
    foreach ($candidate in $tessdataCandidates) {
        if ((Test-Path -LiteralPath (Join-Path $candidate 'eng.traineddata') -PathType Leaf) -or
            (Test-Path -LiteralPath (Join-Path $candidate 'spa.traineddata') -PathType Leaf)) {
            $tessdataHint = [IO.Path]::GetFullPath($candidate)
            break
        }
    }
    if ($null -ne $tessdataHint) { $env:TESSDATA_PREFIX = $tessdataHint }

    $probeErrorPreference = $ErrorActionPreference
    try {
        # Poppler writes its version banner to stderr; Windows PowerShell 5.1 otherwise
        # promotes redirected native stderr to a terminating error when preference is Stop.
        $ErrorActionPreference = 'Continue'
        $rendererVersionLines = @(& $renderer '-v' 2>&1 | ForEach-Object { [string]$_ })
        $rendererExitCode = $LASTEXITCODE
        if ($rendererExitCode -ne 0) { throw (Get-ScanText 'Poppler pdftocairo no pudo iniciarse correctamente.') }
        $engineVersionLines = @(& $engine '--version' 2>&1 | ForEach-Object { [string]$_ })
        $engineExitCode = $LASTEXITCODE
        if ($engineExitCode -ne 0) { throw (Get-ScanText 'Tesseract no pudo iniciarse correctamente.') }
        $languageLines = @(& $engine '--list-langs' 2>&1 | ForEach-Object { [string]$_ })
        $languageExitCode = $LASTEXITCODE
        if ($languageExitCode -ne 0) { throw (Get-ScanText 'No se pudieron consultar los modelos locales de Tesseract.') }
    }
    finally { $ErrorActionPreference = $probeErrorPreference }
    $available = @($languageLines | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z0-9_]+)\s*$') { $Matches[1].ToLowerInvariant() }
    } | Sort-Object -Unique)
    $languages = @(@('eng', 'spa') | Where-Object { $available -contains $_ })
    if ($languages.Count -eq 0) { throw (Get-ScanText 'Tesseract debe tener instalado el modelo de idioma eng o spa.') }
    $languageArgument = $languages -join '+'

    $dataLine = $languageLines | Where-Object { $_ -match '(?i)List of available languages in\s+"([^"]+)"' } | Select-Object -First 1
    if ($null -ne $dataLine -and $dataLine -match '(?i)List of available languages in\s+"([^"]+)"') {
        $tessdataCandidates.Add($Matches[1].TrimEnd('\', '/'))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:TESSDATA_PREFIX)) {
        $tessdataCandidates.Add($env:TESSDATA_PREFIX.TrimEnd('\', '/'))
        $tessdataCandidates.Add((Join-Path $env:TESSDATA_PREFIX 'tessdata'))
    }
    $tessdata = $null
    foreach ($candidate in $tessdataCandidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $candidate = [IO.Path]::GetFullPath($candidate)
        $allModelsPresent = $true
        foreach ($language in $languages) {
            if (-not (Test-Path -LiteralPath (Join-Path $candidate ($language + '.traineddata')) -PathType Leaf)) { $allModelsPresent = $false; break }
        }
        if ($allModelsPresent) { $tessdata = $candidate; break }
    }
    if ($null -eq $tessdata) { throw (Get-ScanText 'No se encontró el archivo de modelo OCR usado por Tesseract; no se puede fijar su huella de caché.') }

    $identity = New-Object 'Collections.Generic.List[string]'
    $identity.Add('enabled'); $identity.Add($renderer); $identity.Add((Get-FileHash -LiteralPath $renderer -Algorithm SHA256).Hash.ToLowerInvariant())
    $identity.Add(($rendererVersionLines -join ' ')); $identity.Add($engine); $identity.Add((Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant())
    $identity.Add(($engineVersionLines -join ' ')); $identity.Add($languageArgument); $identity.Add($tessdata)
    foreach ($language in $languages) {
        $model = Join-Path $tessdata ($language + '.traineddata')
        $identity.Add($language + '=' + (Get-FileHash -LiteralPath $model -Algorithm SHA256).Hash.ToLowerInvariant())
    }
    return [pscustomobject]@{
        Enabled = $true; PdfToCairoPath = $renderer; TesseractPath = $engine
        Languages = $languageArgument; TessdataPath = $tessdata
        Fingerprint = ($identity -join '|')
    }
}

if ($script:RecoveryPhraseSearch -and $PdfOcr) { throw (Get-ScanText 'La búsqueda directa de frases no utiliza OCR; quita -PdfOcr para continuar.') }
$script:PdfOcrRuntime = Get-PdfOcrRuntime ([bool]$PdfOcr) $PdfToCairoPath $TesseractPath

$script:ExcludedDirectoryNames = @('System Volume Information', 'Windows', '$Recycle.Bin')
$script:DotEnvPattern = '(?i)^\.env(?:\..*)?$'
$script:BrowserProfilePattern = '(?i)[\\/]Google[\\/]Chrome[\\/]User Data[\\/]|[\\/]Microsoft[\\/]Edge[\\/]User Data[\\/]|[\\/]Mozilla[\\/]Firefox[\\/]Profiles[\\/]'
$script:WalletContentPathPattern = '(?i)(?:^|[\\/])(?:wallets?|\.?bitcoin|\.?litecoin|\.?dogecoin|\.?monero|\.?ethereum|\.?electrum|armory|multibit|sparrow|wasabi|exodus|atomic(?:wallet)?|coinbase(?: wallet)?|trust(?: wallet)?|coinomi|guarda|mycelium|ledger(?: live)?|trezor|phantom|metamask|solflare|rabby|keplr|imtoken|jaxx)(?:[\\/]|$)'
$script:ContentNamePattern = '(?i)(?:wallet|keystore|private.?key|secret.?key|privkey|clave.?privada|llave.?privada|seed.?phrase|recovery.?phrase)'
$script:ContentExtensions = @(
    '.txt', '.text', '.log', '.json', '.jsonl', '.csv', '.xml', '.html', '.htm',
    '.js', '.map', '.ini', '.cfg', '.conf', '.yaml', '.yml', '.md', '.rtf',
    '.db', '.ldb', '.sqlite', '.sqlite3', '.dat', '.key', '.privkey', '.secret',
    '.wallet', '.backup', '.bak', '.pem', '.asc', '.seed', '.confidential', '.config', '.toml', '.env', '.sql', '.py', '.ps1', '.sh', '.ts', '.tsx', '.jsx', '.properties', '.zip', '.pdf', '.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.odt', '.ods', '.odp'
)
$script:SkipContentExtensions = @(
    '.exe', '.dll', '.sys', '.drv', '.ocx', '.bin', '.7z', '.rar', '.tar',
    '.gz', '.xz', '.bz2', '.iso', '.vhd', '.vhdx', '.img',
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.mp3', '.mp4',
    '.avi', '.mkv', '.mov', '.woff', '.woff2', '.ttf', '.otf', '.wasm', '.crx',
    '.pak', '.node', '.jar', '.class'
)
$script:TextRules = @(
    [pscustomobject]@{
        Evidence = 'possible_bitcoin_private_key'
        Pattern = '(?<![1-9A-HJ-NP-Za-km-z])(?:[59][1-9A-HJ-NP-Za-km-z]{50}|[KLc][1-9A-HJ-NP-Za-km-z]{51})(?![1-9A-HJ-NP-Za-km-z])'
    },
    [pscustomobject]@{
        Evidence = 'possible_extended_private_key'
        Pattern = '(?i)\b(?:xprv|yprv|zprv|tprv|uprv|vprv)[1-9A-HJ-NP-Za-km-z]{90,120}\b'
    },
    [pscustomobject]@{
        Evidence = 'possible_bitcoin_address'
        Pattern = '(?i:\b(?:bc|tb|bcrt)1[ac-hj-np-z02-9]{8,87}\b)|(?<![1-9A-HJ-NP-Za-km-z])[13mn2][1-9A-HJ-NP-Za-km-z]{25,34}(?![1-9A-HJ-NP-Za-km-z])'
    },
    [pscustomobject]@{
        Evidence = 'possible_evm_address'
        Pattern = '(?i)(?<![0-9a-f])0x[0-9a-f]{40}(?![0-9a-f])'
    },
    [pscustomobject]@{
        Evidence = 'possible_monero_address'
        Pattern = '(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{95,106}(?![1-9A-HJ-NP-Za-km-z])'
    },
    [pscustomobject]@{
        Evidence = 'possible_hex_private_key'
        Pattern = '(?i)\b(?:private[\s_-]*key|secret[\s_-]*key|privkey|secretkey|(?:clave|llave)[\s_-]*privada)\b["'']?\s*[:=]\s*["'']?(?:0x)?[0-9a-f]{64}(?![0-9a-f])["'']?'
    },
    [pscustomobject]@{
        Evidence = 'cryptocurrency_terms'
        Pattern = '(?i)\b(?:bitcoin|bitcoins|btc|satoshi|ethereum|ether|eth|litecoin|ltc|dogecoin|doge|monero|xmr|ripple|xrp|solana|cardano|ada|polkadot|dash|zcash|tron|tezos|cosmos|avalanche|chainlink|stellar|bitcoin cash|bitcoin gold|shiba inu|shib|polygon|matic|algorand|near protocol|eos|altcoins?|cryptocurrencies|cryptocurrency|criptomonedas?|criptodivisas?|cryptomonedas?|crypto)\b'
    },
    [pscustomobject]@{
        Evidence = 'wallet_or_recovery_terms'
        Pattern = '(?i)\b(?:wallet|keystore|seed phrase|recovery phrase|mnemonic|private key|secret key|clave privada|llave privada|frase de recuperaci[o\xF3]n|frase semilla|semilla de recuperaci[o\xF3]n|billetera|monedero)\b'
    },
    [pscustomobject]@{
        Evidence = 'mining_or_pool_terms'
        Pattern = '(?i)\b(?:miner|mining|webminer|cryptominer|stratum(?:\+tcp)?|cryptonight|hashrate|coinhive|xmrig|nicehash|ethermine|pool\.mining)\b'
    }
)



function Read-WordList {
    param([string]$Name, [int]$ExpectedCount)
    $words = [IO.File]::ReadAllLines((Join-Path (Join-Path $PSScriptRoot 'resources\wordlists') $Name), [Text.Encoding]::UTF8)
    if ($words.Length -ne $ExpectedCount) { throw ((Get-ScanText 'Lista de palabras inválida: ') + $Name) }
    return ,$words
}

$assemblyPath = Join-Path $PSScriptRoot 'CryptoMnemonicScanner-10.12.dll'
if (-not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) { throw (Get-ScanText 'Falta CryptoMnemonicScanner-10.12.dll; extrae todos los archivos del paquete actualizado.') }
$assemblyHash = (Get-FileHash -LiteralPath $assemblyPath -Algorithm SHA256).Hash
$loadedAssemblyHash = Get-Variable -Name WalletArtifactScannerAssemblyHash -Scope Global -ErrorAction SilentlyContinue
$componentAlreadyLoaded = $null -ne ('CryptoMnemonicScanner' -as [type]) -or $null -ne ('CryptoFileScanner' -as [type]) -or $null -ne ('CryptoConsoleInputSession' -as [type])
if ($componentAlreadyLoaded -and ($null -eq $loadedAssemblyHash -or $loadedAssemblyHash.Value -ne $assemblyHash)) {
    throw (Get-ScanText 'Hay otro detector cargado en esta sesión. Abre una nueva sesión de PowerShell para usar el paquete actualizado.')
}
$scannerAssembly = [Reflection.Assembly]::LoadFile([IO.Path]::GetFullPath($assemblyPath))
if ($null -eq $scannerAssembly.GetType('CryptoFileScanner', $false) -or $null -eq $scannerAssembly.GetType('CryptoConsoleInputSession', $false)) { throw (Get-ScanText 'El componente del detector es anterior al script. Extrae el paquete completo actualizado.') }
if ([CryptoMnemonicScanner].Assembly.ManifestModule.ModuleVersionId -ne $scannerAssembly.ManifestModule.ModuleVersionId -or
    [CryptoFileScanner].Assembly.ManifestModule.ModuleVersionId -ne $scannerAssembly.ManifestModule.ModuleVersionId -or
    [CryptoConsoleInputSession].Assembly.ManifestModule.ModuleVersionId -ne $scannerAssembly.ManifestModule.ModuleVersionId) {
    throw (Get-ScanText 'Hay otro detector cargado en esta sesión. Abre una nueva sesión de PowerShell para usar el paquete actualizado.')
}
$global:WalletArtifactScannerAssemblyHash = $assemblyHash
[CryptoMnemonicScanner]::Configure(
    (Read-WordList 'bip39-english.txt' 2048), (Read-WordList 'bip39-spanish.txt' 2048),
    (Read-WordList 'monero-english.txt' 1626), (Read-WordList 'monero-english-old.txt' 1626),
    (Read-WordList 'monero-spanish.txt' 1626), (Read-WordList 'slip39-english.txt' 1024)
)
[CryptoFileScanner]::Configure([string[]]$script:TextRules.Evidence, [string[]]$script:TextRules.Pattern)
[CryptoFileScanner]::Bip39Only = $script:RecoveryPhraseSearch
[CryptoMnemonicScanner]::Bip39Only = $script:RecoveryPhraseSearch
[CryptoMnemonicScanner]::AllowPunctuationSeparators = $script:RecoveryPhraseSearch
[CryptoDocumentScanner]::Configure((Join-Path $PSScriptRoot 'scripts\Read-PdfWorker.ps1'), ([long]$MaxDocumentMB * 1MB), ([long]$MaxExpandedMB * 1MB),
    [bool]$PdfOcr, $script:PdfOcrRuntime.PdfToCairoPath, $script:PdfOcrRuntime.TesseractPath,
    $script:PdfOcrRuntime.Languages, [int]$PdfOcrDpi, [int]$PdfOcrMaxPages, [int]$PdfOcrTimeoutSeconds,
    $script:PdfOcrRuntime.TessdataPath)
[CryptoDocumentScanner]::DirectRecoverySearch = $script:RecoveryPhraseSearch

$script:FindingTypeLabels = @{
    possible_bip39_mnemonic_phrase = 'frase_bip39_checksum_valido'
    possible_monero_mnemonic_phrase = 'frase_monero_checksum_valido'
    possible_slip39_share = 'respaldo_slip39_checksum_valido'
    possible_bitcoin_private_key = 'candidata_formato_clave_privada_bitcoin'
    possible_extended_private_key = 'candidata_formato_clave_extendida'
    validated_bitcoin_private_key = 'clave_privada_bitcoin_checksum_valido'
    validated_extended_private_key = 'clave_privada_extendida_checksum_valido'
    validated_evm_address = 'direccion_evm_checksum_eip55_valido'
    validated_monero_address = 'direccion_monero_checksum_valido'
    validated_solana_keypair_json = 'keypair_solana_par_claves_validado'
    bitcoin_core_wallet_filename = 'nombre_wallet_core_sin_validar'
    validated_bitcoin_core_wallet_database = 'estructura_wallet_core_validada'
    bitcoin_core_berkeley_db_candidate = 'candidata_wallet_core_berkeley_db'
    validated_electrum_wallet_structure = 'estructura_wallet_electrum_validada'
    possible_encrypted_ethereum_keystore = 'keystore_ethereum_cifrado'
    validated_ethereum_keystore_structure = 'keystore_ethereum_estructura_v3_valida'
    validated_bitcoin_address = 'direccion_bitcoin_checksum_valido'
    public_mnemonic_dictionary = 'diccionario_publico_del_detector'
    container_public_mnemonic_dictionary = 'diccionario_publico_en_comprimido'
    scanner_runtime_copy = 'copia_verificada_del_escaner'
    mnemonic_bip39_public_example_candidate = 'candidata_bip39_ejemplo_publico_checksum_valido'
    possible_bitcoin_address = 'candidata_direccion_bitcoin_sin_checksum'
    possible_evm_address = 'candidata_direccion_evm_sin_validar'
    possible_monero_address = 'candidata_direccion_monero_sin_validar'
    possible_hex_private_key = 'candidata_clave_hexadecimal_sin_validar'
    possible_solana_keypair_json = 'posible_keypair_solana_json'
    known_wallet_software_or_data_path = 'ruta_billetera'
    wallet_or_crypto_related_filename = 'archivo_relacionado_billetera'
    mining_software_named_path = 'ruta_software_minado'
    browser_extension_storage_with_crypto_terms = 'almacenamiento_extension_cripto'
    cryptocurrency_terms = 'terminos_criptomoneda'
    wallet_or_recovery_terms = 'terminos_billetera'
    mining_or_pool_terms = 'terminos_mineria'
    file_over_content_limit = 'archivo_supera_limite'
    file_read_error = 'error_lectura_archivo'
    directory_access_error = 'error_acceso_directorio'
    item_scan_error = 'error_revision_elemento'
    pdf_ocr_candidate_indicator = 'indicador_criptografico_candidato_por_ocr'
    document_read_error = 'error_lectura_documento'
    document_ocr_error = 'error_ocr_pdf'
    document_ocr_page_limit = 'limite_paginas_ocr_pdf'
    document_encrypted = 'documento_cifrado_sin_revisar'
    document_size_limit = 'documento_supera_limite'
    document_resource_limit = 'documento_supera_limite_recursos'
    document_without_extractable_text = 'documento_sin_texto_extraible'
    container_member_read_error = 'error_lectura_contenido_comprimido'
    container_expansion_limit = 'comprimido_supera_limite_expansion'
    container_entry_limit = 'comprimido_supera_limite_entradas'
    container_depth_limit = 'comprimido_supera_limite_anidacion'
}

$script:FindingTypeLabels.file_analysis_error = 'error_analisis_archivo'
foreach ($family in @('bip39', 'monero', 'slip39')) {
    foreach ($quality in @('fragmented', 'repetitive', 'dictionary')) {
        $label = switch ($quality) { 'fragmented' { 'fragmentada' }; 'repetitive' { 'repetitiva' }; 'dictionary' { 'diccionario' } }
        $script:FindingTypeLabels['mnemonic_' + $family + '_' + $quality + '_candidate'] = 'candidata_' + $family + '_' + $label + '_checksum_valido'
    }
}
$script:ContentEvidenceIds = [string[]](@($script:TextRules.Evidence) + @(
    'possible_bip39_mnemonic_phrase', 'possible_monero_mnemonic_phrase', 'possible_slip39_share',
    'possible_encrypted_ethereum_keystore', 'possible_solana_keypair_json',
    'validated_bitcoin_private_key', 'validated_extended_private_key', 'validated_bitcoin_address',
    'validated_evm_address', 'validated_monero_address', 'validated_solana_keypair_json',
    'validated_ethereum_keystore_structure', 'validated_bitcoin_core_wallet_database', 'validated_electrum_wallet_structure',
    'public_mnemonic_dictionary', 'container_public_mnemonic_dictionary', 'scanner_runtime_copy', 'pdf_ocr_candidate_indicator',
    'bitcoin_core_wallet_filename', 'bitcoin_core_berkeley_db_candidate', 'wallet_or_crypto_related_filename'
) + @($script:FindingTypeLabels.Keys | Where-Object { $_ -like 'mnemonic_*_candidate' }))
$dictionaryHashes = @(
    'bip39-english.txt', 'bip39-spanish.txt', 'monero-english.txt', 'monero-english-old.txt', 'monero-spanish.txt', 'slip39-english.txt'
    ) | ForEach-Object { (Get-FileHash -LiteralPath (Join-Path (Join-Path $PSScriptRoot 'resources\wordlists') $_) -Algorithm SHA256).Hash.ToLowerInvariant() }
[CryptoFileScanner]::ConfigurePublicDictionaries([string[]]$dictionaryHashes)
$script:ScannerDataFilePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($name in @(
    'README.md', 'README.es.md', 'LICENSE',
    'Scan-CryptoArtifacts.ps1', 'tools/review/Filter-RecoveryCandidates.ps1', 'tools/review/Export-ScanReviewReports.ps1', 'tools/review/Verify-Bip39Structure.ps1',
    'CryptoMnemonicScanner-10.12.dll', 'CryptoBip39Inspector.dll',
    'scripts/CsvOutputSafety.ps1', 'scripts/Read-PdfWorker.ps1',
    'src/CryptoBip39Inspector.cs', 'src/CryptoDocumentScanner.cs', 'src/CryptoEvidenceQuality.cs', 'src/CryptoFileScanner.cs',
    'src/CryptoKeyValidation.cs', 'src/CryptoMnemonicScanner.cs', 'src/CryptoParallelScanner.cs', 'src/CryptoScanInventory.cs', 'src/CryptoWindowsIO.cs',
    'resources/wordlists/bip39-english.txt', 'resources/wordlists/bip39-spanish.txt',
    'resources/wordlists/monero-english-old.txt', 'resources/wordlists/monero-english.txt', 'resources/wordlists/monero-spanish.txt',
    'resources/wordlists/slip39-english.txt',
    'docs/SECURITY.md', 'docs/THIRD-PARTY.md', 'docs/THIRD-PARTY.es.md'
)) {
    [void]$script:ScannerDataFilePaths.Add([IO.Path]::GetFullPath((Join-Path $PSScriptRoot ($name.Replace('/', [IO.Path]::DirectorySeparatorChar)))))
}
$script:ScannerDependencyFiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($name in @('Microsoft-LICENSE.txt', 'Monero-WORDLIST-LICENSE.txt', 'PdfPig-LICENSE.txt', 'Trezor-MIT-LICENSE.txt', 'packages.lock.json')) {
    [void]$script:ScannerDependencyFiles.Add($name)
}
$dependencyLock = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dependencies\packages.lock.json') -Raw | ConvertFrom-Json
foreach ($dependency in $dependencyLock) {
    foreach ($file in $dependency.Files) { [void]$script:ScannerDependencyFiles.Add($file.File) }
}
foreach ($name in $script:ScannerDependencyFiles) {
    [void]$script:ScannerDataFilePaths.Add([IO.Path]::GetFullPath((Join-Path (Join-Path $PSScriptRoot 'dependencies') $name)))
}
$runtimeNames = [Collections.Generic.List[string]]::new()
$runtimeHashes = [Collections.Generic.List[string]]::new()
$script:RuntimeManifestParts = [Collections.Generic.List[string]]::new()
foreach ($path in @($script:ScannerDataFilePaths | Sort-Object)) {
    # Source and documentation files are optional when deploying only the compiled runtime.
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $name = $path.Substring($PSScriptRoot.TrimEnd('\').Length + 1).Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $runtimeNames.Add($name); $runtimeHashes.Add($hash)
    $script:RuntimeManifestParts.Add($name + '=' + $hash)
}
[CryptoFileScanner]::ConfigureRuntimeFiles($runtimeNames.ToArray(), $runtimeHashes.ToArray())
$script:ContentExtensionSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:RecoveryContentExtensions = [string[]](@($script:ContentExtensions) + @('.eml','.tex','.rst','.org','.adoc','.nfo','.markdown','.readme','.cs','.c','.cpp','.h','.hpp','.java','.go','.rs','.rb','.php','.kt','.swift',''))
$script:RecoveryContentExtensionSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:SkipExtensionSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$script:ExcludedDirectorySet = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($extension in $script:ContentExtensions) { [void]$script:ContentExtensionSet.Add($extension) }
foreach ($extension in $script:RecoveryContentExtensions) { [void]$script:RecoveryContentExtensionSet.Add($extension) }
foreach ($extension in $script:SkipContentExtensions) { [void]$script:SkipExtensionSet.Add($extension) }
foreach ($name in $script:ExcludedDirectoryNames) { [void]$script:ExcludedDirectorySet.Add($name) }
$script:SensitiveRules = @($script:TextRules | Where-Object { $_.Evidence -in @(
    'possible_bitcoin_private_key', 'possible_extended_private_key', 'possible_bitcoin_address',
    'possible_evm_address', 'possible_monero_address', 'possible_hex_private_key'
) })

$script:RecoverySoftwareContextPattern = '(?i)[\\/](?:Program Files(?: \(x86\))?|WindowsApps|node_modules|site-packages|vendor|\.git|tests?|testdata|fixtures?|examples?|samples?|artifacts?|extensions|cache|Cache_Data|Code Cache|AppData[\\/]Local[\\/]Programs)(?:[\\/]|$)|[\\/]wallet-artifact-scanner[\\/](?:tests|artifacts)[\\/]'

function Get-SafeFindingPath {
    param([string]$Path)
    if ([CryptoMnemonicScanner]::Scan($Path).Length -gt 0) { return ([CryptoWindowsIO]::RootPath($Path) + '[RUTA SENSIBLE REDACTADA]') }
    foreach ($rule in $script:SensitiveRules) { $Path = [Text.RegularExpressions.Regex]::Replace($Path, $rule.Pattern, '[REDACTADO]') }
    $Path = [Text.RegularExpressions.Regex]::Replace($Path, '\[\s*(?:[0-9]{1,3}\s*,\s*){63}[0-9]{1,3}\s*\]', '[REDACTADO]')
    return [Text.RegularExpressions.Regex]::Replace($Path, '(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])', '[REDACTADO]')
}

function Add-Finding {
    param([string]$Path, [string[]]$Evidence)
    if ($Evidence.Length -eq 0) { return }
    $safePath = Get-SafeFindingPath $Path
    if ($script:RecoveryPhraseSearch) {
        $fileDates = @{ Created = ''; Modified = '' }
        try {
            $sourceItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            $fileDates.Created = $sourceItem.CreationTimeUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            $fileDates.Modified = $sourceItem.LastWriteTimeUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
        } catch { }
        $hasPublicDictionary = @($Evidence | Where-Object { $_ -in @('public_mnemonic_dictionary','container_public_mnemonic_dictionary') }).Count -gt 0
        foreach ($id in ($Evidence | Sort-Object -Unique)) {
            if ($hasPublicDictionary -and $id -match '^(?:possible_bip39|mnemonic_bip39_)') { continue }
            $isPublicDictionary = $id -in @('public_mnemonic_dictionary','container_public_mnemonic_dictionary')
            $isMatch = $id -in @('possible_bip39_mnemonic_phrase','mnemonic_bip39_public_example_candidate','mnemonic_bip39_fragmented_candidate','mnemonic_bip39_repetitive_candidate','mnemonic_bip39_dictionary_candidate')
            $isCoverageIssue = $id -match '(?:_error|_limit)$|^document_(?:encrypted|without_extractable_text)$|^file_over_content_limit$|^file_read_error$'
            if (-not $isMatch -and -not $isCoverageIssue -and -not $isPublicDictionary) { continue }
            $reason = if ($script:FindingTypeLabels.ContainsKey($id)) { [string]$script:FindingTypeLabels[$id] } else { $id }
            $softwareContext = $Path -match $script:RecoverySoftwareContextPattern -or [IO.Path]::GetExtension($Path) -match '(?i)^\.(?:js|jsx|ts|tsx|map|py|ps1|sh|cs|c|cpp|h|hpp|java|go|rs|rb|php|kt|swift)$'
            $category = if ($id -eq 'mnemonic_bip39_public_example_candidate' -or $isPublicDictionary) { 'ejemplo_publico' }
                elseif ($id -match '^mnemonic_bip39_(?:fragmented|repetitive|dictionary)_candidate$') { 'patron_dudoso_checksum_valido' }
                elseif ($id -eq 'possible_bip39_mnemonic_phrase' -and $softwareContext) { 'contexto_software_o_pruebas' }
                elseif ($id -eq 'possible_bip39_mnemonic_phrase') { 'frase_checksum_valido' }
                else { 'cobertura_incompleta' }
            $limitation = if ($category -eq 'frase_checksum_valido') {
                'El checksum confirma formato BIP39, no titularidad, acceso ni fondos. El contenido de origen no se exporta.'
            } elseif ($category -eq 'patron_dudoso_checksum_valido') {
                'El checksum es válido, pero el patrón estructural es débil. Revisa el archivo original; su contenido no se exporta.'
            } elseif ($isPublicDictionary) {
                'Se reconoció un diccionario público del formato, no una frase personal. El contenido de origen no se exporta.'
            } elseif ($category -eq 'ejemplo_publico') {
                'Coincide con un vector público de prueba BIP39 y puede aparecer en ejemplos o software. No indica titularidad ni fondos.'
            } elseif ($category -eq 'contexto_software_o_pruebas') {
                'Frase con checksum válido en una ruta asociada a software, pruebas o ejemplos; podría ser dato público. Se desconoce titularidad y saldo.'
            } else {
                'La lectura pudo quedar incompleta. No se usa OCR ni descifrado; la limitación concreta figura en Razon.'
            }
            if ($script:FindingKeys.Add($safePath + [char]0 + $category + [char]0 + $reason)) {
                $script:Findings.Add([pscustomobject]@{
                    Ubicacion = $safePath; Categoria = $category; Razon = $reason
                    FechaCreacionUtc = $fileDates.Created; FechaModificacionUtc = $fileDates.Modified; Limitacion = $limitation
                })
            }
        }
        return
    }
    $fileDates = $null
    $strongContentIds = @('validated_bitcoin_private_key','validated_extended_private_key','validated_ethereum_keystore_structure',
        'validated_bitcoin_core_wallet_database','validated_electrum_wallet_structure','validated_solana_keypair_json')
    $genericTextIds = @('cryptocurrency_terms','wallet_or_recovery_terms','mining_or_pool_terms')
    $genericPathIds = @('wallet_or_crypto_related_filename','known_wallet_software_or_data_path')
    $container = [IO.Path]::GetExtension($Path) -ieq '.zip'
    $hasStrongContent = @($Evidence | Where-Object { $_ -in $strongContentIds }).Count -gt 0
    $validatedPairs = @{
        possible_bitcoin_private_key = 'validated_bitcoin_private_key'
        possible_extended_private_key = 'validated_extended_private_key'
        possible_bitcoin_address = 'validated_bitcoin_address'
        possible_evm_address = 'validated_evm_address'
        possible_monero_address = 'validated_monero_address'
        possible_solana_keypair_json = 'validated_solana_keypair_json'
        possible_encrypted_ethereum_keystore = 'validated_ethereum_keystore_structure'
    }
    foreach ($id in $Evidence) {
        if (-not $script:FindingTypeLabels.ContainsKey($id)) { continue }
        # Invalid checksums make Bitcoin/Monero address-like strings weak evidence by default.
        # Keep the option for broad passes where damaged or truncated strings matter.
        if (-not $IncludeUnvalidatedAddressCandidates -and $id -in @('possible_bitcoin_address', 'possible_monero_address')) { continue }
        # The CSV identifies files, not offsets. Keep the specific result when a validator
        # confirms the same format; preserve member-level clues inside ZIPs.
        if (-not $container -and $hasStrongContent -and $id -in $genericTextIds) { continue }
        if (-not $container -and $hasStrongContent -and $id -in $genericPathIds) { continue }
        if (-not $container -and $validatedPairs.ContainsKey($id) -and $Evidence -contains $validatedPairs[$id]) { continue }
        $label = [string]$script:FindingTypeLabels[$id]
        if ($script:FindingKeys.Add($safePath + [char]0 + $label)) {
            $category = Get-FindingCategory $Path $id $Evidence
            if ($null -eq $fileDates) {
                $fileDates = @{ Created = ''; Modified = '' }
                try {
                    # Metadata only: never read or change the source content for report dates.
                    # Container findings identify the outer file, so its dates apply.
                    $sourceItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
                    $fileDates.Created = $sourceItem.CreationTimeUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                    $fileDates.Modified = $sourceItem.LastWriteTimeUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
                } catch { }
            }
            $script:Findings.Add([pscustomobject]@{
                Ubicacion = $safePath; Tipo = $label; Categoria = $category
                FechaCreacionUtc = $fileDates.Created; FechaModificacionUtc = $fileDates.Modified
            })
        }
    }
}

function Get-FindingCategory {
    param([string]$Path, [string]$Id, [string[]]$AllEvidence)
    if ($Id -match '(?:_error|_limit)$|^document_(?:encrypted|without_extractable_text)$|^file_over_content_limit$') { return 'incidencias' }
    if ($AllEvidence -contains 'public_mnemonic_dictionary' -or $AllEvidence -contains 'scanner_runtime_copy') { return 'secundarios' }
    $strongContentIds = @('validated_bitcoin_private_key','validated_extended_private_key','validated_ethereum_keystore_structure',
        'validated_bitcoin_core_wallet_database','validated_electrum_wallet_structure','validated_solana_keypair_json')
    # Strong evidence retains priority even when software or cache paths contain it.
    if ($Id -in $strongContentIds) { return 'principal' }
    if ($Id -eq 'bitcoin_core_wallet_filename') {
        if ($AllEvidence -contains 'validated_bitcoin_core_wallet_database') { return 'principal' }
        return 'secundarios'
    }
    # Bitcoin addresses are public identifiers; a valid checksum alone does not establish a wallet.
    if ($Id -eq 'validated_bitcoin_address') { return 'secundarios' }
    # Context lowers priority for weaker findings; all locations and distinct evidence remain.
    if ($Path -match '(?i)[\\/](?:Program Files(?: \(x86\))?|node_modules|site-packages|vendor|\.git)[\\/]|[\\/](?:Extensions|Cache|Cache_Data|Code Cache)[\\/]|[\\/]wallet-artifact-scanner[\\/](?:tests|artifacts)[\\/]|[\\/]Winamp[\\/].*[\\/]wasabi(?:[\\/]|$)') { return 'secundarios' }
    if ($Path -match '(?i)[\\/]\.codex[\\/](?:plugins|sessions|\.tmp)[\\/]|[\\/]AppData[\\/]Local[\\/]Programs[\\/]|[\\/](?:GPUCache|component_crx_cache|BrowserMetrics)[\\/]') { return 'secundarios' }
    if ([IO.Path]::GetExtension($Path) -match '(?i)^\.(?:js|ts|tsx|jsx|py|ps1|sh|map)$' -and $Id -ne 'possible_hex_private_key') { return 'secundarios' }
    # Filenames and wallet software paths are useful leads, but alone they do not
    # establish that the file contains wallet material. Keep them out of the priority CSV.
    if ($Id -in @('wallet_or_crypto_related_filename', 'known_wallet_software_or_data_path')) { return 'secundarios' }
    # These mnemonic formats have a validated checksum; a hex-key pattern is only a candidate.
    if ($Id -in @('possible_bip39_mnemonic_phrase', 'possible_monero_mnemonic_phrase', 'possible_slip39_share')) { return 'principal' }
    return 'secundarios'
}

function Get-FileFormatEvidence {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([IO.Path]::GetFileName($Path) -match '(?i)^wallet\.dat(?:\..*)?$') {
        return [CryptoFileScanner]::GetBitcoinCoreWalletDatabaseEvidence($Path)
    }
    return @()
}

function Get-DefaultScanRoots {
    $roots = New-Object 'System.Collections.Generic.List[string]'
    $seenRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
        try {
            if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -and
                $drive.DriveType -ne [System.IO.DriveType]::Removable) {
                continue
            }
            if (-not $drive.IsReady) { continue }
            $driveRoot = [System.IO.Path]::GetFullPath($drive.RootDirectory.FullName)
            if ($seenRoots.Add($driveRoot)) { $roots.Add($driveRoot) }
        }
        catch {
            continue
        }
    }
    return $roots.ToArray()
}

function Get-PathEvidence {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][bool]$IsDirectory)
    $evidence = New-Object 'System.Collections.Generic.List[string]'
    $normalizedPath = $Path -replace '/', '\'
    $name = [System.IO.Path]::GetFileName($normalizedPath.TrimEnd('\'))
    $walletPathPattern = '(?i)(?:^|\\)(?:\.?bitcoin|\.?litecoin|\.?dogecoin|dashcore|\.?monero|\.?ethereum|\.?electrum|armory|multibit(?:\s*hd)?|sparrow|wasabi|exodus|atomic(?:wallet)?|coinbase(?: wallet)?|trust(?: wallet)?|coinomi|guarda|mycelium|ledger(?: live)?|trezor|phantom|metamask|solflare|rabby|keplr|imtoken|jaxx)(?:\\|$)'
    if ($normalizedPath -match $walletPathPattern) {
        $evidence.Add('known_wallet_software_or_data_path')
    }
    if ($IsDirectory) {
        if ($name -match '(?i)^(?:bitcoin|litecoin|dogecoin|monero|ethereum|\.?electrum|armory|multibit(?:\s*hd)?|sparrow|wasabi|exodus|atomic(?:wallet)?|coinbase(?: wallet)?|trust(?: wallet)?|coinomi|guarda|mycelium|ledger(?: live)?|trezor|phantom|metamask|solflare|rabby|keplr|imtoken|jaxx|wallets?)$') {
            $evidence.Add('known_wallet_software_or_data_path')
        }
        if ($name -match '(?i)^(?:xmrig|cgminer|bfgminer|cpuminer|minerd|guiminer|nicehash|coinhive|claymore|phoenixminer)$') {
            $evidence.Add('mining_software_named_path')
        }
    }
    else {
        if ($name -match '(?i)^wallet\.dat(?:\..*)?$') {
            $evidence.Add('bitcoin_core_wallet_filename')
        }
        elseif ($name -match '(?i)^(?:UTC--.*|keystore.*\.(?:json|key)|.*(?:wallet|electrum|armory|multibit|bitcoin|litecoin|dogecoin|monero|ethereum|mnemonic|seed.?phrase|recovery.?phrase).*)$') {
            $evidence.Add('wallet_or_crypto_related_filename')
        }
        if ($name -match '(?i)^(?:xmrig|cgminer|bfgminer|cpuminer|minerd|guiminer|nicehash|coinhive|claymore|phoenixminer)(?:\..*)?$') {
            $evidence.Add('mining_software_named_path')
        }
    }
    return @($evidence)
}

function Test-BrowserProfilePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return $Path -match $script:BrowserProfilePattern
}

function Test-BrowserExtensionStoragePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return $Path -match '(?i)[\\/]Google[\\/]Chrome[\\/]User Data[\\/](?:Default|Profile \d+)[\\/](?:Extensions|Local Extension Settings|IndexedDB|Local Storage)[\\/]|[\\/]Microsoft[\\/]Edge[\\/]User Data[\\/](?:Default|Profile \d+)[\\/](?:Extensions|Local Extension Settings|IndexedDB|Local Storage)[\\/]|[\\/]Mozilla[\\/]Firefox[\\/]Profiles[\\/].*[\\/](?:browser-extension-data|storage[\\/]default)[\\/]'
}



function Test-ContentEligible {
    param([string]$Path, [string]$Name)
    $extension = [IO.Path]::GetExtension($Name)
    if ($script:SkipExtensionSet.Contains($extension)) { return $false }
    if ($script:RecoveryPhraseSearch) { return $script:RecoveryContentExtensionSet.Contains($extension) -or $Name -match $script:DotEnvPattern }
    if ($script:ContentExtensionSet.Contains($extension) -or $Name -match $script:DotEnvPattern) { return $true }
    if (Test-BrowserProfilePath $Path) { return $true }
    return $Path -match $script:WalletContentPathPattern -or $Name -match $script:ContentNamePattern
}

function Assert-NoReparseAncestor {
    param([string]$Path)
    $current = [CryptoWindowsIO]::NormalizePath($Path).TrimEnd('\')
    $root = [CryptoWindowsIO]::RootPath($current).TrimEnd('\')
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = [CryptoWindowsIO]::TryGetInfo($current + $(if ($current -eq $root) { '\' } else { '' }))
        if ($null -ne $item) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw (Get-ScanText 'La ubicación pasa por un enlace o junction. Selecciona su ruta física.') }
        }
        if ($current.Length -le $root.Length) { break }
        $current = $current.Substring(0, $current.LastIndexOf('\'))
    }
}

function Resolve-ScanLocation {
    param([string]$Path)
    if (-not [IO.Path]::IsPathRooted($Path)) { $Path = Join-Path (Get-Location).ProviderPath $Path }
    $path = [CryptoWindowsIO]::NormalizePath($Path)
    $info = [CryptoWindowsIO]::GetInfo($path)
    if (($info.Attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw (Get-ScanText 'La ubicación seleccionada no es una carpeta.') }
    Assert-NoReparseAncestor $path
    return $path.TrimEnd('\') + '\'
}

function Test-InRoot {
    param([string]$Path, [string]$ScanRoot)
    $normalizedScanRoot = $ScanRoot.TrimEnd('\', '/')
    $prefix = $normalizedScanRoot + [IO.Path]::DirectorySeparatorChar
    return $Path.TrimEnd('\', '/').Equals($normalizedScanRoot, [StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-OutputPath {
    param([string]$RequestedPath)
    $path = [IO.Path]::GetFullPath($RequestedPath)
    if ([IO.Path]::GetExtension($path) -ine '.csv') { throw (Get-ScanText 'La ruta del resultado debe terminar en .csv.') }
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($path)) -PathType Container)) { throw (Get-ScanText 'La carpeta del CSV debe existir. Si está dentro de una ubicación analizada, exclúyela con -ExcludePath.') }
    if ($script:RecoveryPhraseSearch) { $outputs = @($path) }
    else {
        $outputs = @($path, [IO.Path]::ChangeExtension($path, '.secundarios.csv'), [IO.Path]::ChangeExtension($path, '.incidencias.csv'),
            [IO.Path]::ChangeExtension($path, '.revision.csv'), [IO.Path]::ChangeExtension($path, '.prioritarios.csv'),
            [IO.Path]::ChangeExtension($path, '.secundarios-resumen.csv'), [IO.Path]::ChangeExtension($path, '.secundarios-indicadores-resumen.csv'),
            [IO.Path]::ChangeExtension($path, '.cobertura-resumen.csv'))
    }
    if (-not $NoCache) { $outputs += [IO.Path]::ChangeExtension($path, '.scanstate'); $outputs += [IO.Path]::ChangeExtension($path, '.scanjournal'); $outputs += [IO.Path]::ChangeExtension($path, '.partial.csv') }
    foreach ($output in $outputs) {
        Assert-NoReparseAncestor $output
        if (Test-Path -LiteralPath $output -PathType Container) { throw (Get-ScanText 'La salida apunta a una carpeta.') }
        foreach ($scanRoot in $resolvedRoots) {
            if (Test-InRoot $output $scanRoot) {
                $outputIsExcluded = $false
                foreach ($excludedDirectory in $script:ExcludedDirectoryPaths) {
                    if (Test-InRoot $output $excludedDirectory) { $outputIsExcluded = $true; break }
                }
                if (-not $outputIsExcluded) {
                    throw (Get-ScanText 'El CSV y sus archivos auxiliares dentro de una ubicación analizada deben quedar bajo una carpeta indicada en -ExcludePath.')
                }
            }
        }
    }
    return $path
}

function Start-ScanConsoleSession {
    return [CryptoConsoleInputSession]::new()
}

function Get-AlgorithmFingerprint {
    $parts = New-Object 'Collections.Generic.List[string]'
    $parts.Add($script:AlgorithmVersion)
    $parts.Add([string]$MaxContentMB)
    $parts.Add([string]$MaxDocumentMB)
    $parts.Add([string]$MaxExpandedMB)
    $parts.Add('RecoveryPhraseSearch=' + [string]$script:RecoveryPhraseSearch)
    $parts.Add('AllowPunctuationSeparators=' + [string]([bool]$script:RecoveryPhraseSearch))
    $parts.Add('IncludeUnvalidatedAddressCandidates=' + [string][bool]$IncludeUnvalidatedAddressCandidates)
    $parts.Add('PdfOcr=' + $script:PdfOcrRuntime.Fingerprint)
    if ($script:PdfOcrRuntime.Enabled) {
        $parts.Add('PdfOcrDpi=' + [string]$PdfOcrDpi)
        $parts.Add('PdfOcrMaxPages=' + [string]$PdfOcrMaxPages)
        $parts.Add('PdfOcrTimeoutSeconds=' + [string]$PdfOcrTimeoutSeconds)
    }
    foreach ($rule in $script:TextRules) { $parts.Add($rule.Evidence + '=' + $rule.Pattern) }
    $parts.Add(($script:ContentExtensions -join '|'))
    $parts.Add(('RecoveryContentExtensions=' + ($script:RecoveryContentExtensions -join '|')))
    $parts.Add(($script:SkipContentExtensions -join '|'))
    $parts.Add('ExcludedDirectoryNames=' + ($script:ExcludedDirectoryNames -join '|'))
    $parts.Add('ExcludePath=' + ((@($script:ExcludedDirectoryPaths) | Sort-Object) -join '|'))
    foreach ($pattern in @($script:DotEnvPattern, $script:BrowserProfilePattern, $script:WalletContentPathPattern, $script:ContentNamePattern)) { $parts.Add($pattern) }
    $parts.Add((Get-Command Test-ContentEligible).Definition)
    $parts.Add((Get-Command New-ScanWorkItem).Definition)
    $parts.Add((Get-Command Add-Finding).Definition)
    $parts.Add((Get-Command Get-FindingCategory).Definition)
    $parts.Add((Get-Command Get-PathEvidence).Definition)
    $parts.Add((Get-Command Get-FileFormatEvidence).Definition)
    # This manifest also contains documentation and the report generator. Keep
    # those files available to runtime-copy detection, but changes to them do not
    # change scan evidence and must not invalidate the content cache.
    foreach ($identity in $script:RuntimeManifestParts) {
        $runtimeName = $identity.Substring(0, $identity.IndexOf('='))
        if ($runtimeName -in @('README.md', 'README.es.md', 'LICENSE', 'docs/SECURITY.md', 'docs/THIRD-PARTY.md', 'docs/THIRD-PARTY.es.md', 'scripts/CsvOutputSafety.ps1', 'tools/review/Export-ScanReviewReports.ps1', 'tools/review/Filter-RecoveryCandidates.ps1', 'tools/review/Verify-Bip39Structure.ps1', 'src/CryptoBip39Inspector.cs', 'CryptoBip39Inspector.dll')) { continue }
        $parts.Add($identity)
    }
    foreach ($name in @('CryptoMnemonicScanner-10.12.dll', 'scripts/Read-PdfWorker.ps1', 'resources/wordlists/bip39-english.txt', 'resources/wordlists/bip39-spanish.txt', 'resources/wordlists/monero-english.txt',
        'resources/wordlists/monero-english-old.txt', 'resources/wordlists/monero-spanish.txt', 'resources/wordlists/slip39-english.txt')) {
        $parts.Add($name + '=' + (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot ($name.Replace('/', [IO.Path]::DirectorySeparatorChar))) -Algorithm SHA256).Hash)
    }
    return [CryptoFileScanner]::TextHash(($parts -join "`n"))
}

function Update-ScanProgress {
    param([switch]$Force)
    if ($NoProgress) { return }
    if (-not $Force -and $script:Timer.ElapsedMilliseconds - $script:LastProgressTime -lt 150) { return }
    $script:LastProgressTime = $script:Timer.ElapsedMilliseconds
    if ($null -ne $script:ScanPool) {
        $parallel = $script:ScanPool.GetSnapshot()
        $script:BytesReadTotal = [long]$parallel.BytesRead
        $script:CurrentFileBytes = [long]$parallel.PendingWork
        $script:CurrentFileWeight = [long]$parallel.PendingWork
        $script:ActiveWorkers = $parallel.Active
        $script:PeakWorkers = $parallel.MaximumActive
    }
    if ($null -ne $script:InventoryWorker) {
        $snapshot = $script:InventoryWorker.GetSnapshot($script:RootIndex)
        $script:RootFilesTotal = [long]$snapshot.RootFiles
        $script:RootWorkTotal = [long]$snapshot.RootWork
        $script:AllWorkTotal = [long]$snapshot.TotalWork
        $script:CompletedRootWork = [long]$snapshot.PriorWork
        $script:RootInventoryReady = $snapshot.RootComplete
        $script:AllInventoryReady = $snapshot.AllComplete
        $script:InventoryFiles = [long]$snapshot.TotalFiles
        $script:InventoryCandidates = [long]$snapshot.TotalCandidates
        $script:InventoryErrors = [long]$snapshot.Errors
    }
    $currentWork = [long]$script:RootWorkDone + [Math]::Min([long]$script:CurrentFileBytes, [long]$script:CurrentFileWeight)
    # PowerShell 5.1 picks Max(Int32, Int32) when the first argument is an untyped 1.
    $rootPercent = -1; $globalPercent = -1
    if ($script:RootInventoryReady) {
        $rootPercent = [int][Math]::Floor(100.0 * $currentWork / [Math]::Max([long]1, [long]$script:RootWorkTotal))
        $rootPercent = [Math]::Max($script:LastRootPercent, [Math]::Min(99, $rootPercent))
        $script:LastRootPercent = $rootPercent
    }
    $doneWork = [long]$script:CompletedRootWork + $currentWork
    if ($script:AllInventoryReady) {
        $globalPercent = [int][Math]::Floor(100.0 * $doneWork / [Math]::Max([long]1, [long]$script:AllWorkTotal))
        $globalPercent = [Math]::Max($script:LastGlobalPercent, [Math]::Min(99, $globalPercent))
        $script:LastGlobalPercent = $globalPercent
    }
    $now = [long]$script:ScanTimer.ElapsedMilliseconds
    $script:RateSamples.Enqueue([pscustomobject]@{ Milliseconds=$now; Bytes=[long]$script:BytesReadTotal })
    while ($script:RateSamples.Count -gt 1 -and $script:RateSamples.Peek().Milliseconds -lt $now - 8000) { [void]$script:RateSamples.Dequeue() }
    $old = $script:RateSamples.Peek()
    $script:AverageReadMBps = $script:BytesReadTotal / 1MB / [Math]::Max(0.001, $script:ScanTimer.Elapsed.TotalSeconds)
    $script:RecentReadMBps = [Math]::Max([long]0, ([long]$script:BytesReadTotal - [long]$old.Bytes)) / 1MB / ([Math]::Max([long]1, ($now - [long]$old.Milliseconds)) / 1000.0)
    $eta = (Get-ScanText 'calculando total')
    if ($script:AllInventoryReady) {
        $eta = (Get-ScanText 'calculando tasa')
        if ($doneWork -gt 0 -and $script:ScanTimer.Elapsed.TotalSeconds -gt 0) {
            $remaining = [Math]::Max([long]0, ([long]$script:AllWorkTotal - $doneWork))
            $seconds = $remaining / ($doneWork / $script:ScanTimer.Elapsed.TotalSeconds)
            $eta = (Get-ScanText '> 365 días')
            if ($seconds -le 31536000) {
                $duration = [TimeSpan]::FromSeconds([Math]::Ceiling($seconds))
                $eta = (Get-ScanText '{0}d {1:00}h {2:00}m {3:00}s aprox.') -f $duration.Days, $duration.Hours, $duration.Minutes, $duration.Seconds
            }
        }
    }
    $script:EstimatedRemaining = $eta
    $globalLabel = if ($globalPercent -lt 0) { (Get-ScanText 'Calculando total mientras se analiza') } else { '{0}%' -f $globalPercent }
    Write-Progress -Id 1 -Activity ((Get-ScanText 'Escaneo global — restante: ') + $eta) -Status ((Get-ScanText 'media: {0:N1} MB/s; reciente: {1:N1} MB/s; {2}') -f $script:AverageReadMBps, $script:RecentReadMBps, $globalLabel) -CurrentOperation ((Get-ScanText 'Inventario: {0} archivos/{1} candidatos; ubicación {2}/{3}; trabajadores: {4}/{5}') -f $script:InventoryFiles, $script:InventoryCandidates, ($script:RootIndex + 1), $resolvedRoots.Count, $script:ActiveWorkers, $script:WorkerCount) -PercentComplete $globalPercent
    $fileTotal = if ($script:RootInventoryReady) { [string]$script:RootFilesTotal } else { '?' }
    Write-Progress -Id 2 -ParentId 1 -Activity ((Get-ScanText 'Escaneando ') + $script:ProgressLabel) -Status ((Get-ScanText 'archivos: {0}/{1}; analizados: {2}; caché: {3}; leídos: {4:N1} MB') -f $script:RootFilesDone, $fileTotal, $script:ContentAnalyzedCount, $script:ContentReusedCount, ($script:BytesReadTotal / 1MB)) -PercentComplete $rootPercent
}

function New-ScanWorkItem {
    param([string]$Path, [CryptoScanItem]$Info, [string[]]$PathEvidence)
    $extension = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $json = $extension -eq '.json' -or $Path -match '(?i)(?:^|[\\/])\.?electrum(?:[\\/]|$)|(?:^|[\\/])default_wallet(?:$|[.])'
    $hexContext = $extension -in @('.key', '.privkey', '.secret') -or
        $Path -match '(?i)(?:^|[\\/._ -])(?:private[\s_-]*key|secret[\s_-]*key|privkey|secretkey|(?:clave|llave)[\s_-]*privada)(?:$|[\\/._ -])'
    $pathId = [CryptoFileScanner]::TextHash($script:StableScanRootKey + '|' + $Path.Substring($script:CurrentScanRoot.Length).ToUpperInvariant())
    $cached = if ($NoCache) { $null } else { $script:Cache.Find($pathId) }
    return [CryptoScanWorkItem]::new($Path, $pathId, $Info, $cached, $json, $hexContext, $PathEvidence)
}

function Complete-ScanResult {
    param([CryptoCompletedScan]$Response)
    $work = $Response.Work
    try {
        $evidence = New-Object 'Collections.Generic.List[string]'
        foreach ($id in $work.PathEvidence) { $evidence.Add($id) }
        if ($Response.Failed) { $script:ContentReadErrorCount++; $evidence.Add('file_read_error') }
        else {
            $result = $Response.Result
            if ($Response.Reused) { $script:ContentReusedCount++ } else { $script:ContentAnalyzedCount++ }
            foreach ($id in $result.Evidence) { $evidence.Add($id) }
            if ($result.Evidence.Length -gt 0 -and (Test-BrowserExtensionStoragePath $work.Path)) { $evidence.Add('browser_extension_storage_with_crypto_terms') }
            $script:MembersScanned += $result.MembersScanned
            $script:MembersSkipped += $result.MembersSkipped
            if ($result.Incomplete) { $script:DocumentIncompleteCount++ }
            elseif (-not $NoCache) {
                $script:Cache.Remember($work.PathId, $result.Sha256, $work.Info.Length, $work.Info.LastWriteTicks,
                    $result.Evidence, $result.MembersScanned, $result.MembersSkipped)
            }
        }
        Add-Finding $work.Path $evidence.ToArray()
    }
    finally {
        $script:RootFilesDone++
        $script:RootWorkDone += 4096L + $work.Info.Length
        $script:ScanPool.Acknowledge($Response)
        if (-not $script:Finishing) { Save-ScanCheckpoint; Update-ScanProgress }
    }
}

function Receive-CompletedScans {
    param([switch]$Wait)
    $response = $script:ScanPool.TakeCompleted($(if ($Wait) { 100 } else { 0 }))
    while ($null -ne $response) {
        Complete-ScanResult $response
        $response = $script:ScanPool.TakeCompleted(0)
    }
    if (-not $script:Finishing) { Update-ScanProgress }
}

function Write-FindingsCsv {
    param([string]$Destination, [string]$Category = '')
    if ($script:RecoveryPhraseSearch) {
        $columns = @('Ubicacion','FechaCreacionUtc','FechaModificacionUtc','Categoria','Razon','Limitacion')
        $sorted = @($script:Findings | Sort-Object Ubicacion,Categoria,Razon | Select-Object -Property $columns)
        $safeRows = @(Protect-SpreadsheetCsvRows -Rows $sorted -Columns $columns)
        $lines = if ($safeRows.Count -gt 0) { @($safeRows | ConvertTo-Csv -NoTypeInformation) } else { @('"Ubicacion","FechaCreacionUtc","FechaModificacionUtc","Categoria","Razon","Limitacion"') }
        $content = [string]::Join([Environment]::NewLine,[string[]]$lines) + [Environment]::NewLine
        return [CryptoFileScanner]::WriteTextIfChanged($Destination,$content)
    }
    $columns = @('Ubicacion','Tipo','FechaCreacionUtc','FechaModificacionUtc')
    $sorted = @($script:Findings | Where-Object { -not $Category -or $_.Categoria -eq $Category } | Sort-Object Ubicacion, Tipo | Select-Object -Property $columns)
    $safeRows = @(Protect-SpreadsheetCsvRows -Rows $sorted -Columns $columns)
    $lines = if ($safeRows.Count -gt 0) { @($safeRows | ConvertTo-Csv -NoTypeInformation) } else { @('"Ubicacion","Tipo","FechaCreacionUtc","FechaModificacionUtc"') }
    $content = [string]::Join([Environment]::NewLine, [string[]]$lines) + [Environment]::NewLine
    return [CryptoFileScanner]::WriteTextIfChanged($Destination, $content)
}

function Save-ScanCheckpoint {
    param([switch]$Force)
    if ($NoCache) { return }
    if (-not $Force -and $script:FileCount - $script:LastCheckpointFiles -lt $CheckpointFiles -and $script:Timer.Elapsed.TotalSeconds - $script:LastCheckpointSeconds -lt $CheckpointSeconds) { return }
    try {
        if ($script:Cache.Checkpoint()) {
            [void](Write-FindingsCsv $partialCsvPath)
            $script:CheckpointCount++
        }
    }
    catch {
        if ($script:CheckpointErrors -eq 0) { Write-Host (Get-ScanText 'No se pudo guardar un avance en la carpeta de salida. El escaneo continúa; revisa el resumen final.') }
        $script:CheckpointErrors++
    }
    $script:LastCheckpointFiles = $script:FileCount
    $script:LastCheckpointSeconds = $script:Timer.Elapsed.TotalSeconds
}

if ($AllDrives -and $null -ne $Root -and $Root.Count -gt 0) { throw (Get-ScanText 'Usa -Root o -AllDrives, no ambos.') }
$interactive = $null -eq $Root -or $Root.Count -eq 0
if ($interactive) {
    if (-not $script:RecoveryPhraseSearch) {
        Write-Host (Get-ScanText '[A] Análisis amplio de indicios')
        Write-Host (Get-ScanText '[R] Búsqueda directa de frases BIP39')
        Write-Host (Get-ScanText '[0] Salir')
        while ($true) {
            $modeChoice = (Read-Host (Get-ScanText 'Selecciona modo: A (análisis normal) o R (búsqueda directa BIP39)')).Trim()
            if ($modeChoice -ieq 'A') { break }
            if ($modeChoice -ieq 'R') {
                if ($PdfOcr) { throw (Get-ScanText 'La búsqueda directa de frases no utiliza OCR; quita -PdfOcr para continuar.') }
                $script:RecoveryPhraseSearch = $true
                $RecoveryPhraseSearch = $true
                [CryptoFileScanner]::Bip39Only = $true
                [CryptoMnemonicScanner]::Bip39Only = $true
                [CryptoMnemonicScanner]::AllowPunctuationSeparators = $true
                [CryptoDocumentScanner]::DirectRecoverySearch = $true
                break
            }
            if ($modeChoice -eq '0') { Write-Host (Get-ScanText 'Cancelado.'); return }
            Write-Host (Get-ScanText 'Opción no válida. Elige A, R o 0.')
        }
    }
    $drives = @(Get-DefaultScanRoots)
    if ($AllDrives) { $Root = $drives; $interactive = $false }
    else {
        Write-Host (Get-ScanText $(if ($script:RecoveryPhraseSearch) { 'Búsqueda directa de frases de recuperación BIP39' } else { 'Escáner de indicios de criptomonedas — lectura de archivos' }))
        if ($script:RecoveryPhraseSearch) { Write-Host (Get-ScanText 'Busca frases BIP39 en archivos compatibles de las ubicaciones seleccionadas. El checksum no confirma titularidad ni fondos.') }
        for ($i = 0; $i -lt $drives.Count; $i++) {
            $details = $drives[$i]
            try {
                $drive = [IO.DriveInfo]::new($drives[$i])
                $label = [Text.RegularExpressions.Regex]::Replace($drive.VolumeLabel, '[\p{Cc}]', '')
                if ([string]::IsNullOrWhiteSpace($label)) { $label = (Get-ScanText 'sin etiqueta') }
                if ($label.Length -gt 40) { $label = $label.Substring(0, 40) }
                $details = (Get-ScanText '{0} {1}; {2:N1} GB totales, {3:N1} GB libres') -f $drives[$i], (Get-SafeFindingPath $label), ($drive.TotalSize / 1GB), ($drive.AvailableFreeSpace / 1GB)
            }
            catch { }
            Write-Host ('[{0}] {1}' -f ($i + 1), $details)
        }
        Write-Host (Get-ScanText '[C] Elegir carpeta o ubicación')
        Write-Host (Get-ScanText '[T] Todas las unidades detectadas')
        Write-Host (Get-ScanText '[0] Salir')
        while ($true) {
            $choice = (Read-Host (Get-ScanText 'Selecciona una opción')).Trim()
            if ($choice -eq '0') { Write-Host (Get-ScanText 'Cancelado.'); return }
            if ($choice -ieq 'C') {
                $location = (Read-Host (Get-ScanText 'Ruta de la carpeta (vacío para volver)')).Trim().Trim('"')
                if ([string]::IsNullOrWhiteSpace($location)) { continue }
                try { [void](Resolve-ScanLocation $location) }
                catch { Write-Host $_.Exception.Message; continue }
                $Root = @($location)
                break
            }
            if ($choice -ieq 'T' -and $drives.Count -gt 0) { $Root = $drives; break }
            [int]$number = 0
            if ([int]::TryParse($choice, [ref]$number) -and $number -ge 1 -and $number -le $drives.Count) { $Root = @($drives[$number - 1]); break }
            Write-Host (Get-ScanText 'Selección no válida. Elige un número, C, T o 0.')
        }
    }
}
if ($null -eq $Root -or $Root.Count -eq 0) { throw (Get-ScanText 'No se seleccionó ninguna ubicación disponible.') }
$resolvedRoots = New-Object 'Collections.Generic.List[string]'
$requestedRoots = @($Root | ForEach-Object {
    Resolve-ScanLocation $_
} | Sort-Object Length)
foreach ($path in $requestedRoots) {
    $covered = $false
    foreach ($parent in $resolvedRoots) { if (Test-InRoot $path $parent) { $covered = $true; break } }
    if (-not $covered) { $resolvedRoots.Add($path) }
}
$rootIdentities = [Collections.Generic.Dictionary[string,CryptoVolumeIdentity]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($path in $resolvedRoots) { $rootIdentities.Add($path, [CryptoWindowsIO]::Identify($path)) }

foreach ($requestedExcludePath in $ExcludePath) {
    if ([string]::IsNullOrWhiteSpace($requestedExcludePath)) { throw (Get-ScanText '-ExcludePath no puede estar vacío.') }
    # PowerShell variable names are case-insensitive: do not reuse the string[] parameter ExcludePath.
    [string]$resolvedExcludePath = (Resolve-ScanLocation $requestedExcludePath).TrimEnd('\', '/')
    $insideRoot = $false
    foreach ($scanRoot in $resolvedRoots) {
        if (Test-InRoot $resolvedExcludePath $scanRoot) {
            if ($resolvedExcludePath.Equals($scanRoot.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
                throw (Get-ScanText '-ExcludePath debe indicar una subcarpeta, no la ubicación completa que se escanea.')
            }
            $insideRoot = $true
            break
        }
    }
    if (-not $insideRoot) { throw ((Get-ScanText 'La ruta excluida debe estar dentro de una ubicación escaneada: ') + $requestedExcludePath) }
    [void]$script:ExcludedDirectoryPaths.Add($resolvedExcludePath)
}

if ($csvPathWasProvided -and [string]::IsNullOrWhiteSpace($CsvPath)) { throw (Get-ScanText '-CsvPath no puede estar vacío.') }
if (-not $csvPathWasProvided) {
    $locationIds = @($resolvedRoots | ForEach-Object { $rootIdentities[$_].LocationKey } | Sort-Object)
    $suffix = 'all-' + [CryptoFileScanner]::TextHash(($locationIds -join '|')).Substring(0, 12)
    if ($resolvedRoots.Count -eq 1) {
        $onlyRoot = $resolvedRoots[0]
        $driveName = [CryptoWindowsIO]::RootPath($onlyRoot).TrimEnd('\', ':') -replace '[^A-Za-z0-9_-]', '_'
        $suffix = $driveName + '-' + $rootIdentities[$onlyRoot].LocationKey.Substring(0, 12)
    }
    $outputPrefix = if ($script:RecoveryPhraseSearch) { 'bip39-recovery-search-' } else { 'crypto-artifact-scan-' }
    $CsvPath = Join-Path $PSScriptRoot ($outputPrefix + $suffix + '.csv')
}
if ($interactive) {
    while ($true) {
        $answer = (Read-Host ((Get-ScanText 'Ruta del CSV (ENTER: ') + (Get-SafeFindingPath $CsvPath) + (Get-ScanText '; 0: salir)'))).Trim().Trim('"')
        if ($answer -eq '0') { Write-Host (Get-ScanText 'Cancelado.'); return }
        $requestedOutput = if ([string]::IsNullOrWhiteSpace($answer)) { $CsvPath } else { $answer }
        try { $resolvedCsvPath = Resolve-OutputPath $requestedOutput; break }
        catch { Write-Host $_.Exception.Message }
    }
}
else { $resolvedCsvPath = Resolve-OutputPath $CsvPath }
$statePath = [IO.Path]::ChangeExtension($resolvedCsvPath, '.scanstate')
$journalPath = [IO.Path]::ChangeExtension($resolvedCsvPath, '.scanjournal')
$partialCsvPath = [IO.Path]::ChangeExtension($resolvedCsvPath, '.partial.csv')
$secondaryCsvPath = [IO.Path]::ChangeExtension($resolvedCsvPath, '.secundarios.csv')
$incidentsCsvPath = [IO.Path]::ChangeExtension($resolvedCsvPath, '.incidencias.csv')
$reviewCsvPath = [IO.Path]::ChangeExtension($resolvedCsvPath, '.revision.csv')
$secondarySummaryCsvPath = [IO.Path]::ChangeExtension($resolvedCsvPath, '.secundarios-resumen.csv')
$coverageSummaryCsvPath = [IO.Path]::ChangeExtension($resolvedCsvPath, '.cobertura-resumen.csv')
$algorithm = Get-AlgorithmFingerprint
$rootIds = @($resolvedRoots | ForEach-Object { $rootIdentities[$_].LocationKey } | Sort-Object)
$rootsFingerprint = [CryptoFileScanner]::TextHash(($rootIds -join '|'))
$script:Cache = if ($NoCache) { $null } else { [CryptoScanCache]::new($statePath, $algorithm, $rootsFingerprint, $script:ContentEvidenceIds, [bool]$Rescan, $journalPath) }
$cacheStatus = if ($NoCache) { (Get-ScanText 'desactivada') } else { $script:Cache.Status }
$consoleSession = Start-ScanConsoleSession
try {
if ($consoleSession.IsConsole -and -not $consoleSession.Protected) {
    Write-Host (Get-ScanText 'No se pudo desactivar la selección automática de consola. Si queda en modo Seleccionar, pulsa Esc.')
}
Write-Host ((Get-ScanText 'Ubicaciones: ') + (($resolvedRoots | ForEach-Object { Get-SafeFindingPath $_ }) -join ', '))
Write-Host ((Get-ScanText 'Resultado: ') + (Get-SafeFindingPath $resolvedCsvPath))
Write-Host ((Get-ScanText 'Detectores {0}; caché: {1}') -f $algorithm.Substring(0, 12), (Get-ScanText $cacheStatus))
if ($script:PdfOcrRuntime.Enabled) { Write-Host ((Get-ScanText 'OCR PDF local activado: texto impreso ({0}); límite {1} páginas y {2} s por PDF') -f $script:PdfOcrRuntime.Languages, $PdfOcrMaxPages, $PdfOcrTimeoutSeconds) }
else { Write-Host (Get-ScanText 'OCR PDF: desactivado (opcional: -PdfOcr; requiere Tesseract y Poppler locales)') }

$script:InventoryWorker = $null
$script:ScanPool = $null
$script:CpuBudget = $null
$script:WorkerCount = 0
$script:ActiveWorkers = 0
$script:PeakWorkers = 0
$script:Finishing = $false
$script:RootInventoryReady = [bool]$NoProgress
$script:AllInventoryReady = [bool]$NoProgress
$script:InventoryFiles = [long]0
$script:InventoryCandidates = [long]0
$script:InventoryErrors = [long]0
$script:RateSamples = New-Object 'Collections.Generic.Queue[object]'
$script:AverageReadMBps = 0.0
$script:RecentReadMBps = 0.0
$script:EstimatedRemaining = (Get-ScanText 'calculando total')
$script:AllWorkTotal = [long]0
$script:LastProgressTime = [long]-1000
$script:LastGlobalPercent = 0
$script:CompletedRootWork = [long]0
$script:ScanTimer = [Diagnostics.Stopwatch]::StartNew()
$csvWritten = $false
$stateWritten = $false
$script:LastCheckpointFiles = [long]0
$script:LastCheckpointSeconds = $script:Timer.Elapsed.TotalSeconds
$finished = $false
try {
    $script:CpuBudget = [CryptoCpuBudget]::new($CpuCorePercent)
    $cpuPlan = $script:CpuBudget.Plan
    $script:WorkerCount = $cpuPlan.GetWorkerCount($Workers)
    $script:ScanPool = [CryptoParallelScanner]::new($script:WorkerCount, $script:MaxContentBytes, (-not $NoCache))
    Write-Host ((Get-ScanText 'CPU: solicitado {0}% de núcleos; asignado {1:N1}% ({2}/{3} físicos); {4}/{5} procesadores lógicos; trabajadores: {6}') -f
        $cpuPlan.RequestedCorePercent, $cpuPlan.EffectiveCorePercent, $cpuPlan.SelectedPhysicalCores,
        $cpuPlan.AvailablePhysicalCores, $cpuPlan.SelectedLogicalProcessors, $cpuPlan.AvailableLogicalProcessors, $script:WorkerCount)
    if ($cpuPlan.MinimumCoreApplied) {
        Write-Host (Get-ScanText 'El porcentaje solicitado equivale a menos de un núcleo; se asignó el mínimo de un núcleo físico.')
    }
    if (-not $NoProgress) {
        $inventoryBrowserPattern = if ($script:RecoveryPhraseSearch) { '(?!)' } else { $script:BrowserProfilePattern }
        $inventoryWalletPathPattern = if ($script:RecoveryPhraseSearch) { '(?!)' } else { $script:WalletContentPathPattern }
        $inventoryContentNamePattern = if ($script:RecoveryPhraseSearch) { '(?!)' } else { $script:ContentNamePattern }
        $inventoryContentExtensions = if ($script:RecoveryPhraseSearch) { $script:RecoveryContentExtensions } else { $script:ContentExtensions }
        $script:InventoryWorker = [CryptoScanInventory]::new([string[]]$resolvedRoots.ToArray(),
            [string[]]$inventoryContentExtensions, [string[]]$script:SkipContentExtensions,
            [string[]]$script:ExcludedDirectoryNames, [string[]]@($script:ExcludedDirectoryPaths),
            [string[]]@($script:ScannerDataFilePaths),
            $script:MaxContentBytes, $script:DotEnvPattern, $inventoryBrowserPattern,
            $inventoryWalletPathPattern, $inventoryContentNamePattern)
    }
    for ($script:RootIndex = 0; $script:RootIndex -lt $resolvedRoots.Count; $script:RootIndex++) {
        $scanRoot = $resolvedRoots[$script:RootIndex]
        $script:CurrentScanRoot = $scanRoot
        $script:StableScanRootKey = $rootIdentities[$scanRoot].LocationKey
        $script:RootFilesDone = [long]0
        $script:RootWorkDone = [long]0
        $script:CurrentFileBytes = [long]0
        $script:CurrentFileWeight = [long]0
        $script:LastRootPercent = 0
        $script:RootFilesTotal = [long]0
        $script:RootWorkTotal = [long]0
        $script:ProgressLabel = Get-SafeFindingPath $scanRoot
        Update-ScanProgress -Force
        $pending = New-Object 'Collections.Generic.Stack[string]'
        $pending.Push($scanRoot)
        while ($pending.Count -gt 0) {
            $directory = $pending.Pop()
            try {
                foreach ($item in [CryptoWindowsIO]::Enumerate($directory)) {
                    $path = $item.FullName
                    $countable = $false
                    $scheduled = $false
                    $script:CurrentFileWeight = [long]0
                    $script:CurrentFileBytes = [long]0
                    try {
                        $attrs = $item.Attributes
                        if (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $script:ReparsePointCount++; continue }
                        $name = [IO.Path]::GetFileName($path)
                        if (($attrs -band [IO.FileAttributes]::Directory) -ne 0) {
                            $normalizedDirectoryPath = [CryptoWindowsIO]::NormalizePath($path).TrimEnd('\')
                            $systemDirectory = $script:ExcludedDirectorySet.Contains($name) -and [CryptoWindowsIO]::IsVolumeRootChild($path)
                            if ($systemDirectory -or $script:ExcludedDirectoryPaths.Contains($normalizedDirectoryPath)) { $script:ExcludedDirectoryCount++; continue }
                            $script:DirectoryCount++
                            Add-Finding $path ([string[]]@(Get-PathEvidence $path $true))
                            $pending.Push($path)
                            continue
                        }
                        if ($script:ScannerDataFilePaths.Contains($path)) { continue }
                        $countable = $true
                        $script:FileCount++
                        $fileEvidence = New-Object 'Collections.Generic.List[string]'
                        foreach ($reason in (Get-PathEvidence $path $false)) { $fileEvidence.Add($reason) }
                        if (-not $script:RecoveryPhraseSearch) {
                            foreach ($formatEvidence in (Get-FileFormatEvidence $path)) { $fileEvidence.Add($formatEvidence) }
                        }
                        if (Test-ContentEligible $path $name) {
                            $info = $item
                            if ($info.Length -gt $script:MaxContentBytes) {
                                $script:OversizeCount++
                                $fileEvidence.Add('file_over_content_limit')
                            }
                            else {
                                $work = New-ScanWorkItem $path $info $fileEvidence.ToArray()
                                while (-not $script:ScanPool.TrySubmit($work)) { Receive-CompletedScans -Wait }
                                $scheduled = $true
                            }
                        }
                        else { $script:SkippedFormatCount++ }
                        if (-not $scheduled) { Add-Finding $path $fileEvidence.ToArray() }
                        Receive-CompletedScans
                    }
                    catch [Management.Automation.PipelineStoppedException] { throw }
                    catch { $script:EnumerationErrorCount++; Add-Finding $path @('item_scan_error') }
                    finally {
                        if ($countable -and -not $scheduled) {
                            $script:RootFilesDone++
                            $script:RootWorkDone += 4096L
                            $script:CurrentFileBytes = 0
                            $script:CurrentFileWeight = 0
                            Save-ScanCheckpoint
                            Update-ScanProgress
                        }
                    }
                }
            }
            catch [Management.Automation.PipelineStoppedException] { throw }
            catch { $script:EnumerationErrorCount++; Add-Finding $directory @('directory_access_error') }
        }
        while ($script:ScanPool.GetSnapshot().Outstanding -gt 0) { Receive-CompletedScans -Wait }
        if (-not $NoProgress) {
            Update-ScanProgress -Force
            $globalPercent = -1
            if ($script:RootIndex -eq $resolvedRoots.Count - 1) { $globalPercent = 100 }
            elseif ($script:AllInventoryReady) {
                $completedWork = [long]$script:CompletedRootWork + [long]$script:RootWorkTotal
                $globalPercent = if ($script:AllWorkTotal -gt 0) { [int][Math]::Floor(100.0 * $completedWork / $script:AllWorkTotal) } else { [int][Math]::Floor(100.0 * ($script:RootIndex + 1) / $resolvedRoots.Count) }
                $globalPercent = [Math]::Max($script:LastGlobalPercent, [Math]::Min(99, $globalPercent))
            }
            if ($globalPercent -ge 0) { $script:LastGlobalPercent = $globalPercent }
            Write-Progress -Id 2 -ParentId 1 -Activity ((Get-ScanText 'Escaneando ') + $script:ProgressLabel) -Status (Get-ScanText 'Ubicación terminada: 100%') -PercentComplete 100
            Write-Progress -Id 1 -Activity (Get-ScanText 'Escaneo global') -Status ((Get-ScanText '{0}/{1} ubicaciones terminadas') -f ($script:RootIndex + 1), $resolvedRoots.Count) -PercentComplete $globalPercent
        }
    }
    if ($script:RecoveryPhraseSearch) {
        $coverageLimit = 'Se examinaron archivos compatibles por extensión, sin filtrar por nombre o carpeta. Extensiones contempladas: ' + ($script:RecoveryContentExtensions -join ', ') +
            '. Límites activos: archivo ' + $MaxContentMB + ' MB, PDF/Office/miembro ' + $MaxDocumentMB + ' MB, expansión ' + $MaxExpandedMB + ' MB; ZIP hasta 10.000 entradas y tres niveles. Sin OCR, descifrado ni corrección de palabras. Los patrones dudosos también pasan checksum BIP39. No se revisan imágenes, archivos Office binarios antiguos, RAR/7z ni formatos no compatibles. Omitidos por formato: ' + $script:SkippedFormatCount +
            '; sobre límite de tamaño: ' + $script:OversizeCount + '; lecturas incompletas: ' + $script:DocumentIncompleteCount +
            '; errores de archivo o recorrido: ' + ($script:EnumerationErrorCount + $script:ContentReadErrorCount) +
            '; errores del inventario: ' + $script:InventoryErrors + '; carpetas excluidas: ' + $script:ExcludedDirectoryCount + '; enlaces omitidos: ' + $script:ReparsePointCount +
            '. Ningún resultado o ausencia de coincidencia confirma titularidad, acceso o saldo.'
        $script:Findings.Add([pscustomobject]@{
            Ubicacion = ''; Categoria = 'cobertura'; Razon = 'resumen_cobertura_del_recorrido'
            FechaCreacionUtc = ''; FechaModificacionUtc = ''; Limitacion = $coverageLimit
        })
        $secondaryCsvWritten = $false
        $incidentsCsvWritten = $false
        $csvWritten = Write-FindingsCsv $resolvedCsvPath
    }
    else {
        $secondaryCsvWritten = Write-FindingsCsv $secondaryCsvPath 'secundarios'
        $incidentsCsvWritten = Write-FindingsCsv $incidentsCsvPath 'incidencias'
        $csvWritten = Write-FindingsCsv $resolvedCsvPath 'principal'
    }
    if (-not $NoCache) {
        $stateWritten = $script:Cache.Save($statePath)
        $script:Cache.Finish()
        if (Test-Path -LiteralPath $partialCsvPath) { Remove-Item -LiteralPath $partialCsvPath }
    }
    $finished = $true
}
finally {
    $script:Finishing = $true
    if ($null -ne $script:ScanPool) {
        $script:ScanPool.Dispose()
        Receive-CompletedScans
        $finalParallel = $script:ScanPool.GetSnapshot()
        $script:BytesReadTotal = [long]$finalParallel.BytesRead
        $script:PeakWorkers = $finalParallel.MaximumActive
        $script:ScanPool = $null
    }
    if (-not $finished) { try { Save-ScanCheckpoint -Force } catch { Write-Host (Get-ScanText 'No se pudo guardar el último avance; se conserva el último checkpoint disponible.') } }
    [CryptoDocumentScanner]::StopWorker()
    if ($null -ne $script:InventoryWorker) { $script:InventoryWorker.Dispose(); $script:InventoryWorker = $null }
    if ($null -ne $script:CpuBudget) { $script:CpuBudget.Dispose() }
    $script:ScanTimer.Stop()
    if (-not $NoProgress) {
        Write-Progress -Id 2 -Activity (Get-ScanText 'Escaneo por ubicación') -Completed
        Write-Progress -Id 1 -Activity (Get-ScanText 'Escaneo global') -Completed
    }
    $script:Timer.Stop()
}
$incidents = $script:EnumerationErrorCount + $script:ContentReadErrorCount + $script:DocumentIncompleteCount
$reviewReport = $null
$reviewReportError = $null
if (-not $script:RecoveryPhraseSearch) {
    Write-Host (Get-ScanText 'El escaneo terminó; generando contexto, resumen secundario y reporte de cobertura...')
    try {
        $reviewScriptPath = Join-Path $PSScriptRoot 'tools/review/Export-ScanReviewReports.ps1'
        if (-not (Test-Path -LiteralPath $reviewScriptPath -PathType Leaf)) { throw (Get-ScanText 'Falta tools/review/Export-ScanReviewReports.ps1 en el paquete.') }
        $reviewReport = & $reviewScriptPath -CsvPath $resolvedCsvPath -Language $Language
    }
    catch {
        $reviewReportError = $_.Exception.Message
        Write-Host ((Get-ScanText 'El escaneo terminó, pero no se pudieron generar las vistas de revisión: ') + $reviewReportError) -ForegroundColor Yellow
    }
}
Write-Host ((Get-ScanText 'Terminado en {0:N2} s; archivos: {1}; analizados: {2}; reutilizados: {3}') -f $script:Timer.Elapsed.TotalSeconds, $script:FileCount, $script:ContentAnalyzedCount, $script:ContentReusedCount)
Write-Host ((Get-ScanText 'Indicios: {0}; incidencias: {1}; sobre el límite: {2}; enlaces omitidos: {3}; leídos: {4:N1} MB') -f $script:Findings.Count, $incidents, $script:OversizeCount, $script:ReparsePointCount, ($script:BytesReadTotal / 1MB))
Write-Host ('CSV: ' + (Get-SafeFindingPath $resolvedCsvPath))
if ($script:RecoveryPhraseSearch) {
    $directMatches = @($script:Findings | Where-Object { $_.Categoria -ne 'cobertura' })
    $directCategories = @($directMatches | Group-Object Categoria | Sort-Object Name | ForEach-Object { '{0}: {1}' -f $_.Name,$_.Count }) -join '; '
    $coverageConsole = if ($Language -eq 'en') {
        'Supported formats were searched regardless of file or folder name. OCR, decryption and spelling correction are off. Unsupported formats: {0}; over size limit: {1}; incomplete reads: {2}; file/traversal errors: {3}; inventory errors: {4}; excluded folders: {5}; links skipped: {6}. Ownership and funds are unknown.' -f $script:SkippedFormatCount,$script:OversizeCount,$script:DocumentIncompleteCount,($script:EnumerationErrorCount+$script:ContentReadErrorCount),$script:InventoryErrors,$script:ExcludedDirectoryCount,$script:ReparsePointCount
    } else { $coverageLimit }
    Write-Host ((Get-ScanText 'Categorías: ') + $directCategories)
    Write-Host ((Get-ScanText 'Cobertura directa: ') + $coverageConsole)
}
else {
    Write-Host ((Get-ScanText 'Indicios secundarios: ') + (Get-SafeFindingPath $secondaryCsvPath))
    Write-Host ((Get-ScanText 'Lecturas pendientes e incidencias: ') + (Get-SafeFindingPath $incidentsCsvPath))
    if ($null -eq $reviewReportError) {
        Write-Host ((Get-ScanText 'Revisión con contexto: ') + (Get-SafeFindingPath $reviewCsvPath))
        Write-Host ((Get-ScanText 'Resumen secundario por archivo: ') + (Get-SafeFindingPath $secondarySummaryCsvPath))
        Write-Host ((Get-ScanText 'Resumen de cobertura: ') + (Get-SafeFindingPath $coverageSummaryCsvPath))
    }
    Write-Host ((Get-ScanText 'Registros principales: {0}; secundarios: {1}; incidencias: {2}') -f @($script:Findings | Where-Object { $_.Categoria -eq 'principal' }).Count, @($script:Findings | Where-Object { $_.Categoria -eq 'secundarios' }).Count, @($script:Findings | Where-Object { $_.Categoria -eq 'incidencias' }).Count)
}
Write-Host ((Get-ScanText 'Cobertura: omitidos por formato/nombre: {0}; carpetas excluidas: {1}; contenido interno analizado: {2}; contenido interno omitido: {3}') -f $script:SkippedFormatCount, $script:ExcludedDirectoryCount, $script:MembersScanned, $script:MembersSkipped)
$script:AverageReadMBps = $script:BytesReadTotal / 1MB / [Math]::Max(0.001, $script:ScanTimer.Elapsed.TotalSeconds)
Write-Host ((Get-ScanText 'Lectura media efectiva: {0:N1} MB/s; incidencias del inventario: {1}') -f $script:AverageReadMBps, $script:InventoryErrors)
Write-Host (Get-ScanText '100% corresponde al recorrido terminado; revisa los archivos omitidos, límites e incidencias del resumen.')
if ($incidents -gt 0) { Write-Host (Get-ScanText 'Hay ubicaciones sin revisar por errores. Consulta las incidencias del CSV y vuelve a ejecutar después de resolver el acceso.') }
if ($PassThru) {
    [pscustomobject]@{
        AlgorithmFingerprint = $algorithm; CacheStatus = $cacheStatus; FilesEnumerated = $script:FileCount
        ContentAnalyzed = $script:ContentAnalyzedCount; ContentReused = $script:ContentReusedCount
        BytesRead = $script:BytesReadTotal; Findings = $script:Findings.Count; Incidents = $incidents
        OversizeFiles = $script:OversizeCount; ReparsePointsSkipped = $script:ReparsePointCount
        ElapsedSeconds = $script:Timer.Elapsed.TotalSeconds; CsvWritten = $csvWritten; StateWritten = $stateWritten
        SecondaryCsvWritten = $secondaryCsvWritten; IncidentsCsvWritten = $incidentsCsvWritten
        ReviewCsvPath = $reviewCsvPath; SecondarySummaryCsvPath = $secondarySummaryCsvPath
        CoverageSummaryCsvPath = $coverageSummaryCsvPath
        ReviewReportsWritten = ($null -ne $reviewReport -and ($reviewReport.RevisionChanged -or $reviewReport.SecondarySummaryChanged -or $reviewReport.CoverageSummaryChanged))
        ReviewReportRows = if ($null -ne $reviewReport) { $reviewReport.RevisionRows } else { 0 }
        SecondarySummaryFiles = if ($null -ne $reviewReport) { $reviewReport.SecondaryFiles } else { 0 }
        CoverageSummaryRows = if ($null -ne $reviewReport) { $reviewReport.CoverageSummaryRows } else { 0 }
        CoverageIncidents = if ($null -ne $reviewReport) { $reviewReport.CoverageIncidents } else { 0 }
        CoverageUniqueLocations = if ($null -ne $reviewReport) { $reviewReport.CoverageUniqueLocations } else { 0 }
        ReviewReportError = $reviewReportError
        PrincipalFindings = @($script:Findings | Where-Object { $_.Categoria -eq 'principal' }).Count
        SecondaryFindings = @($script:Findings | Where-Object { $_.Categoria -eq 'secundarios' }).Count
        CoverageFindings = @($script:Findings | Where-Object { $_.Categoria -eq 'incidencias' }).Count
        SkippedByFormat = $script:SkippedFormatCount; ExcludedDirectories = $script:ExcludedDirectoryCount
        MembersScanned = $script:MembersScanned; MembersSkipped = $script:MembersSkipped
        IncompleteDocuments = $script:DocumentIncompleteCount; Checkpoints = $script:CheckpointCount
        CheckpointErrors = $script:CheckpointErrors
        RecoveredEntries = if ($NoCache) { 0 } else { $script:Cache.RecoveredEntries }
        AverageReadMBps = $script:AverageReadMBps; RecentReadMBps = $script:RecentReadMBps
        InventoryEnabled = (-not [bool]$NoProgress)
        InventoryComplete = (-not $NoProgress -and $script:AllInventoryReady); InventoryErrors = $script:InventoryErrors
        WorkerCount = $script:WorkerCount; PeakWorkers = $script:PeakWorkers
        CpuCorePercent = $cpuPlan.RequestedCorePercent; EffectiveCpuCorePercent = $cpuPlan.EffectiveCorePercent
        MinimumCoreApplied = $cpuPlan.MinimumCoreApplied
        AvailablePhysicalCores = $cpuPlan.AvailablePhysicalCores; AllowedPhysicalCores = $cpuPlan.SelectedPhysicalCores
        AllowedLogicalProcessors = $cpuPlan.SelectedLogicalProcessors; CpuAffinityMask = $cpuPlan.Mask.ToString('X')
        VolumeIds = @($resolvedRoots | ForEach-Object { $rootIdentities[$_].Identifier })
        FileSystems = @($resolvedRoots | ForEach-Object { $rootIdentities[$_].FileSystem })
        Status = if ($incidents -gt 0) { 'recorrido_con_incidencias' } else { 'recorrido_completo' }
    }
}
}
finally {
    # Restore after the final summary and PassThru output, including cancellations.
    $consoleSession.Dispose()
}
