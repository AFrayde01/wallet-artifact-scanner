[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReportDirectory,
    [string]$OutputDirectory,
    [switch]$Recurse,
    [ValidateSet('en','es')][string]$Language = 'en',
    [ValidateRange(1,100)][int]$CpuCorePercent = 50,
    [ValidateRange(1,256)][int]$MaxTextMB = 32,
    [ValidateRange(1,256)][int]$MaxDocumentMB = 128,
    [ValidateRange(1,2048)][int]$MaxExpandedMB = 256,
    [ValidateRange(1,2000)][int]$MaxPages = 500,
    [ValidateRange(1,1000)][int]$MaxMatchesPerUnit = 100,
    [ValidateRange(1,10000)][int]$MaxMatchesPerFile = 500,
    [ValidateRange(1,200000)][int]$MaxTotalMatches = 50000
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repositoryRoot 'scripts\CsvOutputSafety.ps1')
function Ui([string]$English,[string]$Spanish) { if ($Language -eq 'es') { return $Spanish }; return $English }
function Field($Row,[string]$Name) { $property=$Row.PSObject.Properties[$Name]; if ($null -eq $property) { return '' }; return [string]$property.Value }
function Safe([string]$Value) { return [CryptoBip39Inspector]::SafeLabel($Value) }
function PhysicalPath([string]$Path) {
    $current=$Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if (((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse_path' }
        }
        $parent=[IO.Directory]::GetParent($current); $current=if ($null -eq $parent) { $null } else { $parent.FullName }
    }
}
$folder=[IO.Path]::GetFullPath($ReportDirectory)
if (-not (Test-Path -LiteralPath $folder -PathType Container)) { throw (Ui 'Reports folder not found.' 'No existe la carpeta de reportes.') }
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory=Join-Path $folder 'structural-review' }
$output=[IO.Path]::GetFullPath($OutputDirectory)
if ([StringComparer]::OrdinalIgnoreCase.Equals($folder.TrimEnd('\'),$output.TrimEnd('\'))) { throw (Ui 'Choose a separate output folder.' 'Elige una carpeta de salida diferente de la carpeta de reportes.') }
PhysicalPath $output
$marker=Join-Path $output '.bip39-structural-output'
if ((Test-Path -LiteralPath $output -PathType Container) -and -not (Test-Path -LiteralPath $marker -PathType Leaf) -and @(Get-ChildItem -LiteralPath $output -Force).Count -gt 0) { throw (Ui 'Choose an empty output folder to protect existing reports.' 'Elige una carpeta de salida vacia para proteger los reportes existentes.') }
[void][IO.Directory]::CreateDirectory($output)
PhysicalPath $marker
if (-not (Test-Path -LiteralPath $marker)) { [IO.File]::WriteAllText($marker,'BIP39 structural output v1',[Text.UTF8Encoding]::new($true)) }
$sources=@(Get-ChildItem -LiteralPath $folder -File -Filter '*.csv' -Recurse:$Recurse | Where-Object { -not $_.FullName.StartsWith($output.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) } | Sort-Object FullName)
$locations=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($source in $sources) {
    $header=Get-Content -LiteralPath $source.FullName -TotalCount 1
    if ([string]::IsNullOrWhiteSpace($header)) { continue }
    $schema=@($header,'"schema"') | ConvertFrom-Csv | Select-Object -First 1
    if ($null -eq $schema.PSObject.Properties['Ubicacion']) { continue }
    $typeColumn=$null
    foreach ($column in @('Tipo','Indicadores','Tipos','IndicadoresReportados','IndicadoresActuales')) { if ($null -ne $schema.PSObject.Properties[$column]) { $typeColumn=$column; break } }
    if ($null -eq $typeColumn) { continue }
    Import-Csv -LiteralPath $source.FullName | ForEach-Object {
        if ((Field $_ $typeColumn) -match 'bip39') {
            $path=Field $_ 'Ubicacion'
            if (-not [string]::IsNullOrWhiteSpace($path)) {
                try { $key=[IO.Path]::GetFullPath($path) } catch { $key=$path }
                if (-not $locations.ContainsKey($key)) { $locations[$key]=[pscustomobject]@{ Path=$path; Reports=[Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal); Contexts=[Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal) } }
                [void]$locations[$key].Reports.Add($source.Name)
                $context=Field $_ 'Contexto'; if ($context) { [void]$locations[$key].Contexts.Add($context) }
            }
        }
    }
}
Write-Host ((Ui 'Consolidated BIP39 locations: {0}' 'Ubicaciones BIP39 consolidadas: {0}') -f $locations.Count)
[void][Reflection.Assembly]::LoadFile((Join-Path $repositoryRoot 'CryptoBip39Inspector.dll'))
[void][Reflection.Assembly]::LoadFile((Join-Path $repositoryRoot 'CryptoMnemonicScanner-10.12.dll'))
$sourceRoot=Join-Path $repositoryRoot 'src'
$wordListRoot=Join-Path $repositoryRoot 'resources\wordlists'
$detectorSource=[IO.File]::ReadAllText((Join-Path $sourceRoot 'CryptoMnemonicScanner.cs'))
$exampleSection=[regex]::Match($detectorSource,'PublicBip39Examples\s*=.*?\{(.*?)\};',[Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $exampleSection.Success) { throw 'Public example definitions are missing; extract the complete package.' }
$examples=@([regex]::Matches($exampleSection.Groups[1].Value,'"([0-9a-f]{32,64})"') | ForEach-Object { $_.Groups[1].Value })
[CryptoBip39Inspector]::Configure([IO.File]::ReadAllLines((Join-Path $wordListRoot 'bip39-english.txt')),[IO.File]::ReadAllLines((Join-Path $wordListRoot 'bip39-spanish.txt')),[string[]]$examples)
foreach ($name in @('System.Runtime.CompilerServices.Unsafe','System.Buffers','System.Numerics.Vectors','System.Memory','System.ValueTuple','Microsoft.Bcl.HashCode','UglyToad.PdfPig.Core','UglyToad.PdfPig.Tokens','UglyToad.PdfPig.Tokenization','UglyToad.PdfPig.Fonts','UglyToad.PdfPig','UglyToad.PdfPig.DocumentLayoutAnalysis')) { [void][Reflection.Assembly]::LoadFrom((Join-Path $repositoryRoot ('dependencies\'+$name+'.dll'))) }
Add-Type -AssemblyName System.IO.Compression
$matchRows=[Collections.Generic.List[object]]::new()
$issueRows=[Collections.Generic.List[object]]::new()
$fileRows=[Collections.Generic.List[object]]::new()
$currentContext=''
$fileMatchStart=0
function Issue([string]$Path,[string]$Member,[int]$Page,[string]$Reason) { $issueRows.Add([pscustomobject]@{ Ubicacion=(Safe $Path); MiembroContenedor=(Safe $Member); Pagina=$Page; Motivo=$Reason }) }
function AnalyzeText([string]$Text,[string]$Path,[string]$Member,[int]$Page,[string]$Geometry,[string]$LayoutState,[string]$ExtractionOrder='text') {
    $remaining=[Math]::Min($MaxMatchesPerFile-($matchRows.Count-$fileMatchStart),$MaxTotalMatches-$matchRows.Count)
    if ($remaining -le 0) { Issue $Path $Member $Page 'match_budget_incomplete'; return }
    $inspection=[CryptoBip39Inspector]::Inspect($Text,[Math]::Min($MaxMatchesPerUnit,$remaining))
    if ($inspection.Truncated) { Issue $Path $Member $Page 'match_limit_incomplete' }
    foreach ($candidate in $inspection.Matches) {
        if ($ExtractionOrder -eq 'pdf_geometric_order' -and [CryptoBip39Inspector]::SameSequence($Geometry,$Text,$candidate.Start,$candidate.End)) { continue }
        $concordance=$LayoutState
        if ($LayoutState -eq 'available') { $concordance=if ([CryptoBip39Inspector]::SameSequence($Geometry,$Text,$candidate.Start,$candidate.End)) { 'same_sequence_in_geometric_order' } else { 'layout_disagrees_review_needed' } }
        $classification=if ($candidate.PublicExample) { 'public_example' }
            elseif ($candidate.Structure -in @('continuous_text','numbered_list','comma_list')) {
                if ($concordance -in @('not_applicable','same_sequence_in_geometric_order')) { 'possible_phrase_structure' } else { 'ambiguous_layout' }
            } else { 'weak_pattern' }
        $matchRows.Add([pscustomobject][ordered]@{
            Ubicacion=(Safe $Path); MiembroContenedor=(Safe $Member); Pagina=$Page; Linea=$candidate.Line; Columna=$candidate.Column
            Idioma=$candidate.Language; CantidadPalabras=$candidate.WordCount; ChecksumValido=$true; Estructura=$candidate.Structure; OrdenExtraccion=$ExtractionOrder
            SeparadoresInvalidos=$candidate.InvalidSeparators; PalabrasUnicas=$candidate.UniqueWords; OrdenNumeracion=$candidate.Numbering
            ConcordanciaGeometrica=$concordance; Clasificacion=$classification
            ContextoReportado=(Safe $currentContext)
            Limitacion='Formato y estructura, no titularidad ni saldo. Linea/columna corresponden al texto extraido; un ejemplo publico puede existir junto a otras frases.'
        })
    }
}
function AnalyzePdf([IO.Stream]$Stream,[string]$Path,[string]$Member) {
    if ($Stream.Length -gt [long]$MaxDocumentMB*1MB) { Issue $Path $Member 0 'pdf_size_limit'; return }
    if ([CryptoBip39Inspector]::HasEncryptionMarker($Stream)) { Issue $Path $Member 0 'encrypted_pdf_not_reviewed'; return }
    $document=$null
    $pdfTimer=[Diagnostics.Stopwatch]::StartNew()
    try {
        $options=[UglyToad.PdfPig.ParsingOptions]::new(); $options.MaxStackDepth=64; $options.UseLenientParsing=$false
        $document=[UglyToad.PdfPig.PdfDocument]::Open($Stream,$options)
        if ($document.IsEncrypted) { Issue $Path $Member 0 'encrypted_pdf_not_reviewed'; return }
        $pageCount=[Math]::Min($MaxPages,$document.NumberOfPages)
        for ($pageNumber=1;$pageNumber -le $pageCount;$pageNumber++) {
            if ($matchRows.Count-$fileMatchStart -ge $MaxMatchesPerFile -or $matchRows.Count -ge $MaxTotalMatches) { Issue $Path $Member $pageNumber 'match_budget_incomplete'; break }
            # Limits are checked between parser calls, not a hard parser timeout.
            if ($pdfTimer.Elapsed.TotalSeconds -gt 180 -or [Diagnostics.Process]::GetCurrentProcess().PrivateMemorySize64 -gt 1GB) { Issue $Path $Member $pageNumber 'pdf_resource_limit_incomplete'; break }
            try {
                $page=$document.GetPage($pageNumber)
                $text=[UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor.ContentOrderTextExtractor]::GetText($page)
                if ($text.Length -gt 1MB) { Issue $Path $Member $pageNumber 'page_text_limit'; continue }
                if ([string]::IsNullOrWhiteSpace($text)) { Issue $Path $Member $pageNumber 'page_without_extractable_text_no_ocr'; continue }
                $geometry=''; $layout='unavailable'
                try { $geometry=[CryptoBip39Inspector]::GeometryText($page.Letters,200000); $layout='available' } catch { Issue $Path $Member $pageNumber 'geometry_unavailable' }
                AnalyzeText $text $Path $Member $pageNumber $geometry $layout 'pdf_content_order'
                if ($layout -eq 'available') { AnalyzeText $geometry $Path $Member $pageNumber $text 'available' 'pdf_geometric_order' }
            } catch [Management.Automation.PipelineStoppedException] { throw }
            catch { Issue $Path $Member $pageNumber 'page_read_error' }
        }
        if ($document.NumberOfPages -gt $MaxPages) { Issue $Path $Member 0 'page_limit_incomplete' }
    } catch [Management.Automation.PipelineStoppedException] { throw }
    catch { Issue $Path $Member 0 'pdf_unreadable_or_encrypted' }
    finally { if ($null -ne $document) { $document.Dispose() } }
}
function AnalyzeStream([IO.Stream]$Stream,[string]$Extension,[string]$Path,[string]$Member,[int]$Depth,$Budget) {
    if ($Depth -gt 3) { Issue $Path $Member 0 'container_depth_limit'; return }
    if ($Extension -eq '.pdf') { AnalyzePdf $Stream $Path $Member; return }
    if ($Extension -in @('.zip','.docx','.xlsx','.pptx','.odt','.ods','.odp')) {
        $archive=$null
        try {
            $archive=[IO.Compression.ZipArchive]::new($Stream,[IO.Compression.ZipArchiveMode]::Read,$true)
            foreach ($entry in $archive.Entries) {
                if ($matchRows.Count-$fileMatchStart -ge $MaxMatchesPerFile -or $matchRows.Count -ge $MaxTotalMatches) { Issue $Path $Member 0 'match_budget_incomplete'; break }
                if ($entry.FullName.EndsWith('/')) { continue }
                $Budget.Entries++
                if ($Budget.Entries -gt 10000) { Issue $Path $Member 0 'entry_limit_incomplete'; break }
                $name=if ($Member) { $Member+' :: '+$entry.FullName } else { $entry.FullName }
                $memberExtension=[IO.Path]::GetExtension($entry.FullName).ToLowerInvariant()
                $memberLimit=if ($memberExtension -in @('.pdf','.zip','.docx','.xlsx','.pptx','.odt','.ods','.odp')) { [long]$MaxDocumentMB*1MB } else { [long]$MaxTextMB*1MB }
                if ($entry.Length -gt $memberLimit -or $Budget.Bytes+$entry.Length -gt [long]$MaxExpandedMB*1MB) { Issue $Path $name 0 'expanded_size_limit'; continue }
                $Budget.Bytes+=$entry.Length
                $input=$null; $memory=$null
                try {
                    $input=$entry.Open(); $memory=[CryptoBip39Inspector]::CopyBounded($input,$entry.Length)
                    AnalyzeStream $memory $memberExtension $Path $name ($Depth+1) $Budget
                } catch [Management.Automation.PipelineStoppedException] { throw }
                catch { Issue $Path $name 0 'member_unreadable_or_encrypted' }
                finally { if ($null -ne $input) { $input.Dispose() }; if ($null -ne $memory) { $memory.Dispose() } }
            }
        } catch [Management.Automation.PipelineStoppedException] { throw }
        catch { Issue $Path $Member 0 'container_read_error' }
        finally { if ($null -ne $archive) { $archive.Dispose() } }
        return
    }
    if ($Extension -in @('.rar','.7z','.doc','.xls','.ppt','.jpg','.jpeg','.png','.gif','.bmp','.tif','.tiff','.webp','.mp3','.mp4','.exe','.dll')) { Issue $Path $Member 0 'unsupported_format_no_ocr'; return }
    if ($Stream.Length -gt [long]$MaxTextMB*1MB) { Issue $Path $Member 0 'text_size_limit'; return }
    $reader=[IO.StreamReader]::new($Stream,[Text.Encoding]::UTF8,$true,4096,$true)
    try { $text=$reader.ReadToEnd() } finally { $reader.Dispose() }
    if ($text.IndexOf([char]0) -ge 0) { Issue $Path $Member 0 'binary_or_unrecognized_encoding_review_needed' }
    if ($text.IndexOf([char]0xFFFD) -ge 0) { Issue $Path $Member 0 'encoding_replacement_characters_review_needed' }
    if ($Extension -eq '.xml') {
        $xml=$null; $stringReader=$null
        try {
            $settings=[Xml.XmlReaderSettings]::new(); $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit; $settings.XmlResolver=$null; $settings.MaxCharactersInDocument=[long]$MaxTextMB*1MB
            $stringReader=[IO.StringReader]::new($text); $xml=[Xml.XmlReader]::Create($stringReader,$settings); $builder=[Text.StringBuilder]::new()
            while ($xml.Read()) {
                if ($xml.NodeType -in @([Xml.XmlNodeType]::Text,[Xml.XmlNodeType]::CDATA,[Xml.XmlNodeType]::SignificantWhitespace)) { [void]$builder.Append($xml.Value) }
                elseif ($xml.NodeType -eq [Xml.XmlNodeType]::EndElement -and $xml.LocalName -in @('p','row','si')) { [void]$builder.AppendLine() }
                elseif ($xml.NodeType -eq [Xml.XmlNodeType]::EndElement -and $xml.LocalName -in @('c','tc')) { [void]$builder.Append(' ') }
            }
            $text=$builder.ToString()
        } catch { Issue $Path $Member 0 'xml_text_extraction_failed' }
        finally { if ($null -ne $xml) { $xml.Dispose() }; if ($null -ne $stringReader) { $stringReader.Dispose() } }
    }
    AnalyzeText $text $Path $Member 0 '' 'not_applicable'
}
function WriteReport([string]$Name,[object[]]$Rows,[string[]]$Columns) {
    $selected=@(Protect-SpreadsheetCsvRows -Rows $Rows -Columns $Columns)
    $lines=if ($selected.Count) { @($selected | ConvertTo-Csv -NoTypeInformation) } else { @(($Columns | ForEach-Object { '"'+$_+'"' }) -join ',') }
    $path=Join-Path $output $Name; PhysicalPath $path
    [void][CryptoFileScanner]::WriteTextIfChanged($path,([string]::Join([Environment]::NewLine,[string[]]$lines)+[Environment]::NewLine))
}
$cpu=$null; $processed=0; $completed=$false
try {
    $cpu=[CryptoCpuBudget]::new($CpuCorePercent)
    foreach ($key in @($locations.Keys | Sort-Object)) {
        $currentContext=[string]::Join(' | ',[string[]]@($locations[$key].Contexts))
        $processed++; Write-Progress -Activity (Ui 'Structural BIP39 review' 'Revision estructural BIP39') -Status ('{0}/{1}' -f $processed,$locations.Count) -PercentComplete ([int](100.0*$processed/[Math]::Max(1,$locations.Count)))
        $stream=$null
        $firstMatch=$matchRows.Count; $firstIssue=$issueRows.Count
        $fileMatchStart=$firstMatch
        try {
            if ($matchRows.Count -ge $MaxTotalMatches) { Issue $key '' 0 'global_match_budget_not_reviewed'; continue }
            if ($key -notmatch '^[A-Za-z]:[\\/]' -or $key -match '\[(?:REDACTADO|RUTA SENSIBLE REDACTADA)\]') { Issue $key '' 0 'unresolvable_report_path'; continue }
            PhysicalPath $key
            $before=Get-Item -LiteralPath $key -Force
            if ($before.PSIsContainer) { Issue $key '' 0 'directory_not_scanned'; continue }
            $stream=[IO.FileStream]::new($key,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
            AnalyzeStream $stream ([IO.Path]::GetExtension($key).ToLowerInvariant()) $key '' 0 ([pscustomobject]@{Entries=0;Bytes=[long]0})
            $after=Get-Item -LiteralPath $key -Force
            if ($before.Length -ne $after.Length -or $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) {
                Issue $key '' 0 'changed_during_read'
                for ($i=$firstMatch;$i -lt $matchRows.Count;$i++) { $matchRows[$i].Clasificacion='changed_file_unverified' }
            }
        } catch [Management.Automation.PipelineStoppedException] { throw }
        catch { Issue $key '' 0 'source_unreadable_or_missing' }
        finally {
            if ($null -ne $stream) { $stream.Dispose() }
            $fileRows.Add([pscustomobject]@{ Ubicacion=(Safe $key); Coincidencias=($matchRows.Count-$firstMatch); Incidencias=($issueRows.Count-$firstIssue); Resultado=if ($issueRows.Count -gt $firstIssue) { 'incomplete_or_failed_read' } else { 'reviewed_supported_content' }; ReportesOrigen=[string]::Join(' | ',[string[]]@($locations[$key].Reports)); Limitacion='Sin coincidencia no demuestra ausencia de respaldos; no se uso OCR ni se descifraron datos.' })
        }
        if ($processed%25 -eq 0) { Write-Host ((Ui 'Reviewed {0}/{1}; structural matches: {2}.' 'Revisados {0}/{1}; coincidencias estructurales: {2}.') -f $processed,$locations.Count,$matchRows.Count) }
    }
    $completed=$true
} finally {
    if ($null -ne $cpu) { $cpu.Dispose() }
    Write-Progress -Activity (Ui 'Structural BIP39 review' 'Revision estructural BIP39') -Completed
    $columns=@('Ubicacion','MiembroContenedor','Pagina','Linea','Columna','Idioma','CantidadPalabras','ChecksumValido','Estructura','OrdenExtraccion','SeparadoresInvalidos','PalabrasUnicas','OrdenNumeracion','ConcordanciaGeometrica','Clasificacion','ContextoReportado','Limitacion')
    if ($completed) {
        WriteReport 'coincidencias.csv' $matchRows.ToArray() $columns
        WriteReport 'candidatos-estructurados.csv' @($matchRows | Where-Object { $_.Clasificacion -in @('possible_phrase_structure','ambiguous_layout') }) $columns
        WriteReport 'incidencias.csv' $issueRows.ToArray() @('Ubicacion','MiembroContenedor','Pagina','Motivo')
        WriteReport 'archivos-revisados.csv' $fileRows.ToArray() @('Ubicacion','Coincidencias','Incidencias','Resultado','ReportesOrigen','Limitacion')
        foreach ($partialName in @('coincidencias.partial.csv','incidencias.partial.csv','archivos-revisados.partial.csv')) {
            $partialPath=Join-Path $output $partialName; PhysicalPath $partialPath
            if ([IO.File]::Exists($partialPath)) { [IO.File]::Delete($partialPath) }
        }
    } else {
        WriteReport 'coincidencias.partial.csv' $matchRows.ToArray() $columns
        WriteReport 'incidencias.partial.csv' $issueRows.ToArray() @('Ubicacion','MiembroContenedor','Pagina','Motivo')
        WriteReport 'archivos-revisados.partial.csv' $fileRows.ToArray() @('Ubicacion','Coincidencias','Incidencias','Resultado','ReportesOrigen','Limitacion')
    }
}
Write-Host ((Ui 'Complete. Reports: {0}. No words or private keys were exported.' 'Terminado. Reportes: {0}. No se exportaron palabras ni claves privadas.') -f $output)
