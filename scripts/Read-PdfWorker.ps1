[CmdletBinding()]
param()

# Dedicated PDF reader. PDF bytes and extracted/OCR text stay in anonymous pipes.
# The OCR path does not create intermediate PDF, image, or text files.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$writer = [IO.BinaryWriter]::new([Console]::OpenStandardOutput())
$pdfOcrEnabled = $env:WALLET_SCANNER_PDF_OCR -eq '1'
$rendererPath = $env:WALLET_SCANNER_PDF_RENDERER
$tesseractPath = $env:WALLET_SCANNER_TESSERACT
$ocrLanguages = $env:WALLET_SCANNER_OCR_LANGUAGES
$ocrDpi = 150
$ocrMaxPages = 100
$ocrTimeoutSeconds = 180
if ($pdfOcrEnabled) {
    if (-not [int]::TryParse($env:WALLET_SCANNER_OCR_DPI, [ref]$ocrDpi) -or
        -not [int]::TryParse($env:WALLET_SCANNER_OCR_MAX_PAGES, [ref]$ocrMaxPages) -or
        -not [int]::TryParse($env:WALLET_SCANNER_OCR_TIMEOUT, [ref]$ocrTimeoutSeconds) -or
        [string]::IsNullOrWhiteSpace($rendererPath) -or [string]::IsNullOrWhiteSpace($tesseractPath) -or
        $ocrLanguages -notmatch '^(?:eng|spa)(?:\+(?:eng|spa))*$') { exit 2 }
}

function Test-OcrPage {
    param($Page)
    $pageArea = [double]$Page.Width * [double]$Page.Height
    if ($pageArea -le 0) { return $false }
    $largestCoverage = 0.0
    $totalCoverage = 0.0
    foreach ($image in $Page.GetImages()) {
        $bounds = $image.Bounds
        $width = [Math]::Abs([double]$bounds.Right - [double]$bounds.Left)
        $height = [Math]::Abs([double]$bounds.Top - [double]$bounds.Bottom)
        $coverage = ($width * $height) / $pageArea
        if ($coverage -gt $largestCoverage) { $largestCoverage = $coverage }
        $totalCoverage = [Math]::Min(2.0, $totalCoverage + $coverage)
    }
    return ($largestCoverage -ge 0.50 -or $totalCoverage -ge 0.75)
}

function Stop-OcrProcess {
    param([Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    try { if (-not $Process.HasExited) { $Process.Kill(); [void]$Process.WaitForExit(2000) } } catch {}
}

function Invoke-PdfPageOcr {
    param([byte[]]$PdfBytes, [int]$PageNumber, [int]$Dpi, [string]$Languages, [int]$TimeoutSeconds)
    $renderer = $null
    $engine = $null
    $copyTask = $null
    try {
        $rendererArgs = '-q -png -singlefile -f ' + $PageNumber + ' -l ' + $PageNumber + ' -r ' + $Dpi + ' -scale-to 2400 - -'
        $renderer = [Diagnostics.Process]::new()
        $renderer.StartInfo = [Diagnostics.ProcessStartInfo]::new()
        $renderer.StartInfo.FileName = $rendererPath
        $renderer.StartInfo.Arguments = $rendererArgs
        $renderer.StartInfo.UseShellExecute = $false
        $renderer.StartInfo.CreateNoWindow = $true
        $renderer.StartInfo.RedirectStandardInput = $true
        $renderer.StartInfo.RedirectStandardOutput = $true
        $renderer.StartInfo.RedirectStandardError = $true
        [void]$renderer.Start()
        $rendererErrors = $renderer.StandardError.ReadToEndAsync()

        $engine = [Diagnostics.Process]::new()
        $engine.StartInfo = [Diagnostics.ProcessStartInfo]::new()
        $engine.StartInfo.FileName = $tesseractPath
        $engine.StartInfo.Arguments = 'stdin stdout -l ' + $Languages + ' --psm 6'
        $engine.StartInfo.UseShellExecute = $false
        $engine.StartInfo.CreateNoWindow = $true
        $engine.StartInfo.RedirectStandardInput = $true
        $engine.StartInfo.RedirectStandardOutput = $true
        $engine.StartInfo.RedirectStandardError = $true
        [void]$engine.Start()
        $engineOutput = $engine.StandardOutput.ReadToEndAsync()
        $engineErrors = $engine.StandardError.ReadToEndAsync()

        # The PDF and PNG move only through process pipes. Nothing is staged on disk.
        $copyTask = $renderer.StandardOutput.BaseStream.CopyToAsync($engine.StandardInput.BaseStream)
        $renderer.StandardInput.BaseStream.Write($PdfBytes, 0, $PdfBytes.Length)
        $renderer.StandardInput.BaseStream.Flush()
        $renderer.StandardInput.Close()
        if (-not $renderer.WaitForExit($TimeoutSeconds * 1000)) { throw [TimeoutException]::new('PDF page render timeout') }
        if (-not $copyTask.Wait($TimeoutSeconds * 1000)) { throw [TimeoutException]::new('PDF image pipe timeout') }
        if ($renderer.ExitCode -ne 0) { throw [IO.InvalidDataException]::new('PDF page render failed') }
        $engine.StandardInput.Close()
        if (-not $engine.WaitForExit($TimeoutSeconds * 1000)) { throw [TimeoutException]::new('OCR page timeout') }
        if (-not $engineOutput.Wait($TimeoutSeconds * 1000) -or -not $engineErrors.Wait($TimeoutSeconds * 1000) -or
            -not $rendererErrors.Wait($TimeoutSeconds * 1000)) { throw [TimeoutException]::new('OCR stream timeout') }
        if ($engine.ExitCode -ne 0) { throw [IO.InvalidDataException]::new('OCR page failed') }
        $text = $engineOutput.Result
        if ($text.Length -gt 1048576) { throw [IO.InvalidDataException]::new('OCR page limit') }
        return $text
    }
    finally {
        Stop-OcrProcess $renderer
        Stop-OcrProcess $engine
        if ($null -ne $renderer) { $renderer.Dispose() }
        if ($null -ne $engine) { $engine.Dispose() }
    }
}

try {
    $dependencyRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'dependencies'
    foreach ($name in @('System.Runtime.CompilerServices.Unsafe','System.Buffers','System.Numerics.Vectors','System.Memory','System.ValueTuple','Microsoft.Bcl.HashCode','UglyToad.PdfPig.Core','UglyToad.PdfPig.Tokens','UglyToad.PdfPig.Tokenization','UglyToad.PdfPig.Fonts','UglyToad.PdfPig','UglyToad.PdfPig.DocumentLayoutAnalysis')) {
        [void][Reflection.Assembly]::LoadFrom((Join-Path $dependencyRoot ($name + '.dll')))
    }
    $reader = [IO.BinaryReader]::new([Console]::OpenStandardInput())
    while ($true) {
        try { $length = $reader.ReadInt32() } catch [IO.EndOfStreamException] { break }
        if ($length -lt 0 -or $length -gt 1GB) { break }
        $bytes = $reader.ReadBytes($length)
        if ($bytes.Length -ne $length) { break }
        $document = $null
        try {
            # Reject encryption markers before the parser can attempt decryption.
            if ([Text.Encoding]::ASCII.GetString($bytes) -match '/Encrypt\b') { $writer.Write([int]-1); $writer.Flush(); continue }
            $options = [UglyToad.PdfPig.ParsingOptions]::new()
            $options.MaxStackDepth = 64
            $options.UseLenientParsing = $false
            $document = [UglyToad.PdfPig.PdfDocument]::Open($bytes, $options)
            if ($document.NumberOfPages -gt 2000) { $writer.Write([int]-3); $writer.Flush(); continue }
            $ocrTimer = [Diagnostics.Stopwatch]::StartNew()
            $ocrPageCount = 0
            $status = 0
            for ($pageNumber = 1; $pageNumber -le $document.NumberOfPages; $pageNumber++) {
                $page = $document.GetPage($pageNumber)
                $text = [UglyToad.PdfPig.DocumentLayoutAnalysis.TextExtractor.ContentOrderTextExtractor]::GetText($page)
                $output = [Text.Encoding]::UTF8.GetBytes($text)
                if ($output.Length -gt 1MB) { throw 'Page limit' }
                $writer.Write([int]1)
                $writer.Write([int]$output.Length)
                $writer.Write([byte[]]$output)
                $writer.Flush()

                if ($pdfOcrEnabled -and $text.Trim().Length -lt 20) {
                    try { $hasPageImage = Test-OcrPage $page }
                    catch { $status = -4; break }
                    if ($hasPageImage) {
                        if ($ocrPageCount -ge $ocrMaxPages) { $status = -5; break }
                        $remaining = $ocrTimeoutSeconds - [int]$ocrTimer.Elapsed.TotalSeconds
                        if ($remaining -le 0) { $status = -3; break }
                        $ocrPageCount++
                        try { $ocrText = Invoke-PdfPageOcr $bytes $pageNumber $ocrDpi $ocrLanguages ([Math]::Min(30, $remaining)) }
                        catch { $status = if ($_.Exception -is [TimeoutException]) { -3 } else { -4 }; break }
                        $ocrOutput = [Text.Encoding]::UTF8.GetBytes($ocrText)
                        if ($ocrOutput.Length -gt 1MB) { $status = -4; break }
                        $writer.Write([int]2)
                        $writer.Write([int]$ocrOutput.Length)
                        $writer.Write([byte[]]$ocrOutput)
                        $writer.Flush()
                    }
                }
            }
            if ($status -lt 0) { $writer.Write([int]$status) } else { $writer.Write([int]0) }
            $writer.Flush()
        }
        catch [OutOfMemoryException] { $writer.Write([int]-3); $writer.Flush() }
        catch { $writer.Write([int]-2); $writer.Flush() }
        finally { if ($null -ne $document) { $document.Dispose() } }
    }
}
catch { try { $writer.Write([int]-2); $writer.Flush() } catch {} }
finally { $writer.Dispose() }
