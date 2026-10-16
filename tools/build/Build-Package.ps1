[CmdletBinding()]
param([switch]$SkipCompile)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dependencyRoot = Join-Path $repositoryRoot 'dependencies'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$stage = Join-Path $tempRoot ('wallet-scanner-build-' + [guid]::NewGuid().ToString('N'))
$package = Join-Path $stage 'windows-crypto-artifact-scan'
[void][IO.Directory]::CreateDirectory($package)

try {
    $locked = Get-Content -LiteralPath (Join-Path $dependencyRoot 'packages.lock.json') -Raw | ConvertFrom-Json
    foreach ($dependency in $locked) {
        foreach ($file in $dependency.Files) {
            if ($file.File -ne [IO.Path]::GetFileName($file.File) -or $file.File -notmatch '^[A-Za-z0-9.]+\.dll$') {
                throw 'The dependency lock contains an invalid DLL filename.'
            }
            $dependencyPath = Join-Path $dependencyRoot $file.File
            if ((Get-FileHash -LiteralPath $dependencyPath -Algorithm SHA256).Hash -ne $file.Sha256) {
                throw ('Dependency SHA-256 does not match the lock: ' + $file.File)
            }
        }
    }

    if (-not $SkipCompile) {
        $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $scannerAssembly = Join-Path $stage 'CryptoMnemonicScanner-10.12.dll'
        & $windowsPowerShell -NoProfile -File (Join-Path $PSScriptRoot 'Compile-Scanner.ps1') -SourceDirectory $repositoryRoot -OutputAssembly $scannerAssembly
        if ($LASTEXITCODE -ne 0) { throw 'The scanner build failed under Windows PowerShell 5.1.' }
        Copy-Item -LiteralPath $scannerAssembly -Destination (Join-Path $repositoryRoot 'CryptoMnemonicScanner-10.12.dll') -Force

        $inspectorAssembly = Join-Path $stage 'CryptoBip39Inspector.dll'
        & $windowsPowerShell -NoProfile -File (Join-Path $PSScriptRoot 'Compile-Bip39Inspector.ps1') -SourceDirectory $repositoryRoot -OutputAssembly $inspectorAssembly
        if ($LASTEXITCODE -ne 0) { throw 'The BIP39 inspector build failed under Windows PowerShell 5.1.' }
        Copy-Item -LiteralPath $inspectorAssembly -Destination (Join-Path $repositoryRoot 'CryptoBip39Inspector.dll') -Force
    }

    $files = @(
        'README.md', 'README.es.md', 'LICENSE',
        'Scan-CryptoArtifacts.ps1', 'tools/review/Filter-RecoveryCandidates.ps1', 'tools/review/Export-ScanReviewReports.ps1', 'tools/review/Verify-Bip39Structure.ps1',
        'CryptoMnemonicScanner-10.12.dll', 'CryptoBip39Inspector.dll',
        'scripts/CsvOutputSafety.ps1', 'scripts/Read-PdfWorker.ps1',
        'src/CryptoBip39Inspector.cs', 'src/CryptoDocumentScanner.cs', 'src/CryptoEvidenceQuality.cs', 'src/CryptoFileScanner.cs',
        'src/CryptoKeyValidation.cs', 'src/CryptoMnemonicScanner.cs', 'src/CryptoParallelScanner.cs', 'src/CryptoScanInventory.cs', 'src/CryptoWindowsIO.cs',
        'resources/wordlists/bip39-english.txt', 'resources/wordlists/bip39-spanish.txt',
        'resources/wordlists/monero-english-old.txt', 'resources/wordlists/monero-english.txt', 'resources/wordlists/monero-spanish.txt',
        'resources/wordlists/slip39-english.txt',
        'docs/SECURITY.md', 'docs/THIRD-PARTY.md', 'docs/THIRD-PARTY.es.md',
        'dependencies/Microsoft-LICENSE.txt', 'dependencies/Monero-WORDLIST-LICENSE.txt',
        'dependencies/PdfPig-LICENSE.txt', 'dependencies/Trezor-MIT-LICENSE.txt', 'dependencies/packages.lock.json'
    )
    foreach ($dependency in $locked) {
        foreach ($file in $dependency.Files) { $files += ('dependencies/' + $file.File) }
    }

    foreach ($name in $files) {
        $relativePath = $name.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $sourcePath = Join-Path $repositoryRoot $relativePath
        $destinationPath = Join-Path $package $relativePath
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw ('Required package file is missing: ' + $name) }
        $destinationDirectory = Split-Path -Parent $destinationPath
        [void][IO.Directory]::CreateDirectory($destinationDirectory)
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
    }

    $archive = Join-Path $stage 'windows-crypto-artifact-scan-10.12.zip'
    $archiveStream = [IO.File]::Open($archive, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $zip = [IO.Compression.ZipArchive]::new($archiveStream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($name in $files) {
            $relativePath = $name.Replace('/', [IO.Path]::DirectorySeparatorChar)
            $sourcePath = Join-Path $package $relativePath
            $entryName = 'windows-crypto-artifact-scan/' + $name.Replace('\', '/')
            $entry = $zip.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
            $inputStream = [IO.File]::OpenRead($sourcePath)
            $outputStream = $entry.Open()
            try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose() }
        }
    }
    finally { $zip.Dispose(); $archiveStream.Dispose() }
    $dist = Join-Path $repositoryRoot 'dist'
    [void][IO.Directory]::CreateDirectory($dist)
    Copy-Item -LiteralPath $archive -Destination (Join-Path $dist 'windows-crypto-artifact-scan-10.12.zip') -Force
    Copy-Item -LiteralPath $archive -Destination (Join-Path $dist 'windows-crypto-artifact-scan.zip') -Force
    Write-Host ('Package updated: ' + (Join-Path $dist 'windows-crypto-artifact-scan-10.12.zip'))
}
finally {
    $target = [IO.Path]::GetFullPath($stage)
    if (-not $target.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to clean a path outside the temporary build directory.' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
