[CmdletBinding()]
param(
    [string]$SourceDirectory,
    [string]$OutputAssembly
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repositoryRoot = if ([string]::IsNullOrWhiteSpace($SourceDirectory)) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { $SourceDirectory }
if ([string]::IsNullOrWhiteSpace($OutputAssembly)) { $OutputAssembly = Join-Path $repositoryRoot 'CryptoMnemonicScanner-10.12.dll' }
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'Compile this component with Windows PowerShell 5.1.' }
$sourceRoot = Join-Path $repositoryRoot 'src'
$sources = @(
    (Join-Path $sourceRoot 'CryptoMnemonicScanner.cs'),
    (Join-Path $sourceRoot 'CryptoFileScanner.cs'),
    (Join-Path $sourceRoot 'CryptoWindowsIO.cs'),
    (Join-Path $sourceRoot 'CryptoKeyValidation.cs'),
    (Join-Path $sourceRoot 'CryptoEvidenceQuality.cs'),
    (Join-Path $sourceRoot 'CryptoDocumentScanner.cs'),
    (Join-Path $sourceRoot 'CryptoScanInventory.cs'),
    (Join-Path $sourceRoot 'CryptoParallelScanner.cs')
)
Add-Type -Path $sources -OutputAssembly $OutputAssembly -ReferencedAssemblies @('System.dll','System.Core.dll','System.Numerics.dll','System.Xml.dll','System.IO.Compression.dll','System.Web.Extensions.dll')
