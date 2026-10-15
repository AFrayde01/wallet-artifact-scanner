[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceDirectory,
    [Parameter(Mandatory = $true)][string]$OutputAssembly
)
$buildScript = Join-Path $PSScriptRoot 'tools\Compile-Scanner.ps1'
& $buildScript @PSBoundParameters
