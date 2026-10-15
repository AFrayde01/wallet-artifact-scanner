[CmdletBinding()]
param([string]$SourceDirectory, [string]$OutputAssembly)
$buildScript = Join-Path $PSScriptRoot 'tools\Compile-Bip39Inspector.ps1'
& $buildScript @PSBoundParameters
