[CmdletBinding()]
param([switch]$SkipCompile)
$buildScript = Join-Path $PSScriptRoot 'tools\Build-Package.ps1'
& $buildScript @PSBoundParameters
