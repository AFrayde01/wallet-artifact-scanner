[CmdletBinding()]
param()
$buildScript = Join-Path $PSScriptRoot 'tools\Restore-Dependencies.ps1'
& $buildScript
