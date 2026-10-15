param([string]$InputRoot, [string]$Csv, [string]$ResultJson, [ValidateRange(1,100)][int]$CpuCorePercent=50, [switch]$Progress)
$ErrorActionPreference = 'Stop'
$scanner = Join-Path (Split-Path $PSScriptRoot -Parent) 'Scan-CryptoArtifacts.ps1'
$summary = & $scanner -Root $InputRoot -CsvPath $Csv -CpuCorePercent $CpuCorePercent -NoProgress:(-not $Progress) -PassThru
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ResultJson -Encoding UTF8
