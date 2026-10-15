[CmdletBinding()]
param([string]$SourceDirectory, [string]$OutputAssembly)
$ErrorActionPreference = 'Stop'
$repositoryRoot = if ([string]::IsNullOrWhiteSpace($SourceDirectory)) { Split-Path -Parent $PSScriptRoot } else { $SourceDirectory }
if ([string]::IsNullOrWhiteSpace($OutputAssembly)) { $OutputAssembly = Join-Path $repositoryRoot 'CryptoBip39Inspector.dll' }
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'Compile with Windows PowerShell 5.1.' }
$parserTokens=$null; $parserErrors=$null
[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repositoryRoot 'Verify-Bip39Structure.ps1'),[ref]$parserTokens,[ref]$parserErrors)
if ($parserErrors.Count -gt 0) { throw ('Inspector script syntax error: ' + $parserErrors[0].Message) }
Add-Type -Path (Join-Path (Join-Path $repositoryRoot 'src') 'CryptoBip39Inspector.cs') -OutputAssembly $OutputAssembly -ReferencedAssemblies @('System.dll','System.Core.dll')
