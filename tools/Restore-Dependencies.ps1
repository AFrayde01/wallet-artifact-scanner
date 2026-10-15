[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$vendor = Join-Path $repositoryRoot 'dependencies'
$lock = Get-Content -LiteralPath (Join-Path $vendor 'packages.lock.json') -Raw | ConvertFrom-Json
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$stage = Join-Path $tempRoot ('wallet-scanner-dependencies-' + [guid]::NewGuid().ToString('D'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    foreach ($package in $lock) {
        if ($package.Package -notmatch '^[a-z0-9.]+$' -or $package.Version -notmatch '^[0-9.]+$') { throw 'Invalid package lock.' }
        $download = Join-Path $stage ($package.Package + '.nupkg')
        $url = 'https://api.nuget.org/v3-flatcontainer/' + $package.Package + '/' + $package.Version + '/' + $package.Package + '.' + $package.Version + '.nupkg'
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $download
        if ((Get-FileHash -LiteralPath $download).Hash -ne $package.PackageSha256) { throw 'Package checksum mismatch.' }
        $archive = [IO.Compression.ZipFile]::OpenRead($download)
        try {
            foreach ($file in $package.Files) {
                if ($file.File -ne [IO.Path]::GetFileName($file.File) -or $file.File -notmatch '^[A-Za-z0-9.]+\.dll$') { throw 'Invalid locked filename.' }
                $entry = $archive.GetEntry($file.Entry)
                if ($null -eq $entry) { throw 'Locked entry missing.' }
                $temporary = Join-Path $stage $file.File
                $inputStream = $entry.Open(); $outputStream = [IO.File]::Create($temporary)
                try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose() }
                if ((Get-FileHash -LiteralPath $temporary).Hash -ne $file.Sha256) { throw 'DLL checksum mismatch.' }
                Copy-Item -LiteralPath $temporary -Destination (Join-Path $vendor $file.File) -Force
            }
        } finally { $archive.Dispose() }
    }
    Write-Host 'Dependencies restored from NuGet and verified with SHA-256.'
}
finally {
    $target = [IO.Path]::GetFullPath($stage)
    if (-not $target.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected cleanup target.' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
