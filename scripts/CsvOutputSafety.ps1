$script:CsvOutputMnemonicWords = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$script:CsvOutputWordListRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'resources\wordlists'
$script:CsvOutputWordListFiles = @(
    [pscustomobject]@{ Name = 'bip39-english.txt'; PrefixLength = 0 }
    [pscustomobject]@{ Name = 'bip39-spanish.txt'; PrefixLength = 0 }
    [pscustomobject]@{ Name = 'monero-english.txt'; PrefixLength = 3 }
    [pscustomobject]@{ Name = 'monero-english-old.txt'; PrefixLength = 4 }
    [pscustomobject]@{ Name = 'monero-spanish.txt'; PrefixLength = 4 }
    [pscustomobject]@{ Name = 'slip39-english.txt'; PrefixLength = 0 }
)
foreach ($wordList in $script:CsvOutputWordListFiles) {
    $wordListPath = Join-Path $script:CsvOutputWordListRoot $wordList.Name
    if (-not (Test-Path -LiteralPath $wordListPath -PathType Leaf)) { continue }
    foreach ($word in [IO.File]::ReadAllLines($wordListPath)) {
        $normalizedWord = $word.Trim().Normalize([Text.NormalizationForm]::FormKD).ToLowerInvariant()
        if ($normalizedWord) { [void]$script:CsvOutputMnemonicWords.Add($normalizedWord) }
        if ($wordList.PrefixLength -gt 0 -and $normalizedWord.Length -ge $wordList.PrefixLength) {
            [void]$script:CsvOutputMnemonicWords.Add($normalizedWord.Substring(0, $wordList.PrefixLength))
        }
    }
}

function Protect-SensitiveCsvText {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $safeValue = $Value
    if ($safeValue.Length -ge 40) {
        $safeValue = [Text.RegularExpressions.Regex]::Replace($safeValue, '\[\s*(?:[0-9]{1,3}\s*,\s*){63}[0-9]{1,3}\s*\]', '[SENSITIVE_KEY_ARRAY_REDACTED]')
        $safeValue = [Text.RegularExpressions.Regex]::Replace($safeValue, '(?i)(?<![a-f0-9])[a-f0-9]{64,}(?![a-f0-9])', '[SENSITIVE_KEY_MATERIAL_REDACTED]')
        $tokenPattern = '(?i)(?<![a-z0-9+/=_-])[a-z0-9+/=_-]{40,}(?![a-z0-9+/=_-])'
        $tokenMatches = [Text.RegularExpressions.Regex]::Matches($safeValue, $tokenPattern)
        for ($index = $tokenMatches.Count - 1; $index -ge 0; $index--) {
            $tokenMatch = $tokenMatches[$index]
            # Avoid replacing long natural-language labels and paths. General base64-like
            # material must contain mixed-case letters and digits; hex keys are handled above.
            if ($tokenMatch.Value -cnotmatch '[a-z]' -or $tokenMatch.Value -cnotmatch '[A-Z]' -or $tokenMatch.Value -notmatch '\d') { continue }
            $safeValue = $safeValue.Substring(0, $tokenMatch.Index) + '[SENSITIVE_KEY_MATERIAL_REDACTED]' + $safeValue.Substring($tokenMatch.Index + $tokenMatch.Length)
        }
    }
    if ($safeValue.Length -lt 47) { return $safeValue }

    $wordMatches = [Text.RegularExpressions.Regex]::Matches($safeValue, '[\p{L}\p{M}]+')
    $ranges = [Collections.Generic.List[object]]::new()
    $runStart = -1
    $runEnd = -1
    $runLength = 0
    foreach ($wordMatch in $wordMatches) {
        $word = $wordMatch.Value.Normalize([Text.NormalizationForm]::FormKD).ToLowerInvariant()
        if ($script:CsvOutputMnemonicWords.Contains($word)) {
            if ($runStart -lt 0) { $runStart = $wordMatch.Index }
            $runEnd = $wordMatch.Index + $wordMatch.Length
            $runLength++
            continue
        }
        if ($runLength -ge 12) { $ranges.Add([pscustomobject]@{ Start = $runStart; End = $runEnd }) }
        $runStart = -1
        $runEnd = -1
        $runLength = 0
    }
    if ($runLength -ge 12) { $ranges.Add([pscustomobject]@{ Start = $runStart; End = $runEnd }) }
    for ($index = $ranges.Count - 1; $index -ge 0; $index--) {
        $range = $ranges[$index]
        $safeValue = $safeValue.Substring(0, $range.Start) + '[SENSITIVE_MNEMONIC_REDACTED]' + $safeValue.Substring($range.End)
    }

    return $safeValue
}

function Protect-SpreadsheetCsvCell {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or $Value -isnot [string]) { return $Value }
    $safeValue = Protect-SensitiveCsvText -Value $Value
    if ([Text.RegularExpressions.Regex]::IsMatch(
            $safeValue,
            '^[\p{Cc}\p{Cf}\p{Zs}\p{Zl}\p{Zp}]*[=+\-@]')) {
        return "'" + $safeValue
    }
    return $safeValue
}

function Protect-SpreadsheetCsvRows {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Columns
    )

    foreach ($row in $Rows) {
        $safeRow = [ordered]@{}
        foreach ($column in $Columns) {
            $property = $row.PSObject.Properties[$column]
            $value = if ($null -eq $property) { $null } else { $property.Value }
            $safeRow[$column] = Protect-SpreadsheetCsvCell -Value $value
        }
        [pscustomobject]$safeRow
    }
}
