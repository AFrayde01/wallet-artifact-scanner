# Wallet Artifact Scanner

A local, read-only Windows PowerShell utility for finding indicators of cryptocurrency wallets, keys, recovery phrases, and related files on selected drives or folders. English is the default interface; pass `-Language es` for Spanish. The Spanish guide is [README.es.md](README.es.md).

The scanner records file locations, timestamps, indicator types, and coverage limits. It does not export detected phrases, private keys, or document text. Paths can still reveal personal information, so keep reports, caches, and logs private. CSV values that could be interpreted as spreadsheet formulas are escaped.

## Requirements

- Windows with Windows PowerShell 5.1.
- .NET Framework 4.6.2 or later for PDF text extraction.
- Administrator privileges are not required for files the current account can read.
- Optional OCR needs local Tesseract and Poppler installations; the package does not install or include them.

## Run a scan

Extract the complete package ZIP, open PowerShell in its top-level folder, and start the interactive menu:

```powershell
.\Scan-CryptoArtifacts.ps1
```

Choose **A** for a broad artifact scan or **R** for direct BIP39 phrase search. Then choose a detected drive, **C** for a folder, **T** for all detected drives, or **0** to exit. The menu and command-line interface use English by default. The CSV column names and stable detection identifiers remain in Spanish for compatibility.

You can also specify locations directly. Keep the CSV output outside scanned roots when possible:

```powershell
powershell.exe -NoProfile -File .\Scan-CryptoArtifacts.ps1 `
  -Root 'D:\Backups' `
  -CsvPath 'C:\CryptoScan\results.csv' `
  -CpuCorePercent 50
```

For direct BIP39 search, add `-RecoveryPhraseSearch`:

```powershell
powershell.exe -NoProfile -File .\Scan-CryptoArtifacts.ps1 `
  -RecoveryPhraseSearch `
  -Root 'D:\Backups' `
  -CsvPath 'C:\CryptoScan\bip39-results.csv'
```

This mode searches supported files for complete BIP39 sequences in English or Spanish and checks their checksum. It does not use OCR, correct spelling, guess missing words, or decrypt files. A checksum match confirms only a valid BIP39 format; it does not establish ownership, access, or funds.

## Main scan options

| Option | Purpose and default |
| --- | --- |
| `-Root <path[]>` | Scan one or more selected folders or drives. Use this or `-AllDrives`. |
| `-AllDrives` | Select all detected local fixed and removable drives. |
| `-ExcludePath <path[]>` | Exclude subfolders under selected roots. Use it when report output must be inside a scanned root. |
| `-RecoveryPhraseSearch` | Search directly for BIP39 phrases instead of performing the broad artifact scan. OCR is unavailable in this mode. |
| `-CsvPath <path>` | Choose the main CSV destination. The output folder must already exist. |
| `-CpuCorePercent <1–100>` | CPU budget by physical cores; defaults to `50`. |
| `-Workers <0–32>` | Set the worker count. `0` chooses automatically. |
| `-MaxContentMB <1–1024>` | Per-file content limit; defaults to `256` MB. |
| `-MaxDocumentMB <1–256>` | Per-document memory limit; defaults to `32` MB. |
| `-MaxExpandedMB <1–2048>` | Expanded ZIP/Office content limit per container; defaults to `256` MB. |
| `-Rescan` / `-NoCache` | Force detectors to run again, or disable cache and checkpoint recovery for this run. |
| `-IncludeUnvalidatedAddressCandidates` | Keep address-shaped Bitcoin and Monero strings with invalid checksums as lower-confidence secondary candidates. |
| `-PdfOcr` | Enable optional printed-text OCR for PDFs using locally installed Tesseract and Poppler. OCR is off by default. |
| `-PdfOcrDpi`, `-PdfOcrMaxPages`, `-PdfOcrTimeoutSeconds` | Set OCR resolution and page/time limits. Defaults are 150 DPI, 100 pages, and 180 seconds per PDF. `-TesseractPath` and `-PdfToCairoPath` select local executables. |
| `-CheckpointSeconds`, `-CheckpointFiles` | Set journal save intervals; defaults are 60 seconds and 1,000 files. |
| `-NoProgress`, `-PassThru`, `-Language` | Hide progress, return the scan summary, or choose the console language (`en` or `es`). |

When scanning all drives, place reports and their cache in a folder excluded with `-ExcludePath`. The scan output folder must be fully covered by that exclusion. The cache stores hashes, metadata, and detection identifiers, not original paths or matched text.

## Follow-up utilities

These commands are available beside the scanner in both the repository and the extracted package:

| Command | Use |
| --- | --- |
| `Filter-RecoveryCandidates.ps1` | Consolidate one prior report (`-CsvPath`) or a report folder (`-ReportDirectory`), then recheck reported files for BIP39 by default. `-VerificationScope AllReported` rechecks every reported location; `-ReportOnly` filters historical report rows without reopening source files. `-OutputPath` changes the destination. `-CpuCorePercent`, `-MaxContentMB`, `-MaxDocumentMB`, and `-MaxExpandedMB` set the resource limits. |
| `New-ScanReviewReports.ps1` | Rebuild the derived review, priority, secondary-summary, and coverage CSVs from an existing main CSV. It does not reread the scanned files. |
| `Verify-Bip39Structure.ps1` | Recheck BIP39 candidates already listed in reports. It does not inventory drives. Use `-ReportDirectory`, optional `-Recurse`, `-OutputDirectory`, `-CpuCorePercent`, `-MaxTextMB`, `-MaxDocumentMB`, `-MaxExpandedMB`, `-MaxPages`, and the match-count limits. |

These utilities may read files named in a report. Process only reports you trust and keep their outputs private. They do not decrypt wallets or recover deleted files. Review tools do not use OCR.

## Coverage and limitations

The broad scan looks for wallet and recovery names, common cryptocurrency terms, validated phrase/key structures, and other file indicators. It reads supported text, selected database strings, ZIP files (including bounded nested ZIPs), XML-based Office documents, and PDFs with extractable text. PDF text extraction uses the bundled PdfPig reader. Optional OCR can recognize printed text in scanned PDFs with local Tesseract and Poppler; it does not read handwriting.

The included dictionaries support BIP39 in English and Spanish, Monero in English, legacy English, and Spanish, and SLIP39 in English. Other languages and unsupported formats may not be recognized. RAR/7z, legacy binary Office files, deleted-file recovery, unallocated disk space, encrypted wallets/databases, and encrypted or damaged documents are not supported. Files beyond configured limits, inaccessible locations, and documents without extractable text are reported as incomplete coverage; no match does not prove that a location has no recovery material.

Validated addresses are public indicators and remain secondary findings. A recognized key or wallet structure does not prove ownership, use, decryptability, or balance. Windows may update last-access metadata while reading files; use a forensic image or hardware write blocker when strict preservation is required.

## Build and test

Build the distributable from the repository root with Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -File .\Build-Package.ps1
```

The build checks dependency hashes, compiles the scanner assemblies, and writes `dist/windows-crypto-artifact-scan.zip`. If the locked DLLs are missing, restore them first; restoration downloads from NuGet and verifies the package and file hashes:

```powershell
powershell.exe -NoProfile -File .\Restore-Dependencies.ps1
powershell.exe -NoProfile -File .\Build-Package.ps1
```

Run the regression suite after building. Its results go to a temporary directory outside the repository:

```powershell
$results = Join-Path $env:TEMP ('wallet-scanner-regression-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
powershell.exe -NoProfile -File .\tests\Run-Regression.ps1 -ResultDirectory $results
```

The tests create synthetic files and folders; they do not scan real drives or run OCR. `tests/Compare-DetectionSample.ps1` is an optional comparison helper that requires explicit report, sample, root, and output paths. Its output can contain paths and hashes, so keep it private.

## Repository layout

```text
Scan-CryptoArtifacts.ps1, Filter-RecoveryCandidates.ps1, New-ScanReviewReports.ps1, Verify-Bip39Structure.ps1
src/                    C# scanner and inspector sources
scripts/                Internal PowerShell runtime helpers
tools/                  Build, compiler, and dependency restoration scripts
resources/wordlists/    Public mnemonic dictionaries
docs/                   Security and third-party documentation
dependencies/           Locked PDF reader DLLs, hashes, and notices
tests/                  Synthetic regression checks
dist/                   Generated distributable ZIP
```

`Build-Package.ps1`, `Compile-Scanner.ps1`, `Compile-Bip39Inspector.ps1`, and `Restore-Dependencies.ps1` remain at the root as compatibility entry points for their corresponding scripts under `tools/`. The ZIP preserves the same runtime folder layout and includes only the public commands, runtime code, required resources, locked dependencies, and documentation.

See [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md) for component notices and licenses. The project source is licensed under [MIT](LICENSE). For vulnerability reporting, see [docs/SECURITY.md](docs/SECURITY.md).
