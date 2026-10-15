# Third-party components

The PDF reader uses PdfPig 0.1.16 by UglyToad and targets .NET Framework 4.6.2. Its DLLs and Microsoft dependencies are bundled, so scanning does not download packages.

| Package | Version | License |
| --- | --- | --- |
| PdfPig | 0.1.16 | Apache-2.0 |
| Microsoft.Bcl.HashCode | 6.0.0 | MIT |
| System.Memory | 4.6.0 | MIT |
| System.Buffers | 4.6.0 | MIT |
| System.Numerics.Vectors | 4.6.0 | MIT |
| System.Runtime.CompilerServices.Unsafe | 6.1.0 | MIT |
| System.ValueTuple | 4.5.0 | MIT |

The original library notices are in `dependencies/PdfPig-LICENSE.txt` and `dependencies/Microsoft-LICENSE.txt`. Package versions, official NuGet package SHA-256 values, and selected DLL SHA-256 values are recorded in `dependencies/packages.lock.json`. `Restore-Dependencies.ps1` restores those bytes for development and verifies their hashes.

Official sources: [PdfPig](https://github.com/UglyToad/PdfPig), [NuGet](https://www.nuget.org/packages/PdfPig/0.1.16), and [Microsoft maintenance packages](https://github.com/dotnet/maintenance-packages).

## Wordlists and reference data

The MIT license in this repository covers this project's code. It does not replace the separate licenses for the following bundled materials:

| Files | Source | License and notice |
| --- | --- | --- |
| `resources/wordlists/bip39-english.txt`, `resources/wordlists/bip39-spanish.txt` | Wordlists from the [BIP-0039 repository](https://github.com/bitcoin/bips/tree/master/bip-0039); the specification declares MIT. | MIT; see Copyright in the [specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). |
| `resources/wordlists/monero-english.txt`, `resources/wordlists/monero-english-old.txt`, `resources/wordlists/monero-spanish.txt` | [Monero mnemonic wordlists](https://github.com/monero-project/monero/tree/master/src/mnemonics). | BSD-3-Clause; copyright and full notice in `dependencies/Monero-WORDLIST-LICENSE.txt`. |
| `resources/wordlists/slip39-english.txt` | [SLIP-0039 wordlist](https://github.com/satoshilabs/slips/blob/master/slip-0039/wordlist.txt). | CC BY-SA 4.0 under the [SatoshiLabs notice](https://github.com/satoshilabs/slips/blob/master/LICENSE); included without modification. |
| Public BIP39 vectors recognized by the detectors | [Trezor python-mnemonic vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json). | MIT; copyright and license notice in `dependencies/Trezor-MIT-LICENSE.txt`. |

These materials remain separate components and are not relicensed under the project's MIT license. Preserve the notices and attributions when redistributing the package. See [THIRD-PARTY.es.md](THIRD-PARTY.es.md) for Spanish.

## Optional OCR engines

The scanner package does not contain or install OCR engines. The optional `-PdfOcr` switch requires Tesseract and Poppler to be installed locally. Tesseract recognizes printed text; Poppler's `pdftocairo` renders pages. Their licenses and notices are independent of this repository. See [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) and [Poppler](https://poppler.freedesktop.org/).
