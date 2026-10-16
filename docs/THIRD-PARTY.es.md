# Bibliotecas incluidas

La lectura PDF usa PdfPig 0.1.16, publicado por UglyToad, con destino .NET Framework 4.6.2. El paquete incluye sus DLL y dependencias Microsoft; no se descargan durante un escaneo.

| Paquete | Versión | Licencia |
| --- | --- | --- |
| PdfPig | 0.1.16 | Apache-2.0 |
| Microsoft.Bcl.HashCode | 6.0.0 | MIT |
| System.Memory | 4.6.0 | MIT |
| System.Buffers | 4.6.0 | MIT |
| System.Numerics.Vectors | 4.6.0 | MIT |
| System.Runtime.CompilerServices.Unsafe | 6.1.0 | MIT |
| System.ValueTuple | 4.5.0 | MIT |

Las licencias y avisos originales se conservan en dependencies/PdfPig-LICENSE.txt y dependencies/Microsoft-LICENSE.txt. Las versiones, SHA-256 de los paquetes oficiales de NuGet y SHA-256 de cada DLL seleccionada están en dependencies/packages.lock.json. tools/build/Restore-Dependencies.ps1 permite restaurar esos mismos bytes en desarrollo, con Internet y validación de hashes.

Fuentes oficiales: [PdfPig](https://github.com/UglyToad/PdfPig), [NuGet](https://www.nuget.org/packages/PdfPig/0.1.16), [paquetes Microsoft](https://github.com/dotnet/maintenance-packages).

## Listas de palabras y datos de referencia

La licencia MIT de este repositorio cubre el código del proyecto. No sustituye ni cambia las licencias de los materiales siguientes, que se distribuyen con sus propios avisos:

| Archivos | Fuente | Licencia y aviso |
| --- | --- | --- |
| `resources/wordlists/bip39-english.txt`, `resources/wordlists/bip39-spanish.txt` | Listas del estándar [BIP-0039](https://github.com/bitcoin/bips/tree/master/bip-0039); la especificación declara licencia MIT. | MIT; ver la sección Copyright de la [especificación](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki). |
| `resources/wordlists/monero-english.txt`, `resources/wordlists/monero-english-old.txt`, `resources/wordlists/monero-spanish.txt` | [Monero mnemonic wordlists](https://github.com/monero-project/monero/tree/master/src/mnemonics). | BSD-3-Clause; copyright y texto completo del aviso en `dependencies/Monero-WORDLIST-LICENSE.txt`. |
| `resources/wordlists/slip39-english.txt` | Lista de palabras de [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039/wordlist.txt). | CC BY-SA 4.0 según el [aviso de SatoshiLabs](https://github.com/satoshilabs/slips/blob/master/LICENSE); se incluye sin modificar. |
| Vectores públicos BIP39 reconocidos por los detectores | [Trezor python-mnemonic vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json). | MIT; aviso de copyright y licencia en `dependencies/Trezor-MIT-LICENSE.txt`. |

Esos materiales son componentes separados: no se ofrecen bajo la licencia MIT del código principal. Al redistribuir el paquete, conserva estos archivos de aviso y las atribuciones correspondientes.

## Motores OCR opcionales externos

El paquete del escáner no contiene motores OCR ni los instala. La opción `-PdfOcr` requiere que el usuario instale Tesseract y Poppler localmente; usa Tesseract para reconocer texto impreso y Poppler `pdftocairo` para renderizar páginas. Sus licencias y avisos son independientes de este repositorio. Consulta [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) y [Poppler](https://poppler.freedesktop.org/).
