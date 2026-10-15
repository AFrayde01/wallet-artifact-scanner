# Escáner local de artefactos de criptomonedas para Windows

Guía en español. Consulta la [guía en inglés](README.md).

Los avisos de seguridad y licencias están en [docs/SECURITY.md](docs/SECURITY.md) y [docs/THIRD-PARTY.es.md](docs/THIRD-PARTY.es.md).

Busca indicios de wallets, claves, frases y datos relacionados con criptomonedas en discos y respaldos accesibles. Funciona en Windows PowerShell 5.1, sin administrador ni instalación de dependencias.

Los CSV guardan ubicaciones y metadatos, pero no frases ni claves encontradas. Las secuencias parecidas a frases y las cadenas con forma de clave se sustituyen por marcadores; esto puede ocultar parte del nombre de un archivo. Para reducir riesgos al abrir los CSV en una hoja de cálculo, las celdas que podrían interpretarse como fórmulas se exportan con un apóstrofo inicial. Mantén los reportes privados.

## Revisar archivos encontrados a partir de los reportes

`Filter-RecoveryCandidates.ps1` lee los CSV de una carpeta (`-ReportDirectory`) o uno individual (`-CsvPath`), consolida ubicaciones sin distinguir mayúsculas/minúsculas y normaliza separadores de ruta. Reconoce `Tipo`, `Tipos` e `Indicadores`; los resúmenes sin ubicaciones individuales se identifican y no inventan archivos. El CSV de salida de la propia ejecución no se incorpora como entrada.

Por defecto relee los archivos con indicios BIP39, incluidos los fragmentados. `-VerificationScope AllReported` relee todos los archivos reportados, sin filtro por extensión. La consolidación de todos los CSV termina antes de iniciar esa relectura; cada ubicación se abre una sola vez. Abre fuentes únicamente para lectura, usa los lectores de texto/PDF/ZIP/Office del escáner y mantiene OCR desactivado. Registra archivos ausentes, inaccesibles, cambiados durante la lectura, rutas redactadas y límites; no los interpreta como ausencia de evidencia. Las carpetas inaccesibles no se recorren. Los recursos públicos/pruebas previamente identificados también se releen; si vuelven a tener BIP39 se conservan en la auditoría como `bip39_in_public_context`, fuera de la lista principal. No descifra wallets ni recupera archivos borrados.

El detector 10.12 reconoce los 24 vectores públicos de BIP39 publicados por [Trezor](https://github.com/trezor/python-mnemonic/blob/master/vectors.json) por su entropía, sin exportar las palabras. La utilidad usa un modo dedicado a BIP39 para omitir cálculos de Monero, SLIP39 y validaciones ajenas a la frase. Conserva las comprobaciones de longitud, diccionario, checksum, continuidad y calidad de separadores. `public_example_detected` identifica una coincidencia con un ejemplo publicado; `weak_bip39_candidate` conserva fragmentados, repetitivos y diccionarios para revisión. Ningún estado demuestra que una wallet sea personal o tenga fondos.

~~~powershell
.\Filter-RecoveryCandidates.ps1 -ReportDirectory 'D:\wallet-scan-reports' -VerificationScope AllReported -CpuCorePercent 80 -Language es
~~~

La salida en modo carpeta es `recuperacion-bip39-unicos.csv`: una fila por ubicación con BIP39 completo y checksum válido detectado al releer. `CantidadReportes` y `ReportesOrigen` indican de qué CSV procede; una ubicación repetida no genera nuevos casos. `recuperacion-bip39-unicos.verificacion.csv` conserva estados y etiquetas actuales sin frases ni claves; durante la relectura se guarda un avance `.verificacion.partial.csv` cada 250 lecturas. Los estados `bip39_detected_incomplete_read` e `incomplete_read` requieren revisar los límites. Los formatos binarios no compatibles o datos cifrados pueden no revelar texto; un resultado sin BIP39 no garantiza que no haya un respaldo.

`-ReportOnly` permite filtrar sin abrir archivos encontrados: conserva únicamente la etiqueta histórica `frase_bip39_checksum_valido`. Acepta reportes antiguos sin fechas, dejando esas columnas vacías en ese modo. `-OutputPath` cambia el destino. No sobrescribe el CSV de entrada; si el contenido final no cambia, no reescribe la salida. El contexto de software/caché se conserva como advertencia de posibles ejemplos. No confirma titularidad ni saldo.

## Ejecutar el escáner

## Verificar la estructura de candidatos BIP39

`Verify-Bip39Structure.ps1` es una segunda revisión localizada. Consolida todos los CSV de `-ReportDirectory` (y subcarpetas con `-Recurse`), reconoce `Tipo`, `Tipos`, `Indicadores` y las etiquetas de auditoría, y relee una sola vez cada ubicación con indicios BIP39. No hace un inventario nuevo de los discos. El directorio de salida no se incorpora como entrada.

~~~powershell
powershell.exe -NoProfile -File .\Verify-Bip39Structure.ps1 -ReportDirectory 'D:\wallet-scan-reports-backups' -Recurse -OutputDirectory 'D:\wallet-scan-structural-review' -CpuCorePercent 80 -MaxDocumentMB 128 -MaxExpandedMB 512 -Language es
~~~

El inspector independiente comprueba diccionarios inglés/español, 12/15/18/21/24 palabras, checksum, separadores, palabras incrustadas en identificadores, diversidad, secuencias de diccionario y orden de listas numeradas. Detecta los vectores públicos conocidos. No exporta palabras, entropía ni identificadores derivados de una frase.

Para PDF analiza texto existente y compara el orden del contenido con una ordenación por posición de las letras. Puede encontrar candidatos presentes solo en una de esas vistas. La comparación geométrica es una heurística: columnas, texto rotado o tipografía pueden dar discrepancias; `ambiguous_layout` requiere revisión manual y no demuestra un falso positivo. La página es la del documento; línea/columna se refieren al texto extraído, no a coordenadas visuales. No se usa OCR.

Para ZIP y documentos Office/OpenDocument accesibles examina los miembros y extrae texto XML sin permitir DTD ni recursos externos. Los ZIP anidados se limitan a tres niveles y 10,000 miembros por archivo. No descifra documentos ni analiza RAR/7z, Office binario antiguo o imágenes. Las rutas sensibles de miembros se redactan. Los límites de tamaño, páginas, coincidencias y recursos quedan registrados. En PDF los límites de tiempo/memoria se comprueban entre llamadas al parser: no constituyen un timeout estricto de una llamada individual.

| Salida | Contenido |
| --- | --- |
| `candidatos-estructurados.csv` | Coincidencias con estructura compatible y casos con disposición ambigua para revisar; ninguna confirma titularidad ni saldo. |
| `coincidencias.csv` | Todas las coincidencias con checksum válido, incluidas débiles, repetitivas, diccionarios y ejemplos públicos, con localización y motivo. |
| `incidencias.csv` | Fuentes inaccesibles, cifradas, sin texto, formatos no compatibles y límites alcanzados. |
| `archivos-revisados.csv` | Una fila por ubicación revisada con conteos y reportes de origen. No encontrar coincidencias no confirma ausencia de respaldos. |

Si se cancela, intenta conservar resultados parciales con el sufijo `.partial.csv`. No inicia wallets ni modifica fuentes. Los CSV idénticos se conservan sin reescribir. Usa una carpeta de salida diferente, vacía o ya identificada por esta utilidad; no sobreescribe carpetas de reportes ajenos. Por defecto limita a 100 coincidencias por unidad, 500 por archivo y 50,000 por ejecución; alcanzar un límite queda como lectura incompleta y puede ajustarse con `-MaxMatchesPerUnit`, `-MaxMatchesPerFile` y `-MaxTotalMatches`. Extrae el paquete completo para disponer de `CryptoBip39Inspector.dll`, los diccionarios, las definiciones públicas y las dependencias PDF.

## Iniciar el escaneo principal

### Buscar frases BIP39 directamente

`-RecoveryPhraseSearch` busca frases directamente en las raíces seleccionadas. No necesita CSV de escaneos previos y no filtra por el nombre del archivo ni por nombres de carpetas personales. Examina los formatos de texto admitidos, PDF con texto extraíble, ZIP y documentos OOXML/OpenDocument compatibles, dentro de los límites normales. También puedes elegir **R** en el menú; **A** conserva el análisis amplio habitual.

~~~powershell
.\Scan-CryptoArtifacts.ps1 -RecoveryPhraseSearch -Root 'D:\respaldos' -CsvPath 'C:\CryptoScan\busqueda-bip39.csv' -CpuCorePercent 50 -Language en
~~~

El detector busca secuencias completas de 12, 15, 18, 21 o 24 palabras BIP39 en inglés o español, separadas por espacios, saltos de línea, listas numeradas o puntuación, y valida el checksum. No corrige palabras ni intenta adivinar frases con errores. El CSV incluye únicamente ubicación, fechas del archivo, categoría, motivo y limitación. `frase_checksum_valido` identifica formato, `patron_dudoso_checksum_valido` conserva secuencias que también pasan checksum pero tienen estructura débil, `ejemplo_publico` identifica vectores de prueba publicados y `contexto_software_o_pruebas` advierte sobre rutas y extensiones asociadas a software, pruebas o ejemplos. Ese contexto no confirma el contenido del programa ni quién es titular.

El modo no exporta palabras, frases, claves, entropía ni contenido del documento. Un checksum válido confirma únicamente el formato BIP39: no demuestra titularidad, acceso ni fondos. No usa OCR ni descifra fuentes; `-PdfOcr` no se admite en este modo. Las imágenes, PDFs sin texto extraíble, archivos cifrados, Office binario antiguo, RAR/7z, formatos no compatibles y archivos que superen sus límites pueden quedar sin revisar; el CSV incluye un resumen de cobertura y motivos de lecturas incompletas. Una ausencia de coincidencias no confirma que no haya una frase guardada.

La caché y el porcentaje de núcleos se mantienen. El cambio de modo, reglas, lectores, formatos admitidos o límites invalida la huella correspondiente. La barra de progreso y `-CpuCorePercent` usan la misma topología física en cualquier equipo.

La interfaz de terminal usa inglés por defecto (`-Language en`). Para mostrar menú, progreso, mensajes y errores propios de la aplicación en español, agrega `-Language es`:

~~~powershell
.\Scan-CryptoArtifacts.ps1 -Language es
~~~

Los nombres de columnas, identificadores de detección y textos de contexto de los CSV conservan el esquema existente en español para mantener compatibilidad. El idioma de la interfaz no cambia los detectores ni los límites de lectura. Los mensajes propios de Windows pueden aparecer en el idioma del sistema. `New-ScanReviewReports.ps1` también acepta `-Language en|es` para sus mensajes de consola.

Extrae la carpeta completa del ZIP y abre PowerShell en ella:

~~~powershell
.\Scan-CryptoArtifacts.ps1
~~~

El menú permite elegir **A** para el escaneo amplio habitual o **R** para búsqueda BIP39 directa. Después muestra unidades listas con letra, etiqueta y capacidad: puedes seleccionar una unidad, elegir **C** para escribir una carpeta o ubicación, **T** para todas las unidades, o **0** para salir. Luego eliges la ruta del CSV. Una opción o salida inválida permite volver a intentarlo.

Por defecto propone guardar el CSV en la carpeta donde está `Scan-CryptoArtifacts.ps1`, incluso si lo inicias desde otra carpeta o desde CMD. ENTER acepta esa ruta. La caché y los avances se guardan junto al CSV. Si la salida queda dentro de una ubicación analizada, el programa la admite solo cuando toda esa carpeta está indicada en `-ExcludePath`; así el recorrido no lee los reportes que va generando.

La carpeta de salida debe existir. Por defecto mantenla **fuera de las ubicaciones analizadas**. Si necesitas incluir todos los discos y guardar los resultados en uno de ellos, indica la carpeta completa con `-ExcludePath`; todos los CSV, la caché y los avances deben quedar dentro de esa carpeta. El programa rechaza las salidas que entren parcialmente en la exclusión o no estén cubiertas por ella, y rechaza enlaces/junctions tanto en las raíces como en las salidas.

Antes de escanear valida también las rutas de todos los reportes derivados. Los reportes se sustituyen mediante archivos temporales en la carpeta de salida: si un CSV anterior fuera un enlace duro a otro archivo, la actualización sustituye el enlace sin modificar los bytes del otro archivo. Los resultados sin cambios conservan sus bytes y fecha de modificación.

El nombre propuesto incluye letra e identificador de ubicación. Este identificador combina la identidad del volumen y la carpeta relativa: dos discos que Windows asigne como `E:` no comparten el resultado predeterminado. Una carpeta diferente también obtiene otro identificador. Puedes cambiar el nombre en el menú; si eliges manualmente el mismo CSV para otro disco, lo sustituirás. En recursos de red se usa el nombre compartido y su serial, sin afirmar identidad del disco físico remoto.

Para ejecutar directamente sin menú:

~~~powershell
.\Scan-CryptoArtifacts.ps1 -Root 'E:\' -CsvPath 'C:\CryptoScan\disco-E.csv'
.\Scan-CryptoArtifacts.ps1 -Root 'E:\respaldos' -CsvPath 'C:\CryptoScan\respaldos.csv'
~~~

También admite varias raíces. Las ubicaciones repetidas o contenidas en otra raíz se recorren una sola vez:

~~~powershell
.\Scan-CryptoArtifacts.ps1 -Root @('E:\', 'F:\') -CsvPath 'C:\CryptoScan\resultado.csv'
~~~

`-ExcludePath` permite omitir subcarpetas exactas dentro de las raíces seleccionadas. Se pasa al ejecutar, no depende de nombres de carpetas fijados en el código, y forma parte de la firma de caché:

~~~powershell
.\Scan-CryptoArtifacts.ps1 -Root 'G:\' -CsvPath 'D:\CryptoScan\disco-G.csv' -ExcludePath 'G:\CryptoScan\reportes-previos'
~~~

`-AllDrives` selecciona todas las unidades locales listas de tipo fijo o extraíble. Si la carpeta de reportes está en una de esas unidades, exclúyela explícitamente junto con el CSV:

~~~powershell
.\Scan-CryptoArtifacts.ps1 -AllDrives -CsvPath 'D:\CryptoScan\reportes\todos.csv' -ExcludePath 'D:\CryptoScan\reportes'
~~~

Para mantener resultados separados por disco, selecciona cada disco en el menú con su propio CSV.

## Progreso y rendimiento

Durante el escaneo se desactiva temporalmente la selección automática con el ratón (QuickEdit) de la consola clásica y se restaura después de mostrar el resumen final. Así se previene que un clic deje bloqueada la salida y parezca que el programa está esperando. No cambia preferencias de Windows ni el algoritmo de detección. Si la ventana ya estaba en modo “Seleccionar” antes de ejecutar el programa, pulsa Esc para salir de ese modo. Cuando se inicia mediante CMD con /k, la consola permanece abierta al terminar y queda en el prompt; el escáner ya finalizó.

El ajuste pasó diez comprobaciones de consola, incluida una consola independiente oculta para verificar aplicación/restauración del modo y restauración tras excepciones. La prueba de actualización confirma que conserva la huella de los detectores, reutiliza la caché y mantiene bytes y fechas del CSV/estado. También se repitieron 123 comprobaciones funcionales, 14 de progreso y siete de lectura durante inventario. Para ejecutar la prueba adicional en Windows PowerShell 5.1: powershell.exe -NoProfile -File .\tests\Test-ConsoleSession.ps1. No usa archivos personales como entrada.

El análisis empieza mientras un trabajador de metadatos calcula el inventario en paralelo. El inventario conserva contadores por ubicación y sus carpetas pendientes; no acumula una lista de todos los archivos ni abre su contenido. Varios trabajadores C# analizan archivos independientes mediante una cola acotada. Un único coordinador agrega los indicios y escribe CSV, journal y caché; el orden de finalización no cambia sus bytes.

**-CpuCorePercent** define el porcentaje de núcleos físicos disponibles que puede usar el escáner, de 1 a 100, con **50% por defecto**. Consulta la topología de cada computadora y calcula automáticamente el número de núcleos como el porcentaje indicado, redondeado hacia abajo. Aplica y verifica la afinidad de todo el proceso antes de iniciar lectores o inventario; también incluye los procesadores lógicos de esos núcleos cuando existe SMT. Con 50%, un equipo de 8 núcleos físicos utiliza 4 y uno de 16 utiliza 8. Inventario, recolector de memoria y lector PDF comparten la asignación. Windows documenta la [herencia de afinidad por procesos auxiliares](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessaffinitymask). Al terminar se restaura la afinidad original de la sesión.

La asignación mínima es un núcleo físico. En un equipo de un núcleo, o cuando el porcentaje equivale a menos de uno, ese mínimo supera el porcentaje solicitado: la terminal lo indica y muestra tanto el porcentaje solicitado como el realmente asignado. En equipos con un número impar de núcleos, el redondeo puede asignar menos del porcentaje solicitado. Este parámetro limita los núcleos donde se ejecuta el proceso; el uso de CPU que muestra Windows depende del trabajo y del disco.

~~~powershell
.\Scan-CryptoArtifacts.ps1 -CpuCorePercent 50
.\Scan-CryptoArtifacts.ps1 -CpuCorePercent 75
~~~

Por defecto, el número de trabajadores es la cantidad de núcleos físicos permitidos, con un máximo de 32. **-Workers**, de 0 a 32 (0 significa automático), permite reducirlo; una solicitud válida mayor que los núcleos asignados se limita automáticamente y mantiene la afinidad de CPU. Por ejemplo, **-Workers 1** analiza un solo archivo a la vez conservando la asignación. Cambiar únicamente el porcentaje o el número de trabajadores conserva la caché y los resultados idempotentes.

La cola admite hasta dos archivos pendientes por trabajador y limita conjuntamente archivos en cola, activos y resultados todavía sin consumir a tres por trabajador. Cada trabajador reutiliza sus buffers. La terminal informa trabajadores activos/permitidos y suma los bytes de todos los lectores sin contarlos dos veces. La cancelación detiene los trabajadores antes de guardar los avances completos y cerrar los auxiliares.

Esta versión admite desde un núcleo físico y requiere un único grupo de procesadores de Windows, de hasta 64 procesadores lógicos. Los equipos con varios grupos de procesadores todavía requieren adaptar la afinidad a esos grupos. Si Windows no permite aplicar o verificar la asignación, el escaneo se detiene antes de leer contenido.

Mientras el total es desconocido, la terminal muestra “Calculando total mientras se analiza”, archivos enumerados/candidatos, archivos ya analizados o reutilizados y bytes leídos. El porcentaje de cada ubicación aparece cuando termina su inventario; la barra global aparece cuando se conocen los totales de todas las ubicaciones. Ambas incorporan el trabajo ya realizado y terminan al 100% cuando acaba el recorrido. Si el análisis acaba antes que el inventario, se cancela el inventario pendiente y se muestra el recorrido terminado.

El estado incluye **velocidad media**, **velocidad reciente** sobre una ventana de hasta ocho segundos y **tiempo restante aproximado**. Son tasas efectivas de bytes leídos durante la lectura, verificación y análisis; no miden la velocidad bruta del hardware. La estimación usa la tasa media del trabajo ponderado por bytes y archivos y comienza cuando existe un total conocido y trabajo procesado. Antes indica “calculando total” o “calculando tasa”. Puede variar con archivos grandes, documentos, errores o datos que cambien.

### OCR local opcional para PDFs escaneados

El OCR está **desactivado por defecto**. Para activarlo instala localmente Tesseract y Poppler con `pdftocairo.exe`, y ejecuta el escáner con `-PdfOcr`. Si el runtime está instalado en `dependencies\ocr\Library\bin`, el escáner encuentra los ejecutables y los modelos `share\tessdata` por sí solo; para otras ubicaciones también puedes indicar `-TesseractPath` y `-PdfToCairoPath`. Tesseract debe tener disponible al menos uno de los modelos `eng` o `spa`; si existen ambos, se usan juntos.

~~~powershell
.\Scan-CryptoArtifacts.ps1 -PdfOcr
.\Scan-CryptoArtifacts.ps1 -Root 'E:\' -CsvPath 'C:\CryptoScan\disco-E.csv' -PdfOcr -PdfOcrMaxPages 100 -PdfOcrTimeoutSeconds 180
.\Scan-CryptoArtifacts.ps1 -PdfOcr -TesseractPath 'C:\Program Files\Tesseract-OCR\tesseract.exe' -PdfToCairoPath 'C:\Tools\poppler\Library\bin\pdftocairo.exe'
~~~

Solo intenta OCR en páginas con menos de 20 caracteres extraíbles y con imágenes que cubren al menos la mitad de la página (o varias imágenes que cubren tres cuartas partes). Usa texto impreso; no está diseñado para escritura a mano. Render y texto pasan por tuberías locales en memoria; no se crean PDF, PNG ni archivos de texto temporales y el texto reconocido nunca se guarda en los CSV, la caché o la consola. Cada PDF tiene un máximo predeterminado de 100 páginas para OCR, 180 segundos y resolución de 150 DPI; puedes ajustar límites con `-PdfOcrMaxPages`, `-PdfOcrTimeoutSeconds` y `-PdfOcrDpi`. Los límites o fallos aparecen en el CSV de incidencias. Un resultado OCR se informa solo como `indicador_criptografico_candidato_por_ocr`, en secundarios y con confianza baja: puede contener errores de reconocimiento y requiere revisar el PDF original. El OCR no confirma que exista una wallet ni identifica página o contenido.

Al activar, desactivar o cambiar el motor, modelos o límites OCR, la huella del algoritmo cambia y se reanalizan los candidatos, incluidos los PDFs antes marcados sin texto extraíble. Las versiones y hashes de `pdftocairo`, Tesseract y los modelos de idioma se incorporan a esa huella para no reutilizar detecciones obtenidas con otra configuración.

El porcentaje combina bytes de contenido candidato y archivos recorridos; avanza durante la lectura de un archivo grande. Si los archivos cambian durante la ejecución o el inventario tiene errores, el total es una estimación; 100% significa que terminó el recorrido. Los errores de acceso/lectura y los contadores de inventario se indican aparte. Dos recorridos concurrentes de metadatos/lectura pueden competir por el disco; este flujo reduce la espera inicial sin prometer mayor velocidad de lectura física.

Cada archivo se lee secuencialmente en bloques de 1 MB, con buffers reutilizados y detección en el componente C#. Varios archivos se pueden leer y analizar al mismo tiempo. Mantiene correctamente caracteres UTF-8/UTF-16 que cruzan bloques; reconoce también UTF-32 con BOM. Los candidatos grandes no se cargan completos en memoria. La caché y los resultados sí requieren memoria proporcional al número de archivos candidatos y hallazgos. La mejora de tiempo depende del contenido y del almacenamiento; varios lectores pueden competir por un mismo disco.

La enumeración, consulta de metadatos y apertura de archivos usan las API Unicode de Windows con rutas extendidas. No cambian el registro ni la configuración del sistema para admitir rutas largas.

Para omitir las barras y el inventario paralelo, usando un solo recorrido de directorios:

~~~powershell
.\Scan-CryptoArtifacts.ps1 -Root 'E:\' -CsvPath 'C:\CryptoScan\disco-E.csv' -NoProgress
~~~

## Repetir y actualizar detectores

Junto al CSV se guarda una caché binaria `.scanstate`. Contiene identificadores SHA-256 de rutas y contenido, tamaño, fecha y tipos de indicio; no contiene rutas originales, texto coincidente, claves ni frases.

- Con la misma ubicación, configuración, detectores y bytes, reutiliza las detecciones anteriores. Verifica SHA-256 incluso si tamaño y fecha siguen iguales, para no pasar por alto cambios de contenido. La repetición todavía lee los archivos candidatos, pero evita ejecutar sus detectores otra vez.
- Los archivos nuevos o modificados se analizan. Los archivos eliminados dejan de aparecer en el resultado. Los errores no se guardan como resultados negativos y se vuelven a intentar.
- Cambiar el DLL, las reglas, las listas, la lógica de lectura/elegibilidad o el límite de tamaño invalida automáticamente la caché mediante una huella del algoritmo. Todos los candidatos de esa ubicación vuelven a analizarse, incluidos los que antes no tenían indicios.
- Al cambiar el DLL, abre una nueva sesión de PowerShell. El escáner rechaza usar el paquete actualizado si esa sesión ya cargó un componente diferente; PowerShell mantiene esos componentes en memoria durante toda la sesión.
- Una caché ausente, dañada o incompatible provoca un análisis completo. No impide escanear.
- CSV y caché se ordenan de forma estable. Si sus bytes son idénticos, no se vuelven a escribir ni cambian sus fechas. Si cambian, se preparan archivos temporales en la carpeta de salida y se sustituyen allí. Si falla la instalación del nuevo archivo, se intenta restaurar el anterior. Una terminación abrupta durante esos renombrados puede dejar el anterior como `.backup.tmp` en la carpeta de salida; la sustitución no es una transacción entre CSV y caché.

Para forzar todos los detectores aunque exista una caché válida:

~~~powershell
.\Scan-CryptoArtifacts.ps1 -Root 'E:\' -CsvPath 'C:\CryptoScan\disco-E.csv' -Rescan
~~~

Para ignorar la caché y crear/actualizar únicamente el CSV:

~~~powershell
.\Scan-CryptoArtifacts.ps1 -Root 'E:\' -CsvPath 'C:\CryptoScan\disco-E.csv' -NoCache
~~~

Mantén el mismo CSV para repetir una ubicación. `-NoCache` no borra una caché existente; simplemente la ignora.

Por defecto, las direcciones Bitcoin y Monero solo se registran cuando pasan su checksum. Para incluir también cadenas con formato aparente pero checksum inválido (útil si se buscan datos truncados o dañados, con más ruido), agrega `-IncludeUnvalidatedAddressCandidates`; quedan en secundarios. Cambiar esta opción invalida la caché para que los resultados se reconstruyan con la misma política.

## Recuperación de avances

Con caché habilitada se guarda un journal `.scanjournal` al terminar un archivo, cuando han pasado 60 segundos o se han recorrido 1,000 archivos desde el último intento de guardado. También se intenta guardar al salir por una interrupción controlada. Puedes ajustar `-CheckpointSeconds` y `-CheckpointFiles`.

El journal contiene hashes, metadatos y tipos; cada registro lleva una comprobación SHA-256. Si el proceso termina abruptamente, la próxima ejecución con la misma ubicación, configuración y CSV recupera los registros completos e ignora un último registro truncado. Verifica otra vez el SHA-256 del contenido antes de reutilizar una detección. El archivo que estaba leyendo deberá revisarse de nuevo.

Junto al journal aparece `nombre.partial.csv`, con los indicios encontrados hasta el último checkpoint. El CSV final anterior se conserva mientras se escanea. Al terminar y guardar el nuevo CSV y estado, se eliminan journal y CSV parcial. Los avances son temporales; guárdalos fuera de las ubicaciones analizadas o dentro de una carpeta cubierta por `-ExcludePath`. `-NoCache` deshabilita esta recuperación.

Si cambia el algoritmo, configuración o ubicación, los avances anteriores no se reutilizan. Una desconexión que permita terminar el recorrido aparece como incidencia en el CSV y el resumen; después de reconectar, vuelve a ejecutar con el mismo resultado para revisar los errores.

## Lectura y resultado

Abre los archivos de origen solo para lectura y no descifra, inicia ni modifica wallets. No ejecuta los archivos encontrados ni consulta fondos. El escaneo no compila código ni se conecta a Internet. Conserva todos los archivos y la carpeta `dependencies` al extraer el paquete.

Los CSV principal, secundario, de incidencias y parcial contienen `Ubicacion`, `Tipo`, `FechaCreacionUtc` y `FechaModificacionUtc`. Las fechas son metadatos del sistema de archivos, capturados al registrar el hallazgo en formato ISO 8601 UTC (sufijo `Z`); no indican cuándo se creó una wallet. Una copia o restauración puede cambiar estos metadatos. Para contenido dentro de un comprimido se usan las fechas del contenedor. Si no se pueden consultar, las celdas quedan vacías. Nunca copia contenido coincidente. Si un nombre o ruta contiene una clave, dirección o frase reconocida, redacta ese dato. Las rutas restantes pueden contener nombres personales; conserva la salida en privado.

Las vistas de revisión, prioritarios y resumen secundario por archivo también conservan ambas fechas. El generador sigue aceptando reportes anteriores de dos columnas y deja sus fechas vacías; no relee los archivos de origen para reconstruir metadatos históricos. Los resúmenes agregados por indicador o cobertura no tienen fechas por archivo.

La versión de detectores **10.12** produce las siguientes salidas junto a la caché:

| Archivo | Contenido |
| --- | --- |
| `nombre.csv` | Hallazgos que el detector prioriza por formato: frases con checksum, claves privadas WIF/extendidas validadas, pares Solana verificados y estructuras reconocidas de keystore/wallet, incluidas Ethereum, Electrum y Bitcoin Core. La vista de revisión puede bajar su confianza según el contexto de la ruta. |
| `nombre.secundarios.csv` | Direcciones públicas validadas, menciones, nombres ambiguos como Wallet/atomic/Trust, recursos de interfaz, coincidencias de formato sin validar, frases fragmentadas/repetitivas, diccionarios, copias verificadas del detector y candidatos en código, software, cachés o historial de Codex. Las cadenas Bitcoin/Monero con checksum inválido solo se incluyen con `-IncludeUnvalidatedAddressCandidates`. Se conservan para revisión. |
| `nombre.incidencias.csv` | Errores de acceso/lectura, documentos cifrados, sin texto extraíble y límites que impidieron completar una lectura. |
| `nombre.revision.csv` | Vista de revisión con ubicación, categoría, tipo, confianza cualitativa y contexto inferido solo del tipo de hallazgo y la ruta. No contiene llaves ni texto detectado. |
| `nombre.prioritarios.csv` | Señales de confianza alta y media para revisar primero. Los formatos WIF/xprv sin checksum validado y los indicios hallados en pruebas del escáner quedan en confianza baja; las frases con checksum dentro de software instalado o dependencias pasan a confianza media. |
| `nombre.secundarios-resumen.csv` | Una fila por ubicación secundaria, con cantidad y tipos de señales para reducir el volumen del CSV detallado. |
| `nombre.secundarios-indicadores-resumen.csv` | Conteos de ubicaciones por tipo, confianza y contexto de ruta; permite dimensionar el ruido sin recorrer miles de filas. |
| `nombre.cobertura-resumen.csv` | Conteos de incidencias por tipo y ubicaciones únicas, clasificados como reintentables, errores de extracción/análisis, límites operativos o contenido no extraíble automáticamente. No contiene rutas. |

La lista principal requiere contenido validado: claves privadas con checksum/rango, frases con checksum o estructuras reconocidas. Un nombre como `keystore.json`, una extensión como `.wallet` o una carpeta de software de wallet, sin contenido validado, queda en secundarios. Esto evita tratar nombres de prueba o archivos vacíos como una detección prioritaria; **un registro secundario también puede contener información real**. La lista principal no confirma titularidad, uso ni saldo. Los CSV son deterministas y no se reescriben si sus bytes no cambian. El CSV parcial de recuperación reúne todas las categorías hasta el último checkpoint.

Al terminar cada escaneo, el programa genera automáticamente los cinco reportes derivados. Para regenerarlos de un resultado anterior, sin volver a leer las unidades:

```powershell
powershell.exe -NoProfile -File .\New-ScanReviewReports.ps1 -CsvPath .\crypto-artifact-scan-C.csv
```

`Confianza` combina el formato con el contexto de la ruta: un checksum o estructura reconocida suele ser `Alta`; señales dentro de pruebas del escáner o listas públicas exactas se muestran como `Baja`, y frases con checksum dentro de software instalado/dependencias como `Media`. `Media` también incluye estructuras parciales; `Baja`, menciones, candidatos incompletos e identificadores públicos; `No evaluable`, incidencias de cobertura. Un registro local de sesión de usuario conserva su contexto separado de los recursos de software. Un candidato WIF sin checksum validado queda marcado como no confirmado. La confianza no mide titularidad, acceso a la wallet ni fondos. En keystores Ethereum V3 solo se comprueba la estructura; no se descifra ni verifica el MAC. El contexto de ruta es una pista para priorizar revisión, no una prueba de origen. Los reportes derivados solo incluyen rutas, etiquetas y metadatos; nunca el contenido detectado. El resumen de cobertura no incluye rutas: los conteos por tipo pueden solaparse si una ubicación tuvo varias incidencias; el total indica ubicaciones únicas.

El límite predeterminado de lectura es 256 MB por archivo, ajustable de 1 a 1024 MB mediante `-MaxContentMB`. Los candidatos mayores se registran como `archivo_supera_limite`, sin leer su contenido. Errores y accesos incompletos aparecen en `nombre.incidencias.csv` y en `nombre.cobertura-resumen.csv`; no equivalen a ausencia de evidencia. El reporte separa los fallos que conviene reintentar después de resolver acceso o bloqueo, los errores del lector, los límites de tamaño/recursos y los documentos cifrados o sin texto extraíble. El OCR opcional permanece apagado salvo que se use `-PdfOcr`; no descifra documentos. Archivos usados por otra aplicación pueden dar error de lectura.

El resumen muestra archivos enumerados, analizados, reutilizados, omitidos por formato/nombre, mayores que el límite, carpetas excluidas, enlaces omitidos y contenidos internos analizados/omitidos. El conteo interno incluye entradas ZIP/XML y páginas PDF, no solo archivos. `-PassThru` añade estos contadores, identidad de los volúmenes, sistema de archivos, checkpoints y estado del recorrido. El 100% representa un recorrido terminado, con filtros y errores indicados aparte.

En `Tipo`, frases BIP-39/Monero/SLIP-39 se identifican con `checksum_valido`. Las frases repetitivas (menos de cuatro palabras distintas), palabras dentro de identificadores, separadores de código y secuencias de diccionario tienen etiquetas `candidata_...` y permanecen en la salida secundaria. Se siguen buscando frases completas posteriores en el mismo archivo. Se admiten espacios, saltos de línea, listas numeradas y listas de palabras entre comillas separadas por comas. Una frase válida de baja diversidad puede ser real y se conserva para revisión.

Para WIF y claves extendidas se conserva el formato candidato y se agrega un tipo con `checksum_valido` cuando pasan Base58Check, estructura y rango de la clave. Si el mismo archivo tiene ambas etiquetas, el CSV conserva la validada. Las direcciones Bitcoin se validan con Base58Check o Bech32/Bech32m, versiones de witness, longitud y padding; se incluyen redes de prueba. Una dirección, incluso validada, es pública y queda en secundarios. Por defecto se omiten cadenas Bitcoin con checksum inválido; `-IncludeUnvalidatedAddressCandidates` las conserva como pistas de baja confianza. Las direcciones EVM con mayúsculas/minúsculas mixtas se validan con checksum EIP-55; las direcciones de un solo caso siguen como candidatas porque no expresan ese checksum. Las direcciones Monero se validan por Base58 Monero, longitud, prefijo de red y checksum. Las direcciones públicas quedan en secundarios; por defecto se omiten las cadenas Monero con checksum inválido, salvo que se solicite la opción de candidatos no validados. La revisión no prueba control de una dirección ni que haya una wallet utilizable.

Los arreglos JSON de 64 bytes compatibles con Solana siguen como candidatos secundarios hasta comprobar que la clave pública Ed25519 coincide con la derivada de los primeros 32 bytes. El par coincidente se etiqueta como validado y pasa a principal; esto confirma la relación de las claves, no saldo, titularidad o uso. El cálculo se hace localmente y nunca se exportan bytes de clave.

Los keystores Ethereum se distinguen por presencia de campos y por estructura JSON v3: cifrado AES-128-CTR, longitudes, MAC, IV y parámetros scrypt/PBKDF2. No se ejecuta el KDF ni se descifran. La validación estructural está limitada a objetos de 64 Ki caracteres y 32 niveles de anidación; coincidencias incompletas se conservan como indicios secundarios. Un JSON con campos o estructura reconocidos no demuestra que el cifrado sea descifrable. Los seis diccionarios públicos incluidos se identifican por SHA-256 del archivo completo; otras listas consecutivas se clasifican como candidatas de diccionario.

Electrum se reconoce por el esquema JSON: tipo y versión de wallet más una estructura keystore `bip32`, `old`, `imported` o `hardware` con material de clave pública/keystore que pasa validaciones de formato. Para limitar memoria, la comprobación solo se activa si los campos principales aparecen en los primeros 64 KiB y el JSON completo no supera 16 MiB. No se descifra el contenido. En `wallet.dat` y respaldos como `wallet.dat.bak` se leen hasta 72 bytes para clasificar la cabecera. SQLite con tamaño mínimo e identificador de red conocido conserva `estructura_wallet_core_validada`. La firma Berkeley DB es genérica y queda en secundarios como `candidata_wallet_core_berkeley_db`; la revisión le asigna confianza media solo si la ruta se asocia con datos de wallet y baja en otras rutas. El archivo se abre solo para lectura; el nombre sin firma reconocida queda como `nombre_wallet_core_sin_validar`. Un formato reconocido no prueba que la wallet se pueda abrir o tenga fondos. Véanse la [cabecera Berkeley DB](https://github.com/bitcoin/bitcoin/blob/master/src/wallet/migrate.cpp) y la [comprobación SQLite de Bitcoin Core](https://github.com/bitcoin/bitcoin/blob/master/src/wallet/sqlite.cpp).

Dentro de ZIP, cada miembro de texto de hasta 64 KiB se compara por SHA-256 con esos diccionarios. El diccionario reconocido se registra como `diccionario_publico_en_comprimido`; cualquier indicio en otro miembro se analiza y clasifica por separado. También funciona en ZIP anidados y sin caché. Una lista modificada o con contenido añadido se analiza normalmente.

Las copias de archivos del detector ya leídos con SHA-256 se identifican por igualdad completa de bytes. Un ZIP del programa solo se clasifica como `copia_verificada_del_escaner` si contiene exactamente todos los archivos esperados por el manifiesto de la versión instalada y cada miembro coincide con el archivo instalado, incluidos los binarios. Cambios, miembros añadidos, duplicados o rutas distintas impiden esa clasificación. El nombre de la carpeta o del ZIP no basta. Todos los patrones encontrados en esas copias públicas exactas tienen confianza baja y quedan fuera del reporte prioritario, incluidos los de claves o estructuras de wallet. Una coincidencia de diccionario en un miembro de un ZIP mixto conserva la prioridad de las claves de otros miembros. No se abren todos los binarios del disco para comprobar su identidad.

Un nombre genérico como `wallet.json`, `keystore.json`, un icono PNG, la biblioteca C++ `atomic`, los certificados Mono `Trust` o los recursos Edge Wallet no tienen prioridad por su nombre. Los nombres y rutas de software de wallets también quedan en secundarios hasta validar contenido; una estructura de wallet o clave validada conserva prioridad incluso dentro de software o caché. Los nombres de wallet hallados en `tests` o `artifacts` del repositorio del escáner también permanecen en secundarios. El nombre `wallet.dat` por sí solo queda en secundarios hasta que su cabecera confirme el formato. Las frases con checksum encontradas en código o recursos de software permanecen en secundarios para revisión: las seis coincidencias de Adobe/VSCode observadas todavía no están confirmadas como wallets. En archivos normales que ya tienen evidencia fuerte de clave o estructura wallet, se omiten filas redundantes de términos y nombres/rutas genéricos; dentro de ZIP se conservan porque pueden provenir de miembros distintos.

Se reconocen además cuatro ejemplos públicos BIP-39 de 12 palabras por su entropía exacta, procedentes de los [vectores publicados por Trezor](https://github.com/trezor/python-mnemonic/blob/master/vectors.json). Es un conjunto limitado. Se mantienen en secundarios porque una copia del ejemplo podría haberse utilizado realmente; encontrarlos no permite descartar todo el archivo.

Referencias de validación: [BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki), [BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki), [EIP-55](https://eips.ethereum.org/EIPS/eip-55), [Base58 Monero](https://github.com/monero-project/monero/blob/master/src/common/base58.cpp), [validación de direcciones Monero](https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/cryptonote_basic_impl.cpp), [configuración de prefijos Monero](https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h), [RFC 8032 Ed25519](https://www.rfc-editor.org/rfc/rfc8032) y [estructura de cuentas Solana](https://solana.com/docs/core/accounts/account-structure). El detector valida el checksum/prefijo de direcciones Monero, pero no replica la prueba de pertenencia a la curva del cliente Monero.

La huella del algoritmo incluye las reglas, la política de candidatos de dirección y los componentes que afectan al análisis. El manifiesto completo sigue ayudando a reconocer copias del detector, pero los documentos y el generador de reportes no invalidan la caché. Un cambio del detector invalida la caché y analiza de nuevo la ubicación; cambiar solo reportes, documentación, núcleos o trabajadores la conserva. El paquete actualizado no transforma automáticamente los CSV de escaneos anteriores.

Windows puede actualizar metadatos de último acceso al leer o montar un disco. Para preservación forense estricta, analiza una imagen o utiliza un bloqueador físico de escritura.

## Cobertura y límites

- Reconoce rutas y nombres de wallets conocidas, perfiles de Chrome/Edge/Firefox y términos de monedas, wallets, recuperación y minería. Incluye términos y etiquetas de claves en español.
- Busca texto en extensiones comunes, bases de datos mediante cadenas legibles, archivos `.env` y archivos con nombre/ruta de wallet o clave aunque su extensión sea desconocida. Omite formatos binarios conocidos.
- Señala WIF y claves extendidas con candidatos y validación de checksum/rango; direcciones Bitcoin, EVM y Monero con validaciones de formato/checksum; claves hexadecimales de 32 bytes etiquetadas o con contexto de clave; keystores Ethereum, estructura JSON de wallets Electrum, cabeceras Berkeley DB/SQLite de `wallet.dat` y arreglos JSON Solana con validación de correspondencia Ed25519. Una dirección pública o una estructura reconocida no demuestra titularidad ni fondos.
- Valida checksum BIP-39 en inglés y español (12/15/18/21/24 palabras), Monero en inglés, inglés antiguo y español (25 palabras, completas o abreviaturas exactas), y SLIP-39 en inglés (20/33 palabras).
- Omite Windows, System Volume Information y $Recycle.Bin solo cuando están directamente en la raíz de una unidad o recurso compartido. `Recovery` se recorre por defecto en cualquier ubicación, porque puede ser una carpeta personal de recuperación o respaldo; puedes excluirla mediante `-ExcludePath`. Las carpetas personales con nombres de sistema dentro de respaldos también se recorren. También omite enlaces/junctions y los propios archivos del detector.
- Lee ZIP y ZIP anidados sin extraer archivos en disco. Busca texto y nombres de wallet dentro de los miembros contemplados. En el CSV se indica la ubicación del contenedor; no se exportan nombres internos ni contenido sensible.
- Extrae texto XML de DOCX, XLSX y PPTX, sin abrir Office, ejecutar macros ni resolver entidades externas. Extrae texto de PDF mediante PdfPig, incluido en el paquete. Opcionalmente, `-PdfOcr` reconoce texto impreso en páginas de PDF escaneadas usando Tesseract y Poppler instalados localmente; no procesa escritura a mano.
- No recupera archivos borrados ni analiza espacio no asignado. No descifra bases de datos ni wallets. No admite RAR/7z ni documentos Office binarios antiguos. Electrum mayor a 16 MiB, con metadatos después de los primeros 64 KiB, variantes de wallet desconocidas, Monero sin checksum, otros idiomas/formatos, archivos dañados o cifrados y extensiones no contempladas pueden no detectarse.

La cobertura es explícita y no exhaustiva. Un indicio requiere revisión y no prueba que existan fondos.

## Límites de documentos y contenedores

- `-MaxDocumentMB`: 32 MB por PDF o documento/contenedor interno que necesite memoria; permite de 1 a 256 MB.
- `-MaxExpandedMB`: 256 MB de contenido expandido acumulado por archivo ZIP/Office; permite de 1 a 2048 MB.
- Máximo 10,000 entradas, 16 MB de metadatos de directorio ZIP y tres niveles de contenedores ZIP anidados. Se comprueba el directorio antes de construir los objetos de las entradas.
- PDF se analiza en un proceso auxiliar de PowerShell con `-File`, sin ruta ni documento en sus argumentos. Los bytes y texto viajan por pipes anónimos. Tiene 45 segundos por PDF, límite de memoria de proceso de 512 MB mediante un Job Object de Windows, hasta 2,000 páginas y 1 MB de texto por página. El proceso se cierra al terminar el escaneo y también si desaparece su proceso padre.
- PDF con marca de cifrado se omite antes de intentar abrirlo. Sin texto extraíble, con error o que supera recursos queda indicado en el CSV. Si se interrumpe el parser, conserva los indicios de las páginas ya analizadas. Los análisis incompletos no se guardan como negativos válidos en la caché.

El lector PDF se comparte y procesa un PDF a la vez para conservar el límite de recursos y evitar mezclar sus pipes. Los demás trabajadores continúan con texto, ZIP y documentos Office en paralelo. Todas las tareas y el proceso PDF permanecen dentro de la afinidad de CPU permitida.

## Desarrollo y pruebas

Desde la raíz del repositorio, compila el paquete con Windows PowerShell 5.1:

~~~powershell
powershell.exe -NoProfile -File .\Build-Package.ps1
~~~

Si faltan dependencias, primero restáuralas y valida sus hashes; este paso requiere Internet:

~~~powershell
powershell.exe -NoProfile -File .\Restore-Dependencies.ps1
powershell.exe -NoProfile -File .\Build-Package.ps1
~~~

Después de compilar, ejecuta la regresión completa y guarda los logs fuera del repositorio:

~~~powershell
$resultados = Join-Path $env:TEMP ('wallet-scanner-regression-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
powershell.exe -NoProfile -File .\tests\Run-Regression.ps1 -ResultDirectory $resultados
~~~

Las pruebas usan archivos sintéticos en carpetas temporales; no escanean unidades reales. `Compare-DetectionSample.ps1` es una utilidad opcional para revisar una muestra local: recibe explícitamente las rutas del CSV original, la muestra verificada, la raíz y la carpeta de salida. Sus resultados pueden contener rutas y hashes, así que mantenlos privados.
