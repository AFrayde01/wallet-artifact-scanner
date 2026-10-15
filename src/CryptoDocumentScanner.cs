using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Text.RegularExpressions;

public static class CryptoDocumentScanner
{
    public static bool DirectRecoverySearch;
    private static long DocumentLimit = 32L * 1024 * 1024, ExpandedLimit = 256L * 1024 * 1024;
    private static string WorkerPath;
    private static bool PdfOcrEnabled;
    private static string PdfToCairoPath, TesseractPath, PdfOcrLanguages, PdfOcrTessdataPath;
    private static int PdfOcrDpi = 150, PdfOcrMaxPages = 100, PdfOcrTimeoutSeconds = 180;
    private static Process Worker;
    private static IntPtr WorkerJob;
    private static Task<string> WorkerErrors;
    private static readonly object PdfGate = new object();
    private const int MaxEntries = 10000, MaxDepth = 3;
    private sealed class Budget { public long Bytes; public int Entries; }
    public static void Configure(string workerPath, long documentLimit, long expandedLimit)
    { Configure(workerPath, documentLimit, expandedLimit, false, "", "", "", 150, 100, 180, ""); }
    public static void Configure(string workerPath, long documentLimit, long expandedLimit, bool pdfOcrEnabled,
        string rendererPath, string ocrEnginePath, string ocrLanguages, int ocrDpi, int maxOcrPages, int ocrTimeoutSeconds,
        string ocrTessdataPath)
    {
        StopWorker(); WorkerPath = workerPath; DocumentLimit = documentLimit; ExpandedLimit = expandedLimit;
        DirectRecoverySearch = false;
        PdfOcrEnabled = pdfOcrEnabled; PdfToCairoPath = rendererPath; TesseractPath = ocrEnginePath; PdfOcrLanguages = ocrLanguages;
        PdfOcrTessdataPath = ocrTessdataPath;
        PdfOcrDpi = ocrDpi; PdfOcrMaxPages = maxOcrPages; PdfOcrTimeoutSeconds = ocrTimeoutSeconds;
    }
    public static bool IsSupported(string extension)
    { return extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) || extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase) || IsOffice(extension); }
    private static bool IsOffice(string extension)
    {
        return extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) || extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) || extension.Equals(".pptx", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".docm", StringComparison.OrdinalIgnoreCase) || extension.Equals(".xlsm", StringComparison.OrdinalIgnoreCase) || extension.Equals(".pptm", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".odt", StringComparison.OrdinalIgnoreCase) || extension.Equals(".ods", StringComparison.OrdinalIgnoreCase) || extension.Equals(".odp", StringComparison.OrdinalIgnoreCase);
    }
    private static void Issue(HashSet<string> evidence, CryptoFileScanResult result, string id)
    { result.Incomplete = true; result.MembersSkipped++; evidence.Add(id); }
    public static CryptoFileScanResult Scan(Stream stream, string extension)
    {
        CryptoFileScanResult result = new CryptoFileScanResult(); HashSet<string> evidence = new HashSet<string>(StringComparer.Ordinal);
        try { ScanContainer(stream, extension.ToLowerInvariant(), 0, new Budget(), evidence, result); }
        catch (OperationCanceledException) { throw; }
        catch { Issue(evidence, result, "document_read_error"); }
        string[] ids = new string[evidence.Count]; evidence.CopyTo(ids); Array.Sort(ids, StringComparer.Ordinal); result.Evidence = ids; return result;
    }
    private static void ScanContainer(Stream stream, string extension, int depth, Budget budget, HashSet<string> evidence, CryptoFileScanResult result)
    {
        CryptoFileScanner.ThrowIfCancelled();
        if (extension == ".pdf") { ScanPdf(stream, evidence, result); return; }
        if (depth > MaxDepth) { Issue(evidence, result, "container_depth_limit"); return; }
        if (!PreflightZip(stream, MaxEntries - budget.Entries)) { Issue(evidence, result, "container_entry_limit"); return; }
        stream.Position = 0;
        bool office = IsOffice(extension);
        using (ZipArchive archive = new ZipArchive(stream, ZipArchiveMode.Read, true))
        {
            if (!office && !DirectRecoverySearch && TryRuntimePackage(archive, budget, result))
            { evidence.Add("scanner_runtime_copy"); return; }
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                CryptoFileScanner.ThrowIfCancelled();
                if (entry.FullName.EndsWith("/", StringComparison.Ordinal)) continue;
                if (++budget.Entries > MaxEntries) { Issue(evidence, result, "container_entry_limit"); break; }
                string name = entry.FullName.Replace('\\', '/'); string ext = Path.GetExtension(name).ToLowerInvariant();
                string leaf = Path.GetFileName(name);
                string nameEvidence = Regex.IsMatch(leaf, @"(?i)^wallet\.dat(?:\..*)?$") ? "bitcoin_core_wallet_filename" :
                    Regex.IsMatch(name, @"(?i)(?:wallet|keystore|electrum|mnemonic|seed.?phrase|recovery.?phrase)") ? "wallet_or_crypto_related_filename" : null;
                bool xmlPart = office && name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) &&
                    (name.StartsWith("word/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("xl/", StringComparison.OrdinalIgnoreCase) || name.StartsWith("ppt/", StringComparison.OrdinalIgnoreCase) ||
                     name.Equals("content.xml", StringComparison.OrdinalIgnoreCase));
                bool supported = xmlPart || (!office && (IsSupported(ext) || IsText(ext, name)));
                if (!supported) { if (nameEvidence != null) evidence.Add(nameEvidence); result.MembersSkipped++; continue; }
                if (entry.Length > ExpandedLimit || entry.Length > ExpandedLimit - budget.Bytes || (IsSupported(ext) && entry.Length > DocumentLimit))
                { if (nameEvidence != null) evidence.Add(nameEvidence); Issue(evidence, result, "container_expansion_limit"); continue; }
                budget.Bytes += entry.Length;
                try
                {
                    bool publicDictionary = false;
                    using (Stream input = entry.Open())
                    using (Stream bounded = new BoundedReadStream(input, entry.Length))
                    {
                        if (xmlPart) ScanXml(bounded, evidence);
                        else if (IsSupported(ext))
                        {
                            using (MemoryStream memory = new MemoryStream()) { bounded.CopyTo(memory); memory.Position = 0; ScanContainer(memory, ext, depth + 1, budget, evidence, result); }
                        }
                        else
                        {
                            // Identify the dictionary in this member, never in the whole mixed archive.
                            CryptoFileScanResult member = CryptoFileScanner.ReadStream(bounded, true, ext == ".json", ext == ".key" || ext == ".privkey" || ext == ".secret", entry.Length, entry.Length <= 65536, null);
                            if (Array.IndexOf(member.Evidence, "public_mnemonic_dictionary") >= 0)
                            { publicDictionary = true; evidence.Add("container_public_mnemonic_dictionary"); }
                            else foreach (string id in member.Evidence) evidence.Add(id);
                        }
                    }
                    if (!publicDictionary && nameEvidence != null) evidence.Add(nameEvidence);
                    result.MembersScanned++;
                }
                catch (OperationCanceledException) { throw; }
                catch { if (nameEvidence != null) evidence.Add(nameEvidence); Issue(evidence, result, "container_member_read_error"); }
            }
        }
    }
    private static bool TryRuntimePackage(ZipArchive archive, Budget budget, CryptoFileScanResult result)
    {
        // A folder name is insufficient: require the complete installed manifest and exact bytes.
        if (CryptoFileScanner.RuntimeFileCount == 0 || archive.Entries.Count != CryptoFileScanner.RuntimeFileCount) return false;
        const string prefix = "windows-crypto-artifact-scan/";
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long bytes = 0;
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            string name = entry.FullName.Replace('\\', '/');
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            name = name.Substring(prefix.Length);
            if (!names.Add(name) || !CryptoFileScanner.IsRuntimeName(name) || entry.Length > ExpandedLimit - budget.Bytes - bytes) return false;
            bytes += entry.Length;
        }
        try
        {
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                CryptoFileScanner.ThrowIfCancelled();
                using (Stream input = entry.Open())
                using (Stream bounded = new BoundedReadStream(input, entry.Length))
                {
                    CryptoFileScanResult member = CryptoFileScanner.ReadStream(bounded, false, false, false, entry.Length, true, null);
                    if (member.BytesRead != entry.Length || !CryptoFileScanner.IsRuntimeFile(entry.FullName.Replace('\\', '/').Substring(prefix.Length), member.Sha256)) return false;
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { return false; }
        budget.Bytes += bytes; budget.Entries += names.Count; result.MembersScanned += names.Count;
        return true;
    }
    private static bool IsText(string ext, string name)
    {
        // Match the common text/data formats; arbitrary executable/media entries stay unopened.
        if (("|.exe|.dll|.sys|.bin|.jpg|.jpeg|.png|.gif|.mp3|.mp4|.iso|.img|.7z|.rar|.gz|.vhd|.vhdx|").Contains("|" + ext + "|")) return false;
        return ("|.txt|.text|.log|.json|.jsonl|.csv|.xml|.html|.htm|.js|.map|.ini|.cfg|.conf|.yaml|.yml|.md|.markdown|.rtf|.db|.ldb|.sqlite|.sqlite3|.dat|.key|.privkey|.secret|.wallet|.backup|.bak|.pem|.asc|.seed|.config|.toml|.env|.sql|.py|.ps1|.sh|.ts|.tsx|.jsx|.properties|.eml|.tex|.rst|.org|.adoc|.nfo|.readme|.cs|.c|.cpp|.h|.hpp|.java|.go|.rs|.rb|.php|.kt|.swift|").Contains("|" + ext + "|") ||
            Regex.IsMatch(name, @"(?i)(?:wallet|keystore|private.?key|secret.?key|privkey|clave.?privada|llave.?privada|seed.?phrase|recovery.?phrase)") ||
            Regex.IsMatch(Path.GetFileName(name), @"(?i)^\.env(?:\..*)?$");
    }
    private static bool PreflightZip(Stream stream, int allowed)
    {
        if (!stream.CanSeek || stream.Length < 22 || allowed < 0) return false;
        int size = (int)Math.Min(65557, stream.Length); byte[] tail = new byte[size]; stream.Position = stream.Length - size;
        ReadExact(stream, tail, size);
        for (int i = size - 22; i >= 0; i--)
        {
            if (BitConverter.ToUInt32(tail, i) != 0x06054b50 || i + 22 + BitConverter.ToUInt16(tail, i + 20) != size) continue;
            if (BitConverter.ToUInt16(tail, i + 4) != 0 || BitConverter.ToUInt16(tail, i + 6) != 0) return false;
            ulong count = BitConverter.ToUInt16(tail, i + 10), centralSize = BitConverter.ToUInt32(tail, i + 12), centralOffset = BitConverter.ToUInt32(tail, i + 16);
            if (count == 65535 || centralSize == UInt32.MaxValue || centralOffset == UInt32.MaxValue)
            {
                if (i < 20 || BitConverter.ToUInt32(tail, i - 20) != 0x07064b50) return false;
                long offset = BitConverter.ToInt64(tail, i - 12); if (offset < 0 || offset > stream.Length - 56) return false;
                stream.Position = offset; byte[] record = new byte[56]; ReadExact(stream, record, record.Length);
                if (BitConverter.ToUInt32(record, 0) != 0x06064b50) return false;
                count = BitConverter.ToUInt64(record, 32); centralSize = BitConverter.ToUInt64(record, 40); centralOffset = BitConverter.ToUInt64(record, 48);
            }
            if (count > (ulong)allowed || centralSize > 16UL * 1024 * 1024 || centralOffset > (ulong)stream.Length || centralSize > (ulong)stream.Length - centralOffset) return false;
            // Count real central-directory records before ZipArchive allocates its entry objects.
            stream.Position = (long)centralOffset; long end = (long)(centralOffset + centralSize); int actual = 0; byte[] header = new byte[46];
            while (stream.Position < end)
            {
                if (++actual > allowed || end - stream.Position < header.Length) return false;
                ReadExact(stream, header, header.Length); if (BitConverter.ToUInt32(header, 0) != 0x02014b50) throw new InvalidDataException();
                int length = BitConverter.ToUInt16(header, 28) + BitConverter.ToUInt16(header, 30) + BitConverter.ToUInt16(header, 32);
                if (length > end - stream.Position) throw new InvalidDataException(); stream.Position += length;
            }
            if ((ulong)actual != count) throw new InvalidDataException(); return true;
        }
        throw new InvalidDataException();
    }
    private static void ReadExact(Stream stream, byte[] buffer, int length)
    { for (int offset = 0; offset < length; ) { int read = stream.Read(buffer, offset, length - offset); if (read == 0) throw new EndOfStreamException(); offset += read; } }
    private sealed class BoundedReadStream : Stream
    {
        private readonly Stream source; private readonly long limit; private long read;
        public BoundedReadStream(Stream stream, long max) { source = stream; limit = max; }
        public override int Read(byte[] buffer, int offset, int count)
        { CryptoFileScanner.ThrowIfCancelled(); int result = source.Read(buffer, offset, (int)Math.Min(count, Math.Max(1, limit - read + 1))); read += result; if (read > limit) throw new InvalidDataException(); return result; }
        public override bool CanRead { get { return true; } } public override bool CanSeek { get { return false; } } public override bool CanWrite { get { return false; } }
        public override long Length { get { return limit; } } public override long Position { get { return read; } set { throw new NotSupportedException(); } }
        public override void Flush() {} public override long Seek(long o, SeekOrigin s) { throw new NotSupportedException(); }
        public override void SetLength(long v) { throw new NotSupportedException(); } public override void Write(byte[] b, int o, int c) { throw new NotSupportedException(); }
    }
    private static void ScanXml(Stream input, HashSet<string> evidence)
    {
        XmlReaderSettings settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = ExpandedLimit };
        StringBuilder text = new StringBuilder(); string tail = "";
        using (XmlReader reader = XmlReader.Create(input, settings))
        {
            char[] buffer = new char[4096];
            while (reader.Read())
            {
                CryptoFileScanner.ThrowIfCancelled();
                if (reader.NodeType == XmlNodeType.Text || reader.NodeType == XmlNodeType.CDATA || reader.NodeType == XmlNodeType.SignificantWhitespace)
                {
                    int count; while ((count = reader.ReadValueChunk(buffer, 0, buffer.Length)) > 0)
                    { text.Append(buffer, 0, count); if (text.Length >= 32768) FlushText(text, ref tail, false, evidence); }
                }
                else if (reader.NodeType == XmlNodeType.EndElement && (reader.LocalName == "p" || reader.LocalName == "si" || reader.LocalName == "c" || reader.LocalName == "row" || reader.LocalName == "v")) text.Append(' ');
            }
        }
        FlushText(text, ref tail, true, evidence);
    }
    private static void FlushText(StringBuilder builder, ref string tail, bool final, HashSet<string> evidence)
    {
        string text = tail + builder.ToString(); int end = text.Length;
        if (!final) while (end > 0 && (Char.IsLetterOrDigit(text[end - 1]) || text[end - 1] == '_')) end--;
        foreach (string id in CryptoFileScanner.ScanText(text.Substring(0, end), false, false)) evidence.Add(id);
        tail = text.Substring(Math.Max(0, text.Length - 8192)); builder.Clear();
    }
    private static void StartWorker()
    {
        if (Worker != null && !Worker.HasExited) return;
        StopWorker();
        ProcessStartInfo startInfo = new ProcessStartInfo {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe"),
            Arguments = "-NoLogo -NoProfile -NonInteractive -File \"" + WorkerPath + "\"", UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (PdfOcrEnabled)
        {
            startInfo.EnvironmentVariables["WALLET_SCANNER_PDF_OCR"] = "1";
            startInfo.EnvironmentVariables["WALLET_SCANNER_PDF_RENDERER"] = PdfToCairoPath;
            startInfo.EnvironmentVariables["WALLET_SCANNER_TESSERACT"] = TesseractPath;
            startInfo.EnvironmentVariables["WALLET_SCANNER_OCR_LANGUAGES"] = PdfOcrLanguages;
            startInfo.EnvironmentVariables["TESSDATA_PREFIX"] = PdfOcrTessdataPath;
            startInfo.EnvironmentVariables["WALLET_SCANNER_OCR_DPI"] = PdfOcrDpi.ToString(System.Globalization.CultureInfo.InvariantCulture);
            startInfo.EnvironmentVariables["WALLET_SCANNER_OCR_MAX_PAGES"] = PdfOcrMaxPages.ToString(System.Globalization.CultureInfo.InvariantCulture);
            startInfo.EnvironmentVariables["WALLET_SCANNER_OCR_TIMEOUT"] = PdfOcrTimeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        Worker = new Process { StartInfo = startInfo };
        Worker.Start(); WorkerErrors = Worker.StandardError.ReadToEndAsync();
        try { WorkerJob = CryptoWindowsIO.BoundWorker(Worker.Handle); }
        catch { StopWorker(); throw; }
    }
    private static void ScanPdf(Stream stream, HashSet<string> evidence, CryptoFileScanResult result)
    {
        // One bounded parser is shared; text, ZIP and Office readers remain parallel.
        lock (PdfGate) {
            CryptoFileScanner.ThrowIfCancelled();
            ScanPdfCore(stream, evidence, result);
        }
    }
    private static void ScanPdfCore(Stream stream, HashSet<string> evidence, CryptoFileScanResult result)
    {
        if (stream.Length > DocumentLimit) { Issue(evidence, result, "document_size_limit"); return; }
        StartWorker(); Process process = Worker;
        HashSet<string> detected = new HashSet<string>(StringComparer.Ordinal); int pages = 0, status = 0; bool anyText = false, anyOcrPage = false;
        CancellationToken token = CryptoFileScanner.Cancellation;
        Task reading = Task.Run(() => {
            CancellationToken previous = CryptoFileScanner.Cancellation;
            CryptoFileScanner.Cancellation = token;
            try {
            BinaryReader reader = new BinaryReader(process.StandardOutput.BaseStream, Encoding.UTF8, true); int frames = 0;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                int code = reader.ReadInt32(); if (code <= 0) { status = code; break; }
                if ((code != 1 && code != 2) || ++frames > 4000) throw new InvalidDataException();
                int length = reader.ReadInt32(); if (length < 0 || length > 1024 * 1024) throw new InvalidDataException();
                byte[] bytes = reader.ReadBytes(length); if (bytes.Length != length) throw new EndOfStreamException();
                string text = Encoding.UTF8.GetString(bytes); if (code == 1 && length > 0) anyText = true;
                string[] ids = CryptoFileScanner.ScanText(text, false, false);
                lock (detected)
                {
                    if (code == 1) { foreach (string id in ids) detected.Add(id); pages++; }
                    else { anyOcrPage = true; if (IsOcrCandidate(ids)) detected.Add("pdf_ocr_candidate_indicator"); }
                }
            }
            }
            finally { CryptoFileScanner.Cancellation = previous; }
        });
        try
        {
            BinaryWriter writer = new BinaryWriter(process.StandardInput.BaseStream, Encoding.UTF8, true);
            writer.Write((int)stream.Length); writer.Flush(); stream.CopyTo(process.StandardInput.BaseStream); process.StandardInput.BaseStream.Flush();
            Stopwatch timer = Stopwatch.StartNew();
            while (!reading.IsCompleted)
            {
                CryptoFileScanner.ThrowIfCancelled();
                int timeoutSeconds = PdfOcrEnabled ? PdfOcrTimeoutSeconds + 30 : 45;
                if (timer.Elapsed.TotalSeconds > timeoutSeconds || (!process.HasExited && process.WorkingSet64 > 512L * 1024 * 1024))
                { StopWorker(); Issue(evidence, result, "document_resource_limit"); return; }
                Thread.Sleep(50);
            }
            reading.GetAwaiter().GetResult();
            if (status < 0) Issue(evidence, result, status == -1 ? "document_encrypted" : status == -3 ? "document_resource_limit" : status == -4 ? "document_ocr_error" : status == -5 ? "document_ocr_page_limit" : "document_read_error");
            else if (!anyText && !anyOcrPage) Issue(evidence, result, "document_without_extractable_text");
        }
        catch (OperationCanceledException) { StopWorker(); throw; }
        catch { StopWorker(); Issue(evidence, result, "document_read_error"); }
        finally
        {
            // Preserve completed pages even when the worker stops before the final frame.
            lock (detected) { foreach (string id in detected) evidence.Add(id); result.MembersScanned += pages; }
            reading.ContinueWith(faulted => GC.KeepAlive(faulted.Exception),
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        }
    }
    public static void StopWorker()
    {
        lock (PdfGate) StopWorkerCore();
    }
    private static bool IsOcrCandidate(string[] ids)
    {
        bool wallet = false, cryptocurrency = false;
        foreach (string id in ids)
        {
            if (id == "possible_bip39_mnemonic_phrase" || id == "possible_monero_mnemonic_phrase" || id == "possible_slip39_share" ||
                id == "possible_bitcoin_private_key" || id == "possible_extended_private_key" || id == "possible_hex_private_key" ||
                id == "validated_bitcoin_private_key" || id == "validated_extended_private_key" || id == "possible_solana_keypair_json" ||
                id == "validated_solana_keypair_json" || id == "validated_bitcoin_address" || id == "validated_evm_address" ||
                id == "validated_monero_address" || id == "possible_bitcoin_address" || id == "possible_evm_address" || id == "possible_monero_address" ||
                id.StartsWith("mnemonic_", StringComparison.Ordinal)) return true;
            if (id == "wallet_or_recovery_terms") wallet = true;
            if (id == "cryptocurrency_terms") cryptocurrency = true;
        }
        return wallet && cryptocurrency;
    }
    private static void StopWorkerCore()
    {
        Process process = Worker; Worker = null;
        CryptoWindowsIO.CloseWorkerJob(WorkerJob); WorkerJob = IntPtr.Zero;
        if (process == null) return;
        try { if (!process.HasExited) process.Kill(); process.WaitForExit(2000); if (WorkerErrors != null && WorkerErrors.IsCompleted) WorkerErrors.GetAwaiter().GetResult(); }
        catch {} finally { process.Dispose(); WorkerErrors = null; }
    }
}
