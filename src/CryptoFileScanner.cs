using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

public sealed class CryptoFileScanResult
{
    public string[] Evidence;
    public string Sha256;
    public long BytesRead;
    public int MembersScanned;
    public int MembersSkipped;
    public bool Incomplete;
}

public static class CryptoFileScanner
{
    public static bool Bip39Only { get; set; }
    private const int ElectrumProbeLimit = 64 * 1024;
    private const int ElectrumJsonLimit = 16 * 1024 * 1024;
    private static string[] RuleIds;
    private static Regex[] Rules;
    private static HashSet<string> PublicDictionaryHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public static void ConfigurePublicDictionaries(string[] hashes) { PublicDictionaryHashes = new HashSet<string>(hashes, StringComparer.OrdinalIgnoreCase); }
    private static Dictionary<string, string> RuntimeFiles = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> RuntimeHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    public static void ConfigureRuntimeFiles(string[] names, string[] hashes)
    {
        if (names.Length != hashes.Length) throw new ArgumentException("Invalid runtime manifest.");
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < names.Length; i++) files.Add(names[i].Replace('\\', '/'), hashes[i]);
        RuntimeFiles = files; RuntimeHashes = new HashSet<string>(hashes, StringComparer.OrdinalIgnoreCase);
    }
    internal static int RuntimeFileCount { get { return RuntimeFiles.Count; } }
    internal static bool IsRuntimeName(string name) { return RuntimeFiles.ContainsKey(name); }
    internal static bool IsRuntimeFile(string name, string hash)
    { string expected; return RuntimeFiles.TryGetValue(name, out expected) && String.Equals(expected, hash, StringComparison.OrdinalIgnoreCase); }
    [ThreadStatic] private static byte[] ReadBuffer;
    [ThreadStatic] private static char[] CharBuffer;
    [ThreadStatic] internal static CancellationToken Cancellation;
    internal static void ThrowIfCancelled() { Cancellation.ThrowIfCancellationRequested(); }
    private static readonly Regex HexKey = new Regex("(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex SolanaArray = new Regex("\\[\\s*(?:[0-9]{1,3}\\s*,\\s*){63}[0-9]{1,3}\\s*\\]", RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(3));
    private static readonly Regex[] KeystoreFields = new Regex[] {
        new Regex("(?i)\"crypto\"\\s*:", RegexOptions.Compiled),
        new Regex("(?i)\"cipher\"\\s*:", RegexOptions.Compiled),
        new Regex("(?i)\"kdfparams\"\\s*:", RegexOptions.Compiled)
    };

    public static void Configure(string[] ids, string[] patterns)
    {
        Bip39Only = false;
        if (ids.Length != patterns.Length) throw new ArgumentException("Invalid content rules.");
        RuleIds = (string[])ids.Clone();
        Rules = new Regex[patterns.Length];
        for (int i = 0; i < patterns.Length; i++)
            Rules[i] = new Regex(patterns[i], RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(3));
    }

    public static string TextHash(string text)
    {
        using (SHA256 sha = SHA256.Create()) return ToHex(sha.ComputeHash(Encoding.UTF8.GetBytes(text)));
    }

    public static string PathId(string path)
    {
        return TextHash(CryptoWindowsIO.NormalizePath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).ToUpperInvariant());
    }

    private static string ToHex(byte[] bytes)
    {
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    public static bool BitcoinCoreWalletDatabaseValid(byte[] header, long length)
    {
        if (header == null) return false;
        byte[] sqlite = Encoding.ASCII.GetBytes("SQLite format 3\0");
        if (length < 512 || header.Length < 72) return false;
        for (int i = 0; i < sqlite.Length; i++) if (header[i] != sqlite[i]) return false;
        byte[][] networks = new byte[][] {
            new byte[] { 0xf9, 0xbe, 0xb4, 0xd9 }, // mainnet
            new byte[] { 0x0b, 0x11, 0x09, 0x07 }, // testnet3
            new byte[] { 0x1c, 0x16, 0x3f, 0x28 }, // testnet4
            new byte[] { 0x0a, 0x03, 0xcf, 0x40 }, // default signet
            new byte[] { 0xfa, 0xbf, 0xb5, 0xda }  // regtest
        };
        foreach (byte[] network in networks)
        {
            bool matches = true;
            for (int i = 0; i < 4; i++) if (header[68 + i] != network[i]) { matches = false; break; }
            if (matches) return true;
        }
        return false;
    }

    public static string[] BitcoinCoreWalletDatabaseEvidence(byte[] header, long length)
    {
        if (BitcoinCoreWalletDatabaseValid(header, length)) return new[] { "validated_bitcoin_core_wallet_database" };
        // Berkeley DB's BTree magic is shared by unrelated databases. Preserve the lead,
        // but only the SQLite network/application id above distinguishes this wallet format.
        if (header != null && length >= 4096 && header.Length >= 16 &&
            ((header[12] == 0x00 && header[13] == 0x05 && header[14] == 0x31 && header[15] == 0x62) ||
             (header[12] == 0x62 && header[13] == 0x31 && header[14] == 0x05 && header[15] == 0x00)))
            return new[] { "bitcoin_core_berkeley_db_candidate" };
        return new string[0];
    }

    public static bool IsBitcoinCoreWalletDatabaseFile(string path)
    { return Array.IndexOf(GetBitcoinCoreWalletDatabaseEvidence(path), "validated_bitcoin_core_wallet_database") >= 0; }

    public static string[] GetBitcoinCoreWalletDatabaseEvidence(string path)
    {
        try
        {
            using (FileStream stream = CryptoWindowsIO.OpenRead(path))
            {
                byte[] header = new byte[72]; int count = 0;
                while (count < header.Length)
                {
                    int read = stream.Read(header, count, header.Length - count);
                    if (read <= 0) break;
                    count += read;
                }
                return BitcoinCoreWalletDatabaseEvidence(header, stream.Length);
            }
        }
        catch (IOException) { return new string[0]; }
        catch (UnauthorizedAccessException) { return new string[0]; }
        catch (ArgumentException) { return new string[0]; }
        catch (NotSupportedException) { return new string[0]; }
    }

    private static Encoding DetectEncoding(byte[] bytes, int count, out int offset)
    {
        offset = 0;
        if (count >= 4 && bytes[0] == 255 && bytes[1] == 254 && bytes[2] == 0 && bytes[3] == 0) { offset = 4; return new UTF32Encoding(false, false); }
        if (count >= 4 && bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 254 && bytes[3] == 255) { offset = 4; return new UTF32Encoding(true, false); }
        if (count >= 2 && bytes[0] == 255 && bytes[1] == 254) { offset = 2; return Encoding.Unicode; }
        if (count >= 2 && bytes[0] == 254 && bytes[1] == 255) { offset = 2; return Encoding.BigEndianUnicode; }
        if (count >= 3 && bytes[0] == 239 && bytes[1] == 187 && bytes[2] == 191) { offset = 3; return Encoding.UTF8; }
        int sample = Math.Min(count, 512);
        int evenZeros = 0, oddZeros = 0;
        for (int i = 0; i < sample; i++) if (bytes[i] == 0) { if ((i & 1) == 0) evenZeros++; else oddZeros++; }
        int minimumZeros = Math.Max(4, sample / 8);
        if (oddZeros >= minimumZeros) return Encoding.Unicode;
        if (evenZeros >= minimumZeros) return Encoding.BigEndianUnicode;
        try
        {
            // A decoder keeps an incomplete multibyte character at the end of the sample.
            new UTF8Encoding(false, true).GetDecoder().GetCharCount(bytes, 0, sample, false);
            return Encoding.UTF8;
        }
        catch (DecoderFallbackException) { return Encoding.Default; }
    }

    private static byte[] ParseSolanaArray(string array)
    {
        string[] tokens = array.Substring(1, array.Length - 2).Split(',');
        if (tokens.Length != 64) return null;
        byte[] bytes = new byte[64];
        for (int i = 0; i < tokens.Length; i++)
        {
            int value;
            if (!Int32.TryParse(tokens[i].Trim(), out value) || value < 0 || value > 255) return null;
            bytes[i] = (byte)value;
        }
        return bytes;
    }

    private static void Detect(string text, bool json, bool hexContext, HashSet<string> evidence, bool[] keystore, string structureText = null)
    {
        if (Bip39Only)
        {
            foreach (string id in CryptoMnemonicScanner.Scan(text)) evidence.Add(id);
            return;
        }
        for (int i = 0; i < Rules.Length; i++)
        {
            ThrowIfCancelled();
            string validated = RuleIds[i] == "possible_bitcoin_private_key" ? "validated_bitcoin_private_key" :
                RuleIds[i] == "possible_extended_private_key" ? "validated_extended_private_key" :
                RuleIds[i] == "possible_bitcoin_address" ? "validated_bitcoin_address" :
                RuleIds[i] == "possible_evm_address" ? "validated_evm_address" :
                RuleIds[i] == "possible_monero_address" ? "validated_monero_address" : "";
            if (validated.Length == 0) { if (!evidence.Contains(RuleIds[i]) && Rules[i].IsMatch(text)) evidence.Add(RuleIds[i]); }
            else if (!evidence.Contains(validated))
                for (Match match = Rules[i].Match(text); match.Success; match = match.NextMatch())
                {
                    evidence.Add(RuleIds[i]);
                    bool bounded = (match.Index == 0 || !IsTokenCharacter(text[match.Index - 1])) && (match.Index + match.Length == text.Length || !IsTokenCharacter(text[match.Index + match.Length]));
                    bool valid = bounded && (validated == "validated_bitcoin_address" ? CryptoEvidenceQuality.BitcoinAddressValid(match.Value) :
                        validated == "validated_evm_address" ? CryptoEvidenceQuality.EvmAddressChecksumValid(match.Value) :
                        validated == "validated_monero_address" ? CryptoEvidenceQuality.MoneroAddressChecksumValid(match.Value) :
                        CryptoKeyValidation.Valid(match.Value, validated == "validated_extended_private_key"));
                    if (valid) { evidence.Add(validated); break; }
                }
        }
        if (json && !evidence.Contains("validated_solana_keypair_json"))
        {
            for (Match match = SolanaArray.Match(text); match.Success; match = match.NextMatch())
            {
                ThrowIfCancelled();
                byte[] keypair = ParseSolanaArray(match.Value);
                if (keypair == null) continue;
                evidence.Add("possible_solana_keypair_json");
                if (CryptoEvidenceQuality.SolanaKeypairMatches(keypair))
                {
                    evidence.Add("validated_solana_keypair_json");
                    break;
                }
            }
        }
        if (hexContext && !evidence.Contains("possible_hex_private_key") && HexKey.IsMatch(text)) evidence.Add("possible_hex_private_key");
        for (int i = 0; i < keystore.Length; i++) if (!keystore[i]) keystore[i] = KeystoreFields[i].IsMatch(text);
        if (keystore[0] && keystore[1] && keystore[2]) evidence.Add("possible_encrypted_ethereum_keystore");
        if (keystore[0] && !evidence.Contains("validated_ethereum_keystore_structure") && CryptoEvidenceQuality.ContainsKeystoreV3(structureText ?? text)) evidence.Add("validated_ethereum_keystore_structure");
        foreach (string id in CryptoMnemonicScanner.Scan(text)) evidence.Add(id);
    }

    public static string[] ScanText(string text, bool json, bool hexContext)
    {
        HashSet<string> evidence = new HashSet<string>(StringComparer.Ordinal);
        Detect(text, json, hexContext, evidence, new bool[3]);
        if (!Bip39Only && json && CryptoEvidenceQuality.ElectrumWalletStructureValid(text)) evidence.Add("validated_electrum_wallet_structure");
        string[] ids = new string[evidence.Count]; evidence.CopyTo(ids); Array.Sort(ids, StringComparer.Ordinal); return ids;
    }

    private static void CollectElectrumJson(string block, ref StringBuilder prefix, ref StringBuilder wallet, ref bool decided)
    {
        if (wallet != null)
        {
            if (wallet.Length + block.Length > ElectrumJsonLimit) { wallet = null; decided = true; return; }
            wallet.Append(block); return;
        }
        if (decided || block.Length == 0) return;
        if (prefix == null && block.Length >= ElectrumProbeLimit)
        {
            bool walletType = block.IndexOf("\"wallet_type\"", 0, ElectrumProbeLimit, StringComparison.OrdinalIgnoreCase) >= 0;
            bool seedVersion = block.IndexOf("\"seed_version\"", 0, ElectrumProbeLimit, StringComparison.OrdinalIgnoreCase) >= 0;
            decided = true;
            if (!walletType || !seedVersion || block.Length > ElectrumJsonLimit) return;
            wallet = new StringBuilder(Math.Min(ElectrumJsonLimit, block.Length));
            wallet.Append(block);
            return;
        }
        if (prefix == null) prefix = new StringBuilder(Math.Min(ElectrumProbeLimit, block.Length));
        int remaining = ElectrumProbeLimit - prefix.Length;
        int take = Math.Min(remaining, block.Length);
        if (take > 0) prefix.Append(block, 0, take);
        string head = prefix.ToString();
        bool looksLikeElectrum = head.IndexOf("\"wallet_type\"", StringComparison.OrdinalIgnoreCase) >= 0 &&
            head.IndexOf("\"seed_version\"", StringComparison.OrdinalIgnoreCase) >= 0;
        if (looksLikeElectrum)
        {
            if (head.Length + block.Length - take > ElectrumJsonLimit) { prefix = null; decided = true; return; }
            wallet = new StringBuilder(Math.Min(ElectrumJsonLimit, head.Length + block.Length - take));
            wallet.Append(head);
            if (block.Length > take) wallet.Append(block, take, block.Length - take);
            prefix = null; decided = true;
        }
        else if (prefix.Length >= ElectrumProbeLimit)
        {
            prefix = null; decided = true;
        }
    }

    private static bool IsTokenCharacter(char value)
    {
        if (value <= 127) return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_';
        if (Char.IsLetterOrDigit(value)) return true;
        System.Globalization.UnicodeCategory category = Char.GetUnicodeCategory(value);
        return category == System.Globalization.UnicodeCategory.NonSpacingMark || category == System.Globalization.UnicodeCategory.SpacingCombiningMark || category == System.Globalization.UnicodeCategory.EnclosingMark;
    }

    public static CryptoFileScanResult ReadFile(string path, bool analyze, bool json, bool hexContext, long maxBytes, bool computeHash, Action<long> progress)
    {
        ThrowIfCancelled();
        using (FileStream stream = CryptoWindowsIO.OpenRead(path))
        {
            bool document = analyze && CryptoDocumentScanner.IsSupported(Path.GetExtension(path));
            CryptoFileScanResult result = ReadStream(stream, analyze && !document, json, hexContext, maxBytes, computeHash || analyze && stream.Length <= 65536, progress);
            if (document)
            {
                stream.Position = 0;
                CryptoFileScanResult content = CryptoDocumentScanner.Scan(stream, Path.GetExtension(path));
                result.Evidence = content.Evidence; result.Incomplete = content.Incomplete;
                result.MembersScanned = content.MembersScanned; result.MembersSkipped = content.MembersSkipped;
            }
            if (analyze && !String.IsNullOrEmpty(result.Sha256) && RuntimeHashes.Contains(result.Sha256))
            {
                var ids = new HashSet<string>(result.Evidence, StringComparer.Ordinal); ids.Add("scanner_runtime_copy");
                result.Evidence = new string[ids.Count]; ids.CopyTo(result.Evidence); Array.Sort(result.Evidence, StringComparer.Ordinal);
            }
            return result;
        }
    }

    public static CryptoFileScanResult ReadStream(Stream stream, bool analyze, bool json, bool hexContext, long maxBytes, bool computeHash, Action<long> progress)
    {
        HashSet<string> evidence = new HashSet<string>(StringComparer.Ordinal);
        long total = 0;
        byte[] buffer = ReadBuffer ?? (ReadBuffer = new byte[1024 * 1024]);
        char[] chars = analyze ? (CharBuffer ?? (CharBuffer = new char[1024 * 1024 + 4])) : null;
        Decoder decoder = null;
        string tail = "";
        string structureTail = "";
        StringBuilder electrumPrefix = null;
        StringBuilder electrumJson = null;
        bool electrumProbeDecided = false;
        bool[] keystore = new bool[3];
        Stopwatch timer = Stopwatch.StartNew();
        long lastNotification = 0, lastReportedBytes = 0;
        using (SHA256 sha = computeHash ? SHA256.Create() : null)
        {
            if (stream.CanSeek && stream.Length > maxBytes) throw new IOException("File exceeds content limit.");
            int count;
            while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                ThrowIfCancelled();
                total += count;
                if (total > maxBytes) throw new IOException("File exceeds content limit.");
                if (sha != null) sha.TransformBlock(buffer, 0, count, buffer, 0);
                if (analyze)
                {
                    int offset = 0;
                    if (decoder == null) decoder = DetectEncoding(buffer, count, out offset).GetDecoder();
                    bool finalChunk = stream.CanSeek && stream.Position == stream.Length;
                    int charCount = decoder.GetChars(buffer, offset, count - offset, chars, 0, finalChunk);
                    string block = new string(chars, 0, charCount);
                    if (json && !evidence.Contains("validated_electrum_wallet_structure"))
                        CollectElectrumJson(block, ref electrumPrefix, ref electrumJson, ref electrumProbeDecided);
                    string text = tail + block;
                    bool needStructure = !evidence.Contains("validated_ethereum_keystore_structure");
                    string structureText = !needStructure || structureTail.Length == 0 ? text : structureTail + block;
                    // A token cut by a block is not yet a complete key/word.
                    int stableEnd = text.Length;
                    if (!finalChunk) while (stableEnd > 0 && IsTokenCharacter(text[stableEnd - 1])) stableEnd--;
                    if (stableEnd > 0) Detect(stableEnd == text.Length ? text : text.Substring(0, stableEnd), json, hexContext, evidence, keystore, structureText);
                    // Preserve a bounded JSON object even when its crypto field is in the next block.
                    bool keepStructure = needStructure && structureText.IndexOf('{', Math.Max(0, structureText.Length - 65536)) >= 0;
                    structureTail = keepStructure ? structureText.Substring(Math.Max(0, structureText.Length - 65536)) : "";
                    // Regex/mnemonic overlap stays small; only the JSON parser needs the larger window.
                    tail = text.Substring(Math.Max(0, text.Length - 8192));
                }
                if (progress != null && timer.ElapsedMilliseconds - lastNotification >= 100)
                {
                    progress(total);
                    lastReportedBytes = total;
                    lastNotification = timer.ElapsedMilliseconds;
                }
            }
            ThrowIfCancelled();
            if (analyze && tail.Length > 0) Detect(tail, json, hexContext, evidence, keystore, structureTail.Length == 0 ? tail : structureTail);
            if (analyze && json && electrumJson != null && CryptoEvidenceQuality.ElectrumWalletStructureValid(electrumJson.ToString()))
                evidence.Add("validated_electrum_wallet_structure");
            if (sha != null) sha.TransformFinalBlock(new byte[0], 0, 0);
            if (progress != null && total != lastReportedBytes && (total >= 1024 * 1024 || timer.ElapsedMilliseconds >= 100))
                progress(total);
            string hash = sha == null ? "" : ToHex(sha.Hash);
            if (analyze && hash.Length > 0 && PublicDictionaryHashes.Contains(hash)) evidence.Add("public_mnemonic_dictionary");
            string[] ids = new string[evidence.Count];
            evidence.CopyTo(ids);
            Array.Sort(ids, StringComparer.Ordinal);
            return new CryptoFileScanResult { Evidence = ids, Sha256 = hash, BytesRead = total };
        }
    }

    private static bool SameFiles(string left, string right)
    {
        if (!File.Exists(right) || new FileInfo(left).Length != new FileInfo(right).Length) return false;
        using (FileStream a = File.OpenRead(left))
        using (FileStream b = File.OpenRead(right))
        {
            byte[] x = new byte[65536], y = new byte[65536];
            int count;
            while ((count = a.Read(x, 0, x.Length)) > 0)
            {
                int offset = 0;
                while (offset < count) { int read = b.Read(y, offset, count - offset); if (read == 0) return false; offset += read; }
                for (int i = 0; i < count; i++) if (x[i] != y[i]) return false;
            }
            return true;
        }
    }

    public static bool CommitOutput(string temporaryPath, string outputPath)
    { return CommitOutput(temporaryPath, outputPath, false); }

    public static bool CommitOutput(string temporaryPath, string outputPath, bool forceReplacement)
    {
        if (!forceReplacement && SameFiles(temporaryPath, outputPath)) { File.Delete(temporaryPath); return false; }
        if (File.Exists(outputPath))
        {
            // Rename within the output folder; do not require ACL/metadata merging.
            string backup = outputPath + "." + Guid.NewGuid().ToString("N") + ".backup.tmp";
            File.Move(outputPath, backup);
            try { File.Move(temporaryPath, outputPath); }
            catch
            {
                if (!File.Exists(outputPath)) File.Move(backup, outputPath);
                throw;
            }
            File.Delete(backup);
        }
        else File.Move(temporaryPath, outputPath);
        return true;
    }

    public static bool WriteTextIfChanged(string path, string text)
    {
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, text, new UTF8Encoding(true));
            return CommitOutput(temporary, path);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}

public sealed class CryptoScanCacheEntry
{
    public string Hash;
    public long Length;
    public long LastWriteTicks;
    public string[] Evidence;
    public bool Seen;
    public int MembersScanned;
    public int MembersSkipped;
}

public sealed class CryptoScanCache
{
    private const string Signature = "WalletArtifactScanCache-v2";
    private const string JournalSignature = "WalletArtifactScanJournal-v1";
    private readonly Dictionary<string, CryptoScanCacheEntry> entries = new Dictionary<string, CryptoScanCacheEntry>(StringComparer.Ordinal);
    private readonly HashSet<string> validEvidence;
    private readonly string algorithm;
    private readonly string roots;
    private readonly string journal;
    private readonly HashSet<string> dirty = new HashSet<string>(StringComparer.Ordinal);
    private bool journalStarted;
    public int RecoveredEntries;
    public string Status = "nueva";

    private static string ReadField(BinaryReader reader)
    {
        int length = 0;
        bool complete = false;
        for (int shift = 0; shift < 35; shift += 7)
        {
            byte value = reader.ReadByte();
            length |= (value & 127) << shift;
            if ((value & 128) == 0) { complete = true; break; }
        }
        if (!complete || length < 0 || length > 128) throw new InvalidDataException();
        byte[] bytes = reader.ReadBytes(length);
        if (bytes.Length != length) throw new EndOfStreamException();
        return new UTF8Encoding(false, true).GetString(bytes);
    }

    public CryptoScanCache(string path, string algorithmFingerprint, string rootsFingerprint, string[] evidenceIds, bool rescan, string journalPath)
    {
        algorithm = algorithmFingerprint;
        roots = rootsFingerprint;
        journal = journalPath;
        validEvidence = new HashSet<string>(evidenceIds, StringComparer.Ordinal);
        if (rescan) { Status = "reescaneo solicitado"; return; }
        LoadState(path);
        LoadJournal();
    }

    private void LoadState(string path)
    {
        if (!File.Exists(path)) return;
        try
        {
            using (BinaryReader reader = new BinaryReader(File.OpenRead(path), Encoding.UTF8))
            {
                if (ReadField(reader) != Signature) { Status = "formato anterior"; return; }
                if (ReadField(reader) != algorithm) { Status = "detectores o configuración cambiaron"; return; }
                if (ReadField(reader) != roots) { Status = "ubicaciones cambiaron"; return; }
                int count = reader.ReadInt32();
                if (count < 0 || count > 10000000 || count > reader.BaseStream.Length / 100) throw new InvalidDataException();
                for (int i = 0; i < count; i++)
                {
                    string id = ReadField(reader);
                    string hash = ReadField(reader);
                    long length = reader.ReadInt64();
                    long ticks = reader.ReadInt64();
                    int typeCount = reader.ReadInt32();
                    if (id.Length != 64 || hash.Length != 64 || length < 0 || ticks < 0 || typeCount < 0 || typeCount > validEvidence.Count) throw new InvalidDataException();
                    string[] evidence = new string[typeCount];
                    for (int j = 0; j < typeCount; j++)
                    {
                        evidence[j] = ReadField(reader);
                        if (!validEvidence.Contains(evidence[j])) throw new InvalidDataException();
                    }
                    int scanned = reader.ReadInt32(), skipped = reader.ReadInt32();
                    if (scanned < 0 || skipped < 0) throw new InvalidDataException();
                    entries.Add(id, new CryptoScanCacheEntry { Hash = hash, Length = length, LastWriteTicks = ticks, Evidence = evidence, MembersScanned = scanned, MembersSkipped = skipped });
                }
                if (reader.BaseStream.Position != reader.BaseStream.Length) throw new InvalidDataException();
            }
            Status = "verificación SHA-256";
        }
        catch (Exception error)
        {
            if (!(error is IOException || error is InvalidDataException || error is UnauthorizedAccessException || error is ArgumentException || error is FormatException)) throw;
            entries.Clear();
            Status = "caché ilegible: reescaneo";
        }
    }

    private void LoadJournal()
    {
        if (!File.Exists(journal)) return;
        try
        {
            using (BinaryReader reader = new BinaryReader(File.OpenRead(journal), Encoding.UTF8))
            {
                if (ReadField(reader) != JournalSignature || ReadField(reader) != algorithm || ReadField(reader) != roots) return;
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    int size = reader.ReadInt32(); if (size < 150 || size > 32768) break;
                    byte[] payload = reader.ReadBytes(size), digest = reader.ReadBytes(32);
                    if (payload.Length != size || digest.Length != 32) break;
                    using (SHA256 sha = SHA256.Create()) if (!EqualBytes(sha.ComputeHash(payload), digest)) break;
                    using (BinaryReader record = new BinaryReader(new MemoryStream(payload), Encoding.UTF8))
                    {
                        string id = ReadField(record), hash = ReadField(record); long length = record.ReadInt64(), ticks = record.ReadInt64(); int count = record.ReadInt32();
                        if (id.Length != 64 || hash.Length != 64 || length < 0 || ticks < 0 || count < 0 || count > validEvidence.Count) break;
                        string[] evidence = new string[count];
                        for (int i = 0; i < count; i++) { evidence[i] = ReadField(record); if (!validEvidence.Contains(evidence[i])) throw new InvalidDataException(); }
                        int scanned = record.ReadInt32(), skipped = record.ReadInt32();
                        if (scanned < 0 || skipped < 0 || record.BaseStream.Position != record.BaseStream.Length) break;
                        entries[id] = new CryptoScanCacheEntry { Hash = hash, Length = length, LastWriteTicks = ticks, Evidence = evidence, MembersScanned = scanned, MembersSkipped = skipped };
                        RecoveredEntries++;
                    }
                }
            }
        }
        catch (Exception error) { if (!(error is IOException || error is InvalidDataException || error is UnauthorizedAccessException || error is ArgumentException)) throw; }
        if (RecoveredEntries > 0) Status = "avances recuperados: verificación SHA-256";
        // Rewrite on the next checkpoint so a truncated tail cannot hide newer records.
    }
    private static bool EqualBytes(byte[] left, byte[] right)
    { if (left.Length != right.Length) return false; for (int i = 0; i < left.Length; i++) if (left[i] != right[i]) return false; return true; }

    public CryptoScanCacheEntry Find(string id)
    {
        CryptoScanCacheEntry entry;
        return entries.TryGetValue(id, out entry) ? entry : null;
    }

    public void Remember(string id, string hash, long length, long ticks, string[] evidence, int scanned, int skipped)
    {
        CryptoScanCacheEntry previous;
        if (entries.TryGetValue(id, out previous) && previous.Hash == hash && previous.Length == length && previous.LastWriteTicks == ticks && Object.ReferenceEquals(previous.Evidence, evidence))
        {
            previous.Seen = true;
            return;
        }
        string[] sorted = (string[])evidence.Clone();
        Array.Sort(sorted, StringComparer.Ordinal);
        entries[id] = new CryptoScanCacheEntry { Hash = hash, Length = length, LastWriteTicks = ticks, Evidence = sorted, Seen = true, MembersScanned = scanned, MembersSkipped = skipped };
        dirty.Add(id);
    }

    private static void WriteEntry(BinaryWriter writer, string id, CryptoScanCacheEntry entry)
    {
        writer.Write(id); writer.Write(entry.Hash); writer.Write(entry.Length); writer.Write(entry.LastWriteTicks);
        writer.Write(entry.Evidence.Length); foreach (string evidence in entry.Evidence) writer.Write(evidence);
        writer.Write(entry.MembersScanned); writer.Write(entry.MembersSkipped);
    }
    public bool Checkpoint()
    {
        if (dirty.Count == 0) return false;
        // A fresh journal includes recovered records, even if this traversal has not seen them yet.
        List<string> ids = new List<string>(journalStarted ? (IEnumerable<string>)dirty : entries.Keys); ids.Sort(StringComparer.Ordinal);
        string target = journalStarted ? journal : journal + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
        using (FileStream stream = new FileStream(target, journalStarted ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.Read))
        using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8))
        {
            if (!journalStarted) { writer.Write(JournalSignature); writer.Write(algorithm); writer.Write(roots); }
            foreach (string id in ids)
            {
                byte[] payload;
                using (MemoryStream memory = new MemoryStream()) { using (BinaryWriter record = new BinaryWriter(memory, Encoding.UTF8, true)) WriteEntry(record, id, entries[id]); payload = memory.ToArray(); }
                writer.Write(payload.Length); writer.Write(payload); using (SHA256 sha = SHA256.Create()) writer.Write(sha.ComputeHash(payload));
            }
            writer.Flush(); stream.Flush(true);
        }
        // Later checkpoints append: detach an old hard link even when its bytes are identical.
        if (!journalStarted) CryptoFileScanner.CommitOutput(target, journal, true);
        }
        finally { if (!journalStarted && File.Exists(target)) File.Delete(target); }
        journalStarted = true; dirty.Clear(); return true;
    }
    public void Finish() { if (File.Exists(journal)) File.Delete(journal); }

    public bool Save(string path)
    {
        List<string> ids = new List<string>();
        foreach (KeyValuePair<string, CryptoScanCacheEntry> item in entries) if (item.Value.Seen) ids.Add(item.Key);
        ids.Sort(StringComparer.Ordinal);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (BinaryWriter writer = new BinaryWriter(File.Create(temporary), Encoding.UTF8))
            {
                writer.Write(Signature);
                writer.Write(algorithm);
                writer.Write(roots);
                writer.Write(ids.Count);
                foreach (string id in ids)
                {
                    CryptoScanCacheEntry entry = entries[id];
                    WriteEntry(writer, id, entry);
                }
            }
            return CryptoFileScanner.CommitOutput(temporary, path);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
