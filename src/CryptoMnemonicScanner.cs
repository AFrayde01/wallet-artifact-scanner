using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

public static class CryptoMnemonicScanner
{
    private sealed class MoneroWordList
    {
        public string[] Words;
        public int PrefixLength;
        public Dictionary<string, int> WordIndices;
        public Dictionary<string, int> PrefixIndices;
    }

    private static Dictionary<string, int[]> Bip39Words;
    private static Dictionary<string, int> Slip39;
    private static MoneroWordList[] MoneroLists;
    private static Dictionary<string, int[]> MoneroExactWords;
    private static Dictionary<string, int[]> MoneroThreeLetterPrefixes;
    private static Dictionary<string, int[]> MoneroFourLetterPrefixes;
    private static readonly int[] Bip39Lengths = new int[] { 12, 15, 18, 21, 24 };
    // Published Trezor BIP39 vector entropies (12, 18 and 24 words).
    // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    // Entropy identifies the same public example across supported languages; never exported.
    private static readonly HashSet<string> PublicBip39Examples = new HashSet<string>(StringComparer.Ordinal) {
        "00000000000000000000000000000000", "000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "23db8160a31d3e0dca3688ed941adbf3", "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "80808080808080808080808080808080", "808080808080808080808080808080808080808080808080",
        "8080808080808080808080808080808080808080808080808080808080808080",
        "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0", "9e885d952ad362caeb4efe34a8e91bd2",
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "c0ba5a8e914111210f2bd131f3d5e08d", "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        "f30f8c1da665478f49b001d94c5fc452", "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    };
    public static bool Bip39Only { get; set; }
    public static bool AllowPunctuationSeparators { get; set; }

    public static void Configure(
        string[] bip39English,
        string[] bip39Spanish,
        string[] moneroEnglish,
        string[] moneroEnglishOld,
        string[] moneroSpanish,
        string[] slip39)
    {
        Bip39Only = false;
        AllowPunctuationSeparators = false;
        Bip39Words = BuildBip39Index(bip39English, bip39Spanish);
        Slip39 = BuildWordIndex(slip39, NormalizationForm.FormKD);
        MoneroLists = new MoneroWordList[]
        {
            BuildMoneroList(moneroEnglish, 3),
            BuildMoneroList(moneroEnglishOld, 4),
            BuildMoneroList(moneroSpanish, 4)
        };
        BuildCombinedMoneroIndices();
    }

    public static string[] Scan(string text)
    {
        if (String.IsNullOrEmpty(text) || Bip39Words == null || MoneroLists == null || Slip39 == null)
        {
            return new string[0];
        }

        List<int> englishSequence = new List<int>(24);
        List<int> spanishSequence = new List<int>(24);
        List<int> slipSequence = new List<int>(33);
        List<int>[] moneroSequences = new List<int>[MoneroLists.Length];
        for (int i = 0; i < moneroSequences.Length; i++)
        {
            moneroSequences[i] = new List<int>(25);
        }

        bool foundBip39 = false;
        bool foundMonero = false;
        bool foundSlip39 = false;
        var quality = new List<int>(33);
        var result = new HashSet<string>(StringComparer.Ordinal);
        int previousEnd = -1;

        for (int cursor = 0; cursor < text.Length; )
        {
            CryptoFileScanner.ThrowIfCancelled();
            while (cursor < text.Length && !IsWordCharacter(text[cursor])) cursor++;
            int start = cursor;
            while (cursor < text.Length && IsWordCharacter(text[cursor])) cursor++;
            int length = cursor - start;
            if (length == 0) break;
            bool embedded = (start > 0 && IsIdentifierCharacter(text[start - 1])) || (cursor < text.Length && IsIdentifierCharacter(text[cursor]));
            int gapQuality = embedded ? 2 : 0;
            if (previousEnd >= 0 && !AllowedSeparator(text, previousEnd, start - previousEnd)) gapQuality |= 1;
            previousEnd = cursor;
            AddWindowWord(quality, gapQuality, 33);
            if (length > 32)
            {
                englishSequence.Clear();
                spanishSequence.Clear();
                slipSequence.Clear();
                foreach (List<int> sequence in moneroSequences) sequence.Clear();
                continue;
            }
            string tokenValue = text.Substring(start, length);
            string normalizedKd = NormalizeToken(tokenValue, NormalizationForm.FormKD);

            if (!foundBip39 || AllowPunctuationSeparators)
            {
                int[] wordIndices;
                if (Bip39Words.TryGetValue(normalizedKd, out wordIndices))
                {
                    if (wordIndices[0] >= 0)
                    {
                        AddWindowWord(englishSequence, wordIndices[0], 24);
                        foundBip39 |= RecordBip39(englishSequence, quality, result);
                    }
                    else englishSequence.Clear();

                    if (wordIndices[1] >= 0)
                    {
                        AddWindowWord(spanishSequence, wordIndices[1], 24);
                        foundBip39 |= RecordBip39(spanishSequence, quality, result);
                    }
                    else spanishSequence.Clear();
                }
                else
                {
                    englishSequence.Clear();
                    spanishSequence.Clear();
                }
            }

            if (!Bip39Only && !foundSlip39)
            {
                int slipWordIndex;
                if (!Slip39.TryGetValue(normalizedKd, out slipWordIndex))
                {
                    slipSequence.Clear();
                }
                else
                {
                    AddWindowWord(slipSequence, slipWordIndex, 33);
                    foreach (int n in new int[] { 20, 33 })
                        if (slipSequence.Count >= n && NeedsCheck("slip39", slipSequence, n, quality, result) && TestSlip39Checksum(slipSequence, n))
                            foundSlip39 |= Record("slip39", slipSequence, n, quality, result);
                }
            }

            if (!Bip39Only && !foundMonero)
            {
                string normalizedMonero = NormalizeToken(tokenValue, NormalizationForm.FormC);
                int[] exactIndices;
                if (!MoneroExactWords.TryGetValue(normalizedMonero, out exactIndices)) exactIndices = null;
                int[] prefix3Indices = null;
                int[] prefix4Indices = null;
                if (normalizedMonero.Length == 3) MoneroThreeLetterPrefixes.TryGetValue(normalizedMonero, out prefix3Indices);
                if (normalizedMonero.Length == 4) MoneroFourLetterPrefixes.TryGetValue(normalizedMonero, out prefix4Indices);
                for (int i = 0; i < MoneroLists.Length; i++)
                {
                    int wordIndex = exactIndices == null ? -1 : exactIndices[i];
                    if (wordIndex < 0 && i == 0 && normalizedMonero.Length == 3 && prefix3Indices != null) wordIndex = prefix3Indices[0];
                    if (wordIndex < 0 && i > 0 && normalizedMonero.Length == 4 && prefix4Indices != null) wordIndex = prefix4Indices[i];
                    List<int> sequence = moneroSequences[i];
                    if (wordIndex < 0)
                    {
                        sequence.Clear();
                        continue;
                    }

                    AddWindowWord(sequence, wordIndex, 25);
                    if (sequence.Count == 25 && NeedsCheck("monero", sequence, 25, quality, result) && HasMoneroChecksum(sequence, MoneroLists[i]))
                    {
                        foundMonero |= Record("monero", sequence, 25, quality, result);
                        if (foundMonero) break;
                    }
                }
            }

            if (foundBip39 && !AllowPunctuationSeparators && (Bip39Only || foundMonero && foundSlip39)) break;
        }

        string[] ids = new string[result.Count]; result.CopyTo(ids); Array.Sort(ids, StringComparer.Ordinal); return ids;
    }

    private static bool IsIdentifierCharacter(char c) { return IsWordCharacter(c) || Char.IsDigit(c) || c == '_'; }
    private static bool AllowedSeparator(string text, int start, int length)
    {
        if (length < 1 || length > 256) return false;
        bool whitespace = true, quotedList = true, comma = false;
        int end = start + length;
        for (int i = start; i < end; i++)
        {
            char c = text[i]; if (Char.IsWhiteSpace(c)) continue;
            whitespace = false; if (c == ',') comma = true;
            if (c != ',' && c != '\'' && c != '"') quotedList = false;
        }
        if (whitespace) return true;
        if (quotedList && comma) return true;
        if (AllowPunctuationSeparators)
        {
            bool punctuation = false;
            for (int i = start; i < end; i++)
            {
                char c = text[i];
                if (Char.IsWhiteSpace(c)) continue;
                if (Char.IsPunctuation(c) || Char.IsSymbol(c)) { punctuation = true; continue; }
                return false;
            }
            if (punctuation) return true;
        }
        int cursor = start;
        while (cursor < end && Char.IsWhiteSpace(text[cursor])) cursor++;
        if (cursor == start) return false;
        int numberStart = cursor;
        while (cursor < end && text[cursor] >= '0' && text[cursor] <= '9') cursor++;
        if (cursor == numberStart || cursor - numberStart > 2 || cursor >= end || text[cursor] != '.' && text[cursor] != ')') return false;
        cursor++; int suffix = cursor;
        while (cursor < end && Char.IsWhiteSpace(text[cursor])) cursor++;
        return cursor > suffix && cursor == end;
    }
    private static bool RecordBip39(List<int> sequence, List<int> quality, HashSet<string> result)
    {
        bool strong = false;
        foreach (int length in Bip39Lengths)
        {
            bool example;
            if (sequence.Count >= length && NeedsCheck("bip39", sequence, length, quality, result) && TestBip39Checksum(sequence, length, out example))
            {
                if (example) result.Add("mnemonic_bip39_public_example_candidate");
                else strong |= Record("bip39", sequence, length, quality, result);
            }
        }
        return strong;
    }
    private static string QualityIssue(List<int> words, int length, List<int> quality)
    {
        int start = words.Count - length, qstart = quality.Count - length;
        bool ascending = true;
        int first = words[start], second = -1, third = -1;
        bool diverse = false;
        for (int i = 0; i < length; i++)
        {
            if ((quality[qstart + i] & 2) != 0 || i > 0 && (quality[qstart + i] & 1) != 0) return "fragmented";
            int word = words[start + i];
            if (!diverse && word != first && word != second && word != third)
            { if (second < 0) second = word; else if (third < 0) third = word; else diverse = true; }
            if (i > 0 && words[start + i] != words[start + i - 1] + 1) ascending = false;
        }
        return ascending ? "dictionary" : !diverse ? "repetitive" : "";
    }
    private static bool NeedsCheck(string family, List<int> words, int length, List<int> quality, HashSet<string> result)
    {
        string issue = QualityIssue(words, length, quality);
        return issue.Length == 0 || !result.Contains("mnemonic_" + family + "_" + issue + "_candidate");
    }
    private static bool Record(string family, List<int> words, int length, List<int> quality, HashSet<string> result)
    {
        string issue = QualityIssue(words, length, quality);
        if (issue.Length > 0) { result.Add("mnemonic_" + family + "_" + issue + "_candidate"); return false; }
        result.Add(family == "slip39" ? "possible_slip39_share" : "possible_" + family + "_mnemonic_phrase");
        return true;
    }

    private static bool IsWordCharacter(char value)
    {
        if (value <= 127) return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
        if (Char.IsLetter(value)) return true;
        UnicodeCategory category = Char.GetUnicodeCategory(value);
        return category == UnicodeCategory.NonSpacingMark || category == UnicodeCategory.SpacingCombiningMark || category == UnicodeCategory.EnclosingMark;
    }

    private static Dictionary<string, int> BuildWordIndex(string[] words, NormalizationForm normalizationForm)
    {
        if (words == null) throw new ArgumentNullException("words");
        Dictionary<string, int> result = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < words.Length; i++)
        {
            string normalized = Normalize(words[i].Trim(), normalizationForm);
            if (normalized.Length == 0 || result.ContainsKey(normalized))
            {
                throw new ArgumentException("Invalid or duplicated mnemonic word.");
            }
            result.Add(normalized, i);
        }
        return result;
    }

    private static Dictionary<string, int[]> BuildBip39Index(string[] englishWords, string[] spanishWords)
    {
        Dictionary<string, int[]> result = new Dictionary<string, int[]>(StringComparer.Ordinal);
        AddBip39Words(result, englishWords, 0);
        AddBip39Words(result, spanishWords, 1);
        return result;
    }

    private static void AddBip39Words(Dictionary<string, int[]> index, string[] words, int languageIndex)
    {
        if (words == null) throw new ArgumentNullException("words");
        for (int i = 0; i < words.Length; i++)
        {
            string normalized = Normalize(words[i].Trim(), NormalizationForm.FormKD);
            int[] indices;
            if (!index.TryGetValue(normalized, out indices))
            {
                indices = new int[] { -1, -1 };
                index.Add(normalized, indices);
            }
            if (indices[languageIndex] >= 0) throw new ArgumentException("Invalid or duplicated BIP-39 word.");
            indices[languageIndex] = i;
        }
    }

    private static MoneroWordList BuildMoneroList(string[] words, int prefixLength)
    {
        if (words == null) throw new ArgumentNullException("words");
        MoneroWordList result = new MoneroWordList();
        result.Words = (string[])words.Clone();
        result.PrefixLength = prefixLength;
        result.WordIndices = new Dictionary<string, int>(StringComparer.Ordinal);
        result.PrefixIndices = new Dictionary<string, int>(StringComparer.Ordinal);
        HashSet<string> ambiguous = new HashSet<string>(StringComparer.Ordinal);

        for (int i = 0; i < words.Length; i++)
        {
            string word = words[i].Trim();
            string normalizedWord = Normalize(word, NormalizationForm.FormC);
            if (normalizedWord.Length == 0 || result.WordIndices.ContainsKey(normalizedWord))
            {
                throw new ArgumentException("Invalid or duplicated Monero word.");
            }
            result.WordIndices.Add(normalizedWord, i);

            string prefix = word.Substring(0, Math.Min(prefixLength, word.Length));
            string normalizedPrefix = Normalize(prefix, NormalizationForm.FormC);
            if (ambiguous.Contains(normalizedPrefix)) continue;
            if (result.PrefixIndices.ContainsKey(normalizedPrefix))
            {
                result.PrefixIndices.Remove(normalizedPrefix);
                ambiguous.Add(normalizedPrefix);
                continue;
            }
            result.PrefixIndices.Add(normalizedPrefix, i);
        }
        return result;
    }

    private static void BuildCombinedMoneroIndices()
    {
        MoneroExactWords = new Dictionary<string, int[]>(StringComparer.Ordinal);
        MoneroThreeLetterPrefixes = new Dictionary<string, int[]>(StringComparer.Ordinal);
        MoneroFourLetterPrefixes = new Dictionary<string, int[]>(StringComparer.Ordinal);

        for (int listIndex = 0; listIndex < MoneroLists.Length; listIndex++)
        {
            foreach (KeyValuePair<string, int> word in MoneroLists[listIndex].WordIndices)
            {
                int[] indices;
                if (!MoneroExactWords.TryGetValue(word.Key, out indices))
                {
                    indices = new int[] { -1, -1, -1 };
                    MoneroExactWords.Add(word.Key, indices);
                }
                indices[listIndex] = word.Value;
            }

            foreach (KeyValuePair<string, int> prefix in MoneroLists[listIndex].PrefixIndices)
            {
                Dictionary<string, int[]> destination = listIndex == 0 ? MoneroThreeLetterPrefixes : MoneroFourLetterPrefixes;
                int[] indices;
                if (!destination.TryGetValue(prefix.Key, out indices))
                {
                    indices = new int[] { -1, -1, -1 };
                    destination.Add(prefix.Key, indices);
                }
                indices[listIndex] = prefix.Value;
            }
        }
    }

    private static string Normalize(string word, NormalizationForm normalizationForm)
    {
        return word.Normalize(normalizationForm).ToLowerInvariant();
    }

    private static string NormalizeToken(string word, NormalizationForm normalizationForm)
    {
        bool allLowerAscii = true;
        bool allAscii = true;
        for (int i = 0; i < word.Length; i++)
        {
            char character = word[i];
            if (character > 127)
            {
                allAscii = false;
                allLowerAscii = false;
                break;
            }
            if (character >= 'A' && character <= 'Z') allLowerAscii = false;
        }
        if (allLowerAscii) return word;
        if (allAscii) return word.ToLowerInvariant();
        return Normalize(word, normalizationForm);
    }

    private static void AddWindowWord(List<int> sequence, int wordIndex, int maxLength)
    {
        sequence.Add(wordIndex);
        if (sequence.Count > maxLength) sequence.RemoveAt(0);
    }

    private static bool HasBip39Checksum(List<int> sequence)
    {
        for (int i = 0; i < Bip39Lengths.Length; i++)
        {
            if (sequence.Count >= Bip39Lengths[i] && TestBip39Checksum(sequence, Bip39Lengths[i])) return true;
        }
        return false;
    }

    private static bool TestBip39Checksum(List<int> sequence, int phraseLength)
    { bool example; return TestBip39Checksum(sequence, phraseLength, out example); }

    private static bool TestBip39Checksum(List<int> sequence, int phraseLength, out bool example)
    {
        example = false;
        int totalBitCount = phraseLength * 11;
        int entropyBitCount = (totalBitCount * 32) / 33;
        int checksumBitCount = totalBitCount - entropyBitCount;
        byte[] entropy = new byte[entropyBitCount / 8];
        int sequenceStart = sequence.Count - phraseLength;

        for (int bitIndex = 0; bitIndex < entropyBitCount; bitIndex++)
        {
            int wordIndex = sequenceStart + (bitIndex / 11);
            int wordBitOffset = 10 - (bitIndex % 11);
            int bit = (sequence[wordIndex] >> wordBitOffset) & 1;
            entropy[bitIndex / 8] |= (byte)(bit << (7 - (bitIndex % 8)));
        }

        byte[] hash;
        using (SHA256 sha = SHA256.Create()) hash = sha.ComputeHash(entropy);
        for (int checksumIndex = 0; checksumIndex < checksumBitCount; checksumIndex++)
        {
            int phraseBitIndex = entropyBitCount + checksumIndex;
            int wordIndex = sequenceStart + (phraseBitIndex / 11);
            int wordBitOffset = 10 - (phraseBitIndex % 11);
            bool actual = ((sequence[wordIndex] >> wordBitOffset) & 1) != 0;
            bool expected = (hash[checksumIndex / 8] & (1 << (7 - (checksumIndex % 8)))) != 0;
            if (actual != expected) return false;
        }
        example = PublicBip39Examples.Contains(BitConverter.ToString(entropy).Replace("-", "").ToLowerInvariant());
        return true;
    }

    private static bool HasMoneroChecksum(List<int> sequence, MoneroWordList wordList)
    {
        StringBuilder prefixes = new StringBuilder(96);
        for (int i = 0; i < 24; i++)
        {
            string word = wordList.Words[sequence[i]].Trim();
            prefixes.Append(word.Substring(0, Math.Min(wordList.PrefixLength, word.Length)));
        }
        byte[] bytes = Encoding.UTF8.GetBytes(prefixes.ToString());
        uint crc = ComputeCrc32(bytes);
        int checksumIndex = (int)(crc % 24);
        return sequence[checksumIndex] == sequence[24];
    }

    private static uint ComputeCrc32(byte[] bytes)
    {
        uint crc = 0xFFFFFFFF;
        for (int i = 0; i < bytes.Length; i++)
        {
            crc ^= bytes[i];
            for (int bit = 0; bit < 8; bit++)
            {
                if ((crc & 1) != 0) crc = (crc >> 1) ^ 0xEDB88320;
                else crc >>= 1;
            }
        }
        return crc ^ 0xFFFFFFFF;
    }

    private static bool HasSlip39Checksum(List<int> sequence)
    {
        if (sequence.Count < 20) return false;
        if (TestSlip39Checksum(sequence, 20)) return true;
        return sequence.Count >= 33 && TestSlip39Checksum(sequence, 33);
    }

    private static bool TestSlip39Checksum(List<int> sequence, int phraseLength)
    {
        bool extendable = ((sequence[sequence.Count - phraseLength + 1] >> 4) & 1) == 1;
        string customization = extendable ? "shamir_extendable" : "shamir";
        List<int> values = new List<int>(customization.Length + phraseLength);
        for (int i = 0; i < customization.Length; i++) values.Add((int)customization[i]);
        int sequenceStart = sequence.Count - phraseLength;
        for (int i = sequenceStart; i < sequence.Count; i++) values.Add(sequence[i]);
        return Slip39Polymod(values) == 1;
    }

    private static long Slip39Polymod(List<int> values)
    {
        long[] generators = new long[]
        {
            0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
            0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120
        };
        long check = 1;
        for (int valueIndex = 0; valueIndex < values.Count; valueIndex++)
        {
            long top = check >> 20;
            check = ((check & 1048575) << 10) ^ values[valueIndex];
            for (int i = 0; i < 10; i++)
            {
                if ((top & (1L << i)) != 0) check ^= generators[i];
            }
        }
        return check;
    }
}
