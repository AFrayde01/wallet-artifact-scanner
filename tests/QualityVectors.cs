using System;
using System.Collections.Generic;
using System.Text;
public static class QualityVectors
{
    public static string ExtendedPublicKey()
    {
        byte[] payload = new byte[78];
        payload[0] = 0x04; payload[1] = 0x88; payload[2] = 0xb2; payload[3] = 0x1e;
        payload[45] = 0x02; payload[46] = 1;
        byte[] digest; using (var sha = System.Security.Cryptography.SHA256.Create()) digest = sha.ComputeHash(sha.ComputeHash(payload));
        byte[] number = new byte[payload.Length + 4]; Array.Copy(payload, number, payload.Length); Array.Copy(digest, 0, number, payload.Length, 4);
        const string alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; var result = new StringBuilder();
        int first = 0;
        while (first < number.Length)
        {
            int remainder = 0;
            for (int i = first; i < number.Length; i++) { int value = remainder * 256 + number[i]; number[i] = (byte)(value / 58); remainder = value % 58; }
            result.Insert(0, alphabet[remainder]); while (first < number.Length && number[first] == 0) first++;
        }
        return result.ToString();
    }

    public static string Wif(bool compressed)
    {
        byte[] payload = new byte[compressed ? 34 : 33]; payload[0] = 239; payload[32] = 1; if (compressed) payload[33] = 1;
        byte[] digest; using (var sha = System.Security.Cryptography.SHA256.Create()) digest = sha.ComputeHash(sha.ComputeHash(payload));
        byte[] number = new byte[payload.Length + 4]; Array.Copy(payload, number, payload.Length); Array.Copy(digest, 0, number, payload.Length, 4);
        const string alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; var result = new StringBuilder();
        int first = 0;
        while (first < number.Length)
        {
            int remainder = 0;
            for (int i = first; i < number.Length; i++) { int value = remainder * 256 + number[i]; number[i] = (byte)(value / 58); remainder = value % 58; }
            result.Insert(0, alphabet[remainder]); while (first < number.Length && number[first] == 0) first++;
        }
        return result.ToString();
    }
    public static string Monero(string[] words, int prefix, bool abbreviate)
    {
        var parts = new List<string>(); var crcText = new StringBuilder();
        var counts = new Dictionary<string, int>();
        foreach (string w in words) { string p = w.Substring(0, Math.Min(prefix, w.Length)); int n; counts.TryGetValue(p, out n); counts[p] = n + 1; }
        var usable = new List<string>(); foreach (string w in words) if (counts[w.Substring(0, Math.Min(prefix, w.Length))] == 1) usable.Add(w);
        for (int i = 0; i < 24; i++) { string word = usable[(i * 13 + 17) % usable.Count]; parts.Add(abbreviate ? word.Substring(0, Math.Min(prefix, word.Length)) : word); crcText.Append(word.Substring(0, Math.Min(prefix, word.Length))); }
        uint crc = 0xffffffff;
        foreach (byte b in Encoding.UTF8.GetBytes(crcText.ToString())) { crc ^= b; for (int i = 0; i < 8; i++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320 : crc >> 1; }
        parts.Add(parts[(int)((crc ^ 0xffffffff) % 24)]); return String.Join(" ", parts.ToArray());
    }
    public static string Witness(string hrp, int version, int bytes, bool wrongChecksum, int extraPadding)
    {
        const string alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        var data = new List<int> { version }; int acc = 0, bits = 0;
        for (int i = 0; i < bytes; i++) { acc = ((acc << 8) | (i * 13 + 7) % 256) & 65535; bits += 8; while (bits >= 5) { bits -= 5; data.Add((acc >> bits) & 31); } }
        if (bits > 0) data.Add((acc << (5 - bits)) & 31);
        for (int i = 0; i < extraPadding; i++) data.Add(0);
        var values = new List<int>(); foreach (char c in hrp) values.Add(c >> 5); values.Add(0); foreach (char c in hrp) values.Add(c & 31);
        values.AddRange(data); values.AddRange(new int[6]);
        uint chk = 1; uint[] gen = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
        foreach (int v in values) { uint top = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ (uint)v; for (int i = 0; i < 5; i++) if (((top >> i) & 1) != 0) chk ^= gen[i]; }
        chk ^= (version == 0) != wrongChecksum ? 1U : 0x2bc830a3U;
        var result = new StringBuilder(hrp + "1"); foreach (int n in data) result.Append(alphabet[n]);
        for (int i = 0; i < 6; i++) result.Append(alphabet[(int)((chk >> (5 * (5 - i))) & 31)]);
        return result.ToString();
    }

    public static string SolanaKeypairJson(bool corruptPublic)
    {
        // RFC 8032 Ed25519 test vector 1: a public seed and its matching public key.
        const string seedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        const string publicHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        byte[] pair = new byte[64];
        for (int i = 0; i < 32; i++)
        {
            pair[i] = Convert.ToByte(seedHex.Substring(i * 2, 2), 16);
            pair[32 + i] = Convert.ToByte(publicHex.Substring(i * 2, 2), 16);
        }
        if (corruptPublic) pair[63] ^= 1;
        var result = new StringBuilder("[");
        for (int i = 0; i < pair.Length; i++) { if (i > 0) result.Append(','); result.Append(pair[i]); }
        result.Append(']');
        return result.ToString();
    }
}
