using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

// Validation returns evidence types only. Source strings never leave the detector.
public static class CryptoEvidenceQuality
{
    private const string Base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const string Bech32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static readonly uint[] Generators = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    private static readonly int[] MoneroEncodedBlockSizes = { 0, 2, 3, 5, 6, 7, 9, 10, 11 };
    private static readonly BigInteger Ed25519P = (BigInteger.One << 255) - 19;
    private static readonly BigInteger Ed25519D = Mod(-new BigInteger(121665) * BigInteger.ModPow(new BigInteger(121666), Ed25519P - 2, Ed25519P));
    private static readonly BigInteger Ed25519BaseX = BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202", CultureInfo.InvariantCulture);
    private static readonly BigInteger Ed25519BaseY = BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960", CultureInfo.InvariantCulture);
    private static readonly ulong[] KeccakRoundConstants = {
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
    };
    private static readonly int[] KeccakRotations = {
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
    };

    private struct Ed25519Point
    {
        public BigInteger X, Y, Z, T;
        public Ed25519Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t) { X = x; Y = y; Z = z; T = t; }
    }

    private static BigInteger Mod(BigInteger value)
    {
        value %= Ed25519P;
        return value.Sign < 0 ? value + Ed25519P : value;
    }

    private static ulong RotateLeft(ulong value, int shift)
    { return shift == 0 ? value : (value << shift) | (value >> (64 - shift)); }

    private static void KeccakPermutation(ulong[] state)
    {
        ulong[] c = new ulong[5], d = new ulong[5], b = new ulong[25];
        for (int round = 0; round < KeccakRoundConstants.Length; round++)
        {
            for (int x = 0; x < 5; x++) c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            for (int x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ RotateLeft(c[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++) for (int x = 0; x < 5; x++) state[x + 5 * y] ^= d[x];
            for (int y = 0; y < 5; y++) for (int x = 0; x < 5; x++)
            {
                int destinationX = y;
                int destinationY = (2 * x + 3 * y) % 5;
                b[destinationX + 5 * destinationY] = RotateLeft(state[x + 5 * y], KeccakRotations[x + 5 * y]);
            }
            for (int y = 0; y < 5; y++) for (int x = 0; x < 5; x++)
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            state[0] ^= KeccakRoundConstants[round];
        }
    }

    // Keccak-256 uses the original Keccak padding (0x01), not SHA3-256 padding (0x06).
    private static byte[] Keccak256(byte[] input)
    {
        const int rate = 136;
        ulong[] state = new ulong[25];
        int offset = 0;
        while (input.Length - offset >= rate)
        {
            for (int i = 0; i < rate; i++) state[i >> 3] ^= (ulong)input[offset + i] << ((i & 7) * 8);
            KeccakPermutation(state); offset += rate;
        }
        byte[] last = new byte[rate]; int remaining = input.Length - offset;
        if (remaining > 0) Array.Copy(input, offset, last, 0, remaining);
        last[remaining] = 0x01; last[rate - 1] |= 0x80;
        for (int i = 0; i < rate; i++) state[i >> 3] ^= (ulong)last[i] << ((i & 7) * 8);
        KeccakPermutation(state);
        byte[] digest = new byte[32];
        for (int i = 0; i < digest.Length; i++) digest[i] = (byte)(state[i >> 3] >> ((i & 7) * 8));
        return digest;
    }

    public static bool EvmAddressChecksumValid(string value)
    {
        if (String.IsNullOrEmpty(value) || value.Length != 42 || !value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return false;
        bool hasLower = false, hasUpper = false;
        for (int i = 2; i < value.Length; i++)
        {
            char c = value[i];
            if (c >= 'a' && c <= 'f') hasLower = true;
            else if (c >= 'A' && c <= 'F') hasUpper = true;
            else if (c < '0' || c > '9') return false;
        }
        // Uniform-case addresses are valid EVM addresses but carry no EIP-55 case checksum.
        if (!hasLower || !hasUpper) return false;
        byte[] hash = Keccak256(Encoding.ASCII.GetBytes(value.Substring(2).ToLowerInvariant()));
        for (int i = 0; i < 40; i++)
        {
            char c = value[i + 2];
            bool hexLetter = (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hexLetter) continue;
            int nibble = (i & 1) == 0 ? hash[i >> 1] >> 4 : hash[i >> 1] & 15;
            bool shouldUpper = nibble >= 8;
            if (shouldUpper != (c >= 'A' && c <= 'F')) return false;
        }
        return true;
    }

    private static int MoneroDecodedBlockSize(int encodedSize)
    {
        for (int i = 0; i < MoneroEncodedBlockSizes.Length; i++) if (MoneroEncodedBlockSizes[i] == encodedSize) return i;
        return -1;
    }

    private static bool DecodeMoneroBlock(string text, int textOffset, int encodedSize, byte[] output, int outputOffset, int decodedSize)
    {
        ulong value = 0;
        for (int i = 0; i < encodedSize; i++)
        {
            int digit = Base58.IndexOf(text[textOffset + i]);
            if (digit < 0 || value > (UInt64.MaxValue - (uint)digit) / 58) return false;
            value = value * 58 + (uint)digit;
        }
        if (decodedSize < 8 && value >= (1UL << (decodedSize * 8))) return false;
        for (int i = decodedSize - 1; i >= 0; i--) { output[outputOffset + i] = (byte)value; value >>= 8; }
        return value == 0;
    }

    private static byte[] DecodeMoneroAddress(string value)
    {
        int fullBlocks = value.Length / 11, tailChars = value.Length % 11;
        int tailBytes = MoneroDecodedBlockSize(tailChars);
        if (tailChars != 0 && tailBytes <= 0) return null;
        byte[] decoded = new byte[fullBlocks * 8 + tailBytes];
        for (int i = 0; i < fullBlocks; i++)
            if (!DecodeMoneroBlock(value, i * 11, 11, decoded, i * 8, 8)) return null;
        if (tailChars > 0 && !DecodeMoneroBlock(value, fullBlocks * 11, tailChars, decoded, fullBlocks * 8, tailBytes)) return null;
        return decoded;
    }

    public static bool MoneroAddressChecksumValid(string value)
    {
        if (String.IsNullOrEmpty(value) || (value.Length != 95 && value.Length != 106)) return false;
        byte[] decoded = DecodeMoneroAddress(value);
        if (decoded == null || (decoded.Length != 69 && decoded.Length != 77)) return false;
        int checksumOffset = decoded.Length - 4;
        byte[] hash = Keccak256(CopyPrefix(decoded, checksumOffset));
        int difference = 0;
        for (int i = 0; i < 4; i++) difference |= hash[i] ^ decoded[checksumOffset + i];
        if (difference != 0) return false;
        int payloadLength = checksumOffset - 1;
        byte prefix = decoded[0];
        bool integrated = prefix == 19 || prefix == 25 || prefix == 54;
        bool knownPrefix = prefix == 18 || prefix == 19 || prefix == 42 ||
            prefix == 24 || prefix == 25 || prefix == 36 ||
            prefix == 53 || prefix == 54 || prefix == 63;
        return knownPrefix && payloadLength == (integrated ? 72 : 64);
    }

    private static byte[] CopyPrefix(byte[] bytes, int length)
    { byte[] result = new byte[length]; Array.Copy(bytes, result, length); return result; }

    private static BigInteger FromLittleEndianUnsigned(byte[] value, int offset, int count)
    {
        byte[] positive = new byte[count + 1]; Array.Copy(value, offset, positive, 0, count);
        return new BigInteger(positive);
    }

    private static Ed25519Point Ed25519Add(Ed25519Point p, Ed25519Point q)
    {
        BigInteger a = Mod((p.Y - p.X) * (q.Y - q.X));
        BigInteger b = Mod((p.Y + p.X) * (q.Y + q.X));
        BigInteger c = Mod(2 * Ed25519D * p.T * q.T);
        BigInteger d = Mod(2 * p.Z * q.Z);
        BigInteger e = Mod(b - a), f = Mod(d - c), g = Mod(d + c), h = Mod(b + a);
        return new Ed25519Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static Ed25519Point Ed25519Double(Ed25519Point p)
    {
        BigInteger a = Mod(p.X * p.X), b = Mod(p.Y * p.Y), c = Mod(2 * p.Z * p.Z), d = Mod(-a);
        BigInteger e = Mod((p.X + p.Y) * (p.X + p.Y) - a - b);
        BigInteger g = Mod(d + b), f = Mod(g - c), h = Mod(d - b);
        return new Ed25519Point(Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h));
    }

    private static byte[] Ed25519PublicFromSeed(byte[] seed)
    {
        byte[] expanded;
        using (SHA512 sha = SHA512.Create()) expanded = sha.ComputeHash(seed);
        expanded[0] &= 248; expanded[31] &= 63; expanded[31] |= 64;
        BigInteger scalar = FromLittleEndianUnsigned(expanded, 0, 32);
        Ed25519Point identity = new Ed25519Point(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
        Ed25519Point point = new Ed25519Point(Ed25519BaseX, Ed25519BaseY, BigInteger.One, Mod(Ed25519BaseX * Ed25519BaseY));
        Ed25519Point result = identity;
        for (int bit = 0; bit < 255; bit++)
        {
            if ((bit & 31) == 0) CryptoFileScanner.ThrowIfCancelled();
            if (!scalar.IsEven) result = Ed25519Add(result, point);
            scalar >>= 1;
            point = Ed25519Double(point);
        }
        BigInteger inverse = BigInteger.ModPow(result.Z, Ed25519P - 2, Ed25519P);
        BigInteger x = Mod(result.X * inverse), y = Mod(result.Y * inverse);
        byte[] little = y.ToByteArray(), encoded = new byte[32];
        Array.Copy(little, encoded, Math.Min(little.Length, encoded.Length));
        if (!x.IsEven) encoded[31] |= 0x80;
        Array.Clear(expanded, 0, expanded.Length);
        return encoded;
    }

    public static bool SolanaKeypairMatches(byte[] keypair)
    {
        if (keypair == null || keypair.Length != 64) return false;
        byte[] seed = new byte[32]; Array.Copy(keypair, 0, seed, 0, seed.Length);
        byte[] publicKey = Ed25519PublicFromSeed(seed);
        int difference = 0;
        for (int i = 0; i < 32; i++) difference |= publicKey[i] ^ keypair[32 + i];
        Array.Clear(seed, 0, seed.Length); Array.Clear(publicKey, 0, publicKey.Length);
        return difference == 0;
    }

    public static bool BitcoinAddressValid(string value)
    {
        if (String.IsNullOrEmpty(value) || value.Length > 90) return false;
        if (value.StartsWith("bc1", StringComparison.OrdinalIgnoreCase) || value.StartsWith("tb1", StringComparison.OrdinalIgnoreCase) || value.StartsWith("bcrt1", StringComparison.OrdinalIgnoreCase)) return WitnessValid(value);
        if (value.Length < 26 || value.Length > 35) return false;
        var bytes = new List<byte> { 0 };
        foreach (char c in value)
        {
            int carry = Base58.IndexOf(c); if (carry < 0) return false;
            for (int i = 0; i < bytes.Count; i++) { carry += bytes[i] * 58; bytes[i] = (byte)carry; carry >>= 8; }
            while (carry > 0) { bytes.Add((byte)carry); carry >>= 8; }
        }
        for (int i = 0; i < value.Length - 1 && value[i] == '1'; i++) bytes.Add(0);
        bytes.Reverse(); byte[] b = bytes.ToArray();
        if (b.Length != 25 || (b[0] != 0 && b[0] != 5 && b[0] != 111 && b[0] != 196)) return false;
        using (var sha = SHA256.Create())
        { byte[] h = sha.ComputeHash(sha.ComputeHash(b, 0, 21)); for (int i = 0; i < 4; i++) if (h[i] != b[21 + i]) return false; }
        return true;
    }
    private static uint Step(uint check, int value)
    {
        uint top = check >> 25; check = ((check & 0x1ffffff) << 5) ^ (uint)value;
        for (int i = 0; i < 5; i++) if (((top >> i) & 1) != 0) check ^= Generators[i];
        return check;
    }
    private static bool WitnessValid(string s)
    {
        if (s != s.ToLowerInvariant() && s != s.ToUpperInvariant()) return false;
        s = s.ToLowerInvariant(); int pos = s.LastIndexOf('1');
        if (pos < 1 || s.Length - pos < 8) return false;
        string hrp = s.Substring(0, pos); if (hrp != "bc" && hrp != "tb" && hrp != "bcrt") return false;
        uint check = 1;
        foreach (char c in hrp) check = Step(check, c >> 5);
        check = Step(check, 0); foreach (char c in hrp) check = Step(check, c & 31);
        var data = new List<int>();
        for (int i = pos + 1; i < s.Length; i++) { int n = Bech32.IndexOf(s[i]); if (n < 0) return false; data.Add(n); check = Step(check, n); }
        int version = data[0]; if (version > 16 || check != (version == 0 ? 1U : 0x2bc830a3U)) return false;
        int acc = 0, bits = 0, count = 0;
        for (int i = 1; i < data.Count - 6; i++) { acc = ((acc << 5) | data[i]) & 4095; bits += 5; while (bits >= 8) { bits -= 8; count++; } }
        if (bits >= 5 || ((acc << (8 - bits)) & 255) != 0 || count < 2 || count > 40) return false;
        return version != 0 || count == 20 || count == 32;
    }

    private static object Field(Dictionary<string, object> d, string key)
    { object value; return d != null && d.TryGetValue(key, out value) ? value : null; }

    private static bool ElectrumKeystoreValid(object value)
    {
        var keystore = value as Dictionary<string, object>;
        string type = Field(keystore, "type") as string;
        if (type == null) return false;
        if (type == "bip32" || type == "hardware")
        {
            string xpub = Field(keystore, "xpub") as string;
            string xprv = Field(keystore, "xprv") as string;
            return CryptoKeyValidation.ExtendedPublicKeyValid(xpub) ||
                !String.IsNullOrEmpty(xprv) && CryptoKeyValidation.Valid(xprv, true);
        }
        if (type == "old") return Hex(Field(keystore, "mpk"), 64);
        if (type == "imported")
        {
            var pairs = Field(keystore, "keypairs") as Dictionary<string, object>;
            if (pairs == null || pairs.Count == 0) return false;
            foreach (var pair in pairs)
            {
                string privateValue = pair.Value as string;
                bool publicKeyShape = pair.Key != null && Regex.IsMatch(pair.Key, "\\A(?:[0-9a-fA-F]{66}|[0-9a-fA-F]{130})\\z");
                if (publicKeyShape && !String.IsNullOrWhiteSpace(privateValue)) return true;
            }
        }
        return false;
    }

    public static bool ElectrumWalletStructureValid(string json)
    {
        const int MaxCharacters = 16 * 1024 * 1024;
        if (String.IsNullOrEmpty(json) || json.Length > MaxCharacters ||
            json.IndexOf("\"wallet_type\"", StringComparison.OrdinalIgnoreCase) < 0 ||
            json.IndexOf("\"seed_version\"", StringComparison.OrdinalIgnoreCase) < 0) return false;
        try
        {
            var parser = new JavaScriptSerializer { MaxJsonLength = MaxCharacters, RecursionLimit = 64 };
            var root = parser.DeserializeObject(json) as Dictionary<string, object>;
            string walletType = Field(root, "wallet_type") as string;
            object version = Field(root, "seed_version");
            long seedVersion;
            if (walletType == null || !(version is int || version is long) ||
                !Int64.TryParse(Convert.ToString(version, System.Globalization.CultureInfo.InvariantCulture), out seedVersion) ||
                seedVersion < 4 || seedVersion > 73) return false;
            bool recognizedType = walletType == "old" || walletType == "standard" || walletType == "imported" ||
                walletType == "multisig" || walletType == "2fa" || walletType == "bip44" || walletType == "xpub" ||
                walletType == "trezor" || walletType == "keepkey" || walletType == "ledger" || walletType == "btchip";
            Match multisig = Regex.Match(walletType, "\\A([1-9][0-9]?)of([1-9][0-9]?)\\z");
            if (!recognizedType && !multisig.Success) return false;
            if (multisig.Success)
            {
                int required = Int32.Parse(multisig.Groups[1].Value), total = Int32.Parse(multisig.Groups[2].Value);
                if (required > total || total > 15) return false;
            }
            if (ElectrumKeystoreValid(Field(root, "keystore"))) return true;
            for (int i = 1; i <= 15; i++) if (ElectrumKeystoreValid(Field(root, "x" + i + "/"))) return true;
            return false;
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (OverflowException) { return false; }
    }

    private static bool Hex(object value, int bytes)
    {
        string s = value as string; if (s == null || s.Length != bytes * 2) return false;
        foreach (char c in s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
        return true;
    }
    private static bool Positive(object value)
    { return value is int && (int)value > 0 || value is long && (long)value > 0; }
    private static bool Salt(object value)
    {
        string s = value as string; return s != null && s.Length >= 2 && s.Length <= 512 && (s.Length & 1) == 0 && Hex(s, s.Length / 2);
    }
    public static bool KeystoreV3Valid(string json)
    {
        if (String.IsNullOrEmpty(json) || json.Length > 65536) return false;
        try
        {
            var parser = new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 32 };
            var root = parser.DeserializeObject(json) as Dictionary<string, object>;
            if (!Object.Equals(Field(root, "version"), 3)) return false;
            var crypto = (Field(root, "crypto") ?? Field(root, "Crypto")) as Dictionary<string, object>;
            if (!Object.Equals(Field(crypto, "cipher"), "aes-128-ctr") || !Hex(Field(crypto, "ciphertext"), 32) || !Hex(Field(crypto, "mac"), 32)) return false;
            var cipher = Field(crypto, "cipherparams") as Dictionary<string, object>;
            var kdf = Field(crypto, "kdfparams") as Dictionary<string, object>;
            if (!Hex(Field(cipher, "iv"), 16) || !Object.Equals(Field(kdf, "dklen"), 32) || !Salt(Field(kdf, "salt"))) return false;
            if (Object.Equals(Field(crypto, "kdf"), "scrypt"))
            {
                object n = Field(kdf, "n"); if (!Positive(n) || !Positive(Field(kdf, "r")) || !Positive(Field(kdf, "p"))) return false;
                long count = Convert.ToInt64(n); return count > 1 && (count & (count - 1)) == 0;
            }
            return Object.Equals(Field(crypto, "kdf"), "pbkdf2") && Positive(Field(kdf, "c")) && Object.Equals(Field(kdf, "prf"), "hmac-sha256");
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (OverflowException) { return false; }
    }
    public static bool ContainsKeystoreV3(string text)
    {
        // Bound both parsing and nesting, including objects embedded in JSON arrays or logs.
        var starts = new List<int>(); bool quoted = false, escaped = false;
        for (int i = 0; i < text.Length; i++)
        {
            if ((i & 4095) == 0) CryptoFileScanner.ThrowIfCancelled();
            char c = text[i];
            if (quoted) { if (escaped) escaped = false; else if (c == '\\') escaped = true; else if (c == '"') quoted = false; continue; }
            if (c == '"') { quoted = true; continue; }
            if (c == '{') { starts.Add(i); if (starts.Count > 32) return false; }
            else if (c == '}' && starts.Count > 0)
            {
                int start = starts[starts.Count - 1]; starts.RemoveAt(starts.Count - 1);
                int length = i - start + 1;
                if (length <= 65536 && text.IndexOf("\"version\"", start, length, StringComparison.Ordinal) >= 0 && KeystoreV3Valid(text.Substring(start, length))) return true;
            }
        }
        return false;
    }
}
