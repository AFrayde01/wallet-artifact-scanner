using System;
using System.Collections.Generic;
using System.Security.Cryptography;

public static class CryptoKeyValidation
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static readonly byte[] Order = new byte[] { 255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,254,186,174,220,230,175,72,160,59,191,210,94,140,208,54,65,65 };

    public static bool ExtendedPublicKeyValid(string text)
    {
        if (String.IsNullOrEmpty(text) || text.Length > 128) return false;
        List<byte> bytes = new List<byte> { 0 };
        foreach (char c in text)
        {
            int carry = Alphabet.IndexOf(c); if (carry < 0) return false;
            for (int i = 0; i < bytes.Count; i++) { carry += bytes[i] * 58; bytes[i] = (byte)carry; carry >>= 8; }
            while (carry > 0) { bytes.Add((byte)carry); carry >>= 8; }
        }
        for (int i = 0; i < text.Length - 1 && text[i] == '1'; i++) bytes.Add(0);
        bytes.Reverse(); byte[] decoded = bytes.ToArray();
        int length = decoded.Length - 4;
        if (length != 78) return false;
        using (SHA256 sha = SHA256.Create())
        {
            byte[] checksum = sha.ComputeHash(sha.ComputeHash(decoded, 0, length));
            for (int i = 0; i < 4; i++) if (checksum[i] != decoded[length + i]) return false;
        }
        uint version = ((uint)decoded[0] << 24) | ((uint)decoded[1] << 16) | ((uint)decoded[2] << 8) | decoded[3];
        if (version != 0x0488b21e && version != 0x049d7cb2 && version != 0x04b24746 &&
            version != 0x043587cf && version != 0x044a5262 && version != 0x045f1cf6 &&
            version != 0x0295b43f && version != 0x02aa7ed3 && version != 0x024289ef && version != 0x02575483) return false;
        if (decoded[45] != 2 && decoded[45] != 3) return false;
        bool nonzero = false;
        for (int i = 46; i < 78; i++) if (decoded[i] != 0) nonzero = true;
        return nonzero;
    }

    public static bool Valid(string text, bool extended)
    {
        if (text.Length > 128) return false;
        List<byte> bytes = new List<byte> { 0 };
        foreach (char c in text)
        {
            int carry = Alphabet.IndexOf(c);
            if (carry < 0) return false;
            for (int i = 0; i < bytes.Count; i++) { carry += bytes[i] * 58; bytes[i] = (byte)carry; carry >>= 8; }
            while (carry > 0) { bytes.Add((byte)carry); carry >>= 8; }
        }
        for (int i = 0; i < text.Length - 1 && text[i] == '1'; i++) bytes.Add(0);
        bytes.Reverse(); byte[] decoded = bytes.ToArray();
        int length = decoded.Length - 4;
        if (length < 1) return false;
        using (SHA256 sha = SHA256.Create())
        {
            byte[] checksum = sha.ComputeHash(sha.ComputeHash(decoded, 0, length));
            for (int i = 0; i < 4; i++) if (checksum[i] != decoded[length + i]) return false;
        }
        int keyOffset;
        if (extended)
        {
            if (length != 78 || decoded[45] != 0) return false;
            uint version = ((uint)decoded[0] << 24) | ((uint)decoded[1] << 16) | ((uint)decoded[2] << 8) | decoded[3];
            if (version != 0x0488ade4 && version != 0x049d7878 && version != 0x04b2430c && version != 0x04358394 && version != 0x044a4e28 && version != 0x045f18bc) return false;
            keyOffset = 46;
        }
        else
        {
            if ((length != 33 && length != 34) || (decoded[0] != 128 && decoded[0] != 239) || (length == 34 && decoded[33] != 1)) return false;
            keyOffset = 1;
        }
        bool nonzero = false;
        for (int i = 0; i < 32; i++) if (decoded[keyOffset + i] != 0) nonzero = true;
        if (!nonzero) return false;
        for (int i = 0; i < 32; i++) { if (decoded[keyOffset + i] < Order[i]) return true; if (decoded[keyOffset + i] > Order[i]) return false; }
        return false;
    }
}
