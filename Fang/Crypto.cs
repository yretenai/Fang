using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Fang.Structures;

namespace Fang;

public static class Crypto {
    public static ulong CalculateFilelistSeed(ulong a, ulong b) {
        Span<ulong> stack = stackalloc ulong[2] { a, b };
        return CalculateFilelistSeed(MemoryMarshal.AsBytes(stack));
    }

    public static ulong CalculateFilelistSeed(Span<byte> header) => (ulong) ((header[9] << 24) | (header[12] << 16) | (header[2] << 8) | header[0]);

    public static void CryptFilelist(Span<byte> data) {
        Span<byte> key = stackalloc byte[256];
        var header = MemoryMarshal.Read<FilelistEncryptedHeader>(data);
        var body = data.Slice(0x10, header.Size);
        if (header.IsEncrypted) {
            header.Magic = FilelistEncryptedHeader.DecryptedMagic;
            ExpandKey(key, header.Seed);
            Decrypt(key, body);
        } else {
            MD5.HashData(body).CopyTo(data);
            header.Magic = FilelistEncryptedHeader.EncryptedMagic;
            ExpandKey(key, header.Seed);
            Encrypt(key, body);
        }
    }

    public static void CryptScript(Span<byte> data, bool decrypt) {
        var seed = MemoryMarshal.Read<ulong>(data);
        Crypt(data[8..], seed, decrypt);
    }

    public static void Crypt(Span<byte> data, ulong seed, bool decrypt) {
        Span<byte> key = stackalloc byte[256];
        ExpandKey(key, seed);
        if (decrypt) {
            Decrypt(key, data);
        } else {
            Encrypt(key, data);
        }
    }

    // 009FCC10
    public static void ExpandKey(Span<byte> key, ulong seed) {
        var key32 = MemoryMarshal.Cast<byte, uint>(key);
        var key64 = MemoryMarshal.Cast<byte, ulong>(key);

        // init seed vector
        var loSeed = (uint) (seed & 0xFFFFFFFF);
        var hiSeed = (uint) (seed >> 32);
        key32[0] = BitOperations.RotateRight(BinaryPrimitives.ReverseEndianness(loSeed), 16);
        key32[1] = BitOperations.RotateLeft(BinaryPrimitives.ReverseEndianness(hiSeed), 8);

        // crypt key
        key[0] += 0x45;
        for (var i = 1; i < 8; ++i) {
            var tmp = key[i - 1] - 0x2C + key[i];
            key[i] = (byte) (tmp ^ (key[i - 1] << 2) ^ 0x45);
        }

        // expand key to all 256 bits
        var kidx = 2;
        for (var i = 0; i < 32; ++i) {
            var a = 5 * key64[(kidx >> 1) - 1];
            a ^= (ulong) key32[kidx - 1] << 32;
            key32[kidx] = (uint) (key32[kidx - 2] ^ a);
            key32[kidx + 1] = (uint) (a >> 32);
            a = key32[kidx - 2] | (a & 0xFFFFFFFF00000000);

            var b = key32[kidx];
            kidx += 2;
            key32[kidx - 2] = (uint) (a ^ b);
            key32[kidx - 1] ^= key32[kidx - 3];
        }
    }

    // 009FCFD0
    public static void Decrypt(Span<byte> key, Span<byte> buffer) {
        for (var blockNo = 0u; blockNo < buffer.Length >> 3; ++blockNo) {
            var block = buffer.Slice((int) (blockNo << 3), 8);
            DecryptRound(key, block, blockNo);
            DecryptFinal(key, block, blockNo);
        }
    }

    // 009FCCE0
    public static void Encrypt(Span<byte> key, Span<byte> buffer) {
        for (var blockNo = 0u; blockNo < buffer.Length >> 3; ++blockNo) {
            var block = buffer.Slice((int) (blockNo << 3), 8);
            EncryptFinal(key, block, blockNo);
            EncryptRound(key, block, blockNo);
        }
    }

    // 009FD050
    private static void DecryptFinal(Span<byte> key, Span<byte> buffer, uint block) {
        var key64 = MemoryMarshal.Cast<byte, ulong>(key);
        var buffer32 = MemoryMarshal.Cast<byte, uint>(buffer);
        var buffer64 = MemoryMarshal.Cast<byte, ulong>(buffer);
        var index = (int) (block << 3);
        var state = (ulong)block << 23;

        // generate block key
        var bkey = (state | ((uint) index << 10) | (uint) index | ((ulong) block << 33)) + 0xA1652347;

        // get expanded key
        var ekey = key64[(int) (block % 32)];

        // xor magic
        buffer64[0] = ekey ^ bkey ^ (buffer64[0] - ekey);

        // swap blocks
        (buffer32[0], buffer32[1]) = (buffer32[1], buffer32[0]);
    }

    // 009FCD60
    private static void EncryptFinal(Span<byte> key, Span<byte> buffer, uint block) {
        var key64 = MemoryMarshal.Cast<byte, ulong>(key);
        var buffer32 = MemoryMarshal.Cast<byte, uint>(buffer);
        var buffer64 = MemoryMarshal.Cast<byte, ulong>(buffer);
        var index = (int) (block << 3);
        var state = (ulong)block << 23;

        // swap blocks
        (buffer32[0], buffer32[1]) = (buffer32[1], buffer32[0]);

        // generate block key
        var bkey = (state | ((uint) index << 10) | (uint) index | ((ulong) block << 33)) + 0xA1652347;

        // get expanded key
        var ekey = key64[(int) (block % 32)];

        buffer64[0] = (ekey ^ bkey ^ buffer64[0]) + ekey;
    }

    // 009FD110
    private static void DecryptRound(Span<byte> key, Span<byte> buffer, uint block) {
        var offset = 0;
        // block specific xor byte
        var xor = (byte) (0x45 ^ block);
        do {
            // xor current byte
            var tmp = (byte) (xor ^ buffer[offset]);
            xor = buffer[offset];
            buffer[offset] = tmp;

            for (var i = 0; i < 8; ++i) {
                // perform 8 rounds of shuffling
                buffer[offset] = (byte) (0x78 + (buffer[offset] - key[(int) (((block << 3) + i) % 256)]));
            }

            offset++;
        } while (offset < 8);
    }

    // 009FCE30
    private static void EncryptRound(Span<byte> key, Span<byte> buffer, uint block) {
        var offset = 0;
        // block specific xor byte
        var xor = (byte) (0x45 ^ block);
        do {
            for (var i = 0; i < 8; ++i) {
                // perform 8 rounds of shuffling
                buffer[offset] = (byte) (0x88 + (byte) (buffer[offset] + key[(int) (((block << 3) + i) % 256)]));
            }

            // xor current byte
            xor ^= buffer[offset];
            buffer[offset] = xor;

            offset++;
        } while (offset < 8);
    }
}
