using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Fang;

public static class Crypto {
    public static ulong CalculateFilelistSeed(ulong a, ulong b) => CalculateFilelistSeed(MemoryMarshal.AsBytes(new[] { a, b }.AsSpan()));
    public static ulong CalculateFilelistSeed(Span<byte> header) => (ulong) ((header[9] << 24) | (header[12] << 16) | (header[2] << 8) | header[0]);

    // 009FCC10
    public static Span<byte> ExpandKey(ulong seed) {
        var key = new byte[264].AsSpan();
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

        // clear last 8 bits for xor storage
        key32[64] = 0;
        key32[65] = 0;
        return key;
    }

    // 009FCFD0
    public static void Decrypt(Span<byte> key, Span<byte> buffer) {
        var key64 = MemoryMarshal.Cast<byte, ulong>(key);
        for (var blockNo = 0u; blockNo < buffer.Length >> 3; ++blockNo) {
            key64[32] = blockNo << 23; // arbitrary but whatever.
            var block = buffer.Slice((int) (blockNo << 3), 8);
            DecryptRound(key, block, blockNo);
            DecryptFinal(key, block, blockNo);
        }
    }

    // 009FCCE0
    public static void Encrypt(Span<byte> key, Span<byte> buffer) {
        var key64 = MemoryMarshal.Cast<byte, ulong>(key);
        for (var blockNo = 0u; blockNo < buffer.Length >> 3; ++blockNo) {
            key64[32] = blockNo << 23;
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

        // generate block key
        var bkey = (key64[32] | ((uint) index << 10) | (uint) index | ((ulong) block << 32)) + 0xA1652347;

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

        // swap blocks
        (buffer32[0], buffer32[1]) = (buffer32[1], buffer32[0]);

        // generate block key
        var bkey = (key64[32] | ((uint) index << 10) | (uint) index | ((ulong) block << 32)) + 0xA1652347;

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
