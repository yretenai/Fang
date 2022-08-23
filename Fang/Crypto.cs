using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Fang;

public class Crypto {
    public static ulong CalculateFilelistSeed(ulong a, ulong b) => CalculateFilelistSeed(MemoryMarshal.AsBytes(new[] { a, b }.AsSpan()));
    public static ulong CalculateFilelistSeed(Span<byte> header) => (ulong) ((header[9] << 24) | (header[12] << 16) | (header[2] << 8) | header[0]);

    // 00749DC0
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
    public static void Decrypt(ref Span<byte> key, ref Span<byte> buffer) {
        var key64 = MemoryMarshal.Cast<byte, ulong>(key);
        for (var block = 0u; block < buffer.Length >> 3; ++block) {
            key64[32] = block << 0x17; // arbitrary but whatever.
            Round(ref key, ref buffer, block);
            Final(ref key, ref buffer, block);
        }
    }

    // 009FD050
    private static void Final(ref Span<byte> key, ref Span<byte> buffer, uint block) {
        var key32 = MemoryMarshal.Cast<byte, uint>(key);
        var buffer32 = MemoryMarshal.Cast<byte, uint>(buffer);
        var index = (int) (block << 3);

        // generate initial key states
        var a = key32[64] | ((uint) index << 0x0A) | (uint) index;
        var sbb = (byte) (a > ~0xA1652347 ? 1 : 0); // carry flag for subtract-borrow instruction
        var b = ((block << 1) | key32[65]) + sbb; 
        a += 0xA1652347;

        // grab key states for the block
        var c = key32[(int) (block << 1) % 64];
        var d = key32[(int) ((block << 1) + 1) % 64];

        // mutate block states with initial key state
        var iva = c ^ a ^ (buffer32[index >> 2] - c);
        var ivb = d ^ b ^ (buffer32[(index >> 2) + 1] - d);

        // swap blocks
        buffer32[index >> 2] = ivb;
        buffer32[(index >> 2) + 1] = iva;
    }

    // 009FD110
    private static void Round(ref Span<byte> key, ref Span<byte> buffer, uint block) {
        var index = (int) (block << 3);

        var offset = 0;
        // block specific xor byte
        var xor = (byte) (0x45 ^ block);
        do {
            // xor current byte
            var tmp = (byte) (xor ^ buffer[index + offset]);
            xor = buffer[index + offset];
            buffer[index + offset] = tmp;
            
            for(var i = 0; i < 8; ++i) {
                // perform 8 rounds of xor
                buffer[index + offset] = (byte) (0x78 + buffer[index + offset] - key[(index + i) % 256]);
            }

            offset++;
        } while (offset < 8);
    }
}
