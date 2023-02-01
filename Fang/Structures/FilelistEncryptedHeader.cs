using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Fang.Structures;

[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 0x20)]
public readonly record struct FilelistEncryptedHeader(ulong A, ulong B, int SizeBE, int Tag) {
    public int Size => BinaryPrimitives.ReverseEndianness(SizeBE) + 0x10;
    public bool IsEncrypted => Tag == 0x1DE03478;
    public ulong Seed => Crypto.CalculateFilelistSeed(A, B);
}
