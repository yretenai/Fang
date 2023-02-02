using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Fang.Structures;

[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 0x20)]
public record struct FilelistEncryptedHeader {
    public ulong A;
    public ulong B;
    public int SizeBE;
    public uint Magic;

    public const uint EncryptedMagic = 0x1DE03478;
    public const uint DecryptedMagic = 0xE21FCB87;

    public int Size {
        get => BinaryPrimitives.ReverseEndianness(SizeBE) + 0x10;
        set => SizeBE = BinaryPrimitives.ReverseEndianness(value) - 0x10;
    }

    public bool IsEncrypted => Magic == EncryptedMagic;
    public ulong Seed => Crypto.CalculateFilelistSeed(ref this);
}
