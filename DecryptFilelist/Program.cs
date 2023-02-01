using System.Diagnostics;
using System.Runtime.InteropServices;
using Fang;
using Fang.Structures;

using var fs = File.Open(args[0], FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
Span<FilelistEncryptedHeader> header = stackalloc FilelistEncryptedHeader[1];
fs.ReadExactly(MemoryMarshal.AsBytes(header));
if (!header[0].IsEncrypted) {
    return;
}

var key = Crypto.ExpandKey(header[0].Seed);
var buffer = new byte[header[0].Size].AsSpan();
fs.ReadExactly(buffer);
Crypto.Decrypt(key, buffer);
File.WriteAllBytes(args[0] + ".dec", buffer.ToArray());

key = Crypto.ExpandKey(header[0].Seed);
Crypto.Encrypt(key, buffer);
File.WriteAllBytes(args[0] + ".enc", buffer.ToArray());
