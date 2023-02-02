using Fang;

var data = File.ReadAllBytes(args[0]);
Crypto.CryptFilelist(data.AsSpan());
File.WriteAllBytes(args[0] + ".dec", data);

Crypto.CryptFilelist(data.AsSpan());
File.WriteAllBytes(args[0] + ".enc", data);
