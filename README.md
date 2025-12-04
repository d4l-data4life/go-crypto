# Go-Crypto Library

This is the Go-Library that wraps reusable cryptographic functions used within D4L.
It is used by the [Consent Service](https://github.com/gesundheitscloud/consent-management) and 
[Data Donation Service](https://github.com/gesundheitscloud/cov-donation)
to implement the crypto protocols for consent signing, secure data donation and revocation.

## Hybrid Encryption

Hybrid encryption is the combination of a symmetric and an asymmetric encryption and used where asymmetric encryption would be required,
but is too slow or limited in the length of possible plaintexts. We use it to encrypt JSON strings addressed to the Data Donation Service
or donated resources addressed to the ALP.

The hybrid-encypted message we use is a byte array where fields are serialized as byte arrays and concatenated in that order.
All numbers (key and plaintext lengths) use little endian byte order. The number of bytes each field consumes is shown below next to the field description.

### Version 1 (AES with CBC, deprecated)

The ciphertext is the plaintext t randomly padded up to a multiple of 16 bytes, encrypted with AES in CBC block mode using a random symmetric
key of 256 bits and a random initialisation vector. That key is encrypted with the public key of the receiver and sent in the *encKey* part of the message.

| field | description | length in bytes | example |
|---------|-------------------------------------|-------------------------|-----------------------|
| version | version to support new formats | 1 | `0x01` |
| encKeyLen | length of encrypted symmetric key | 2 | `0x00 0x01` |
| encKey | encrypted symmetric key | encKeyLen | `0x7b 0xe8 0xd6 ... 0xb1 0x56 0x50` (256 bytes) |
| plaintextLen | length of plaintext | 8 | `0x14 0x00 0x00 0x00 0x00 0x00 0x00 0x00` |
| iv | initialisation vector | 16 | `0xb4 0x93 0xaf 0x01 0x51 0x4c 0x3a 0x16 0x46 0xe3 0x2f 0x16 0xce 0x20 0xf8 0x4a` |
| ciphertext | padded and AES CBC encrypted plaintext | plaintextLen + (16 - plaintextLen) mod 16 | `0xbc 0x37 0xf8 ... 0x1e 0xc7 0x38` (32 bytes) |

### Version 2 (AES with GCM, default for encryption)

The ciphertext is the plaintext t encrypted with AES in GCM block mode using a random symmetric
key of 256 bits and a random 128 bit initialisation vector. That key is encrypted with the public key of the receiver and sent in the *encKey* part of the message.

| field | description | length in bytes | example |
|---------|-------------------------------------|-------------------------|-----------------------|
| version | version to support new formats | 1 | `0x02` |
| encKeyLen | length of encrypted symmetric key | 2 | `0x00 0x01` |
| encKey | encrypted symmetric key | encKeyLen | `0x78 0x94 0x13 ... 0xda 0x76 0xf0` (256 bytes) |
| iv | initialisation vector | 16 | `0xb1 0x50 0x4d 0xba 0x80 0x0b 0x3d 0xee 0xa0 0xd2 0x1a 0x92 0x48 0x1b 0x66 0x2d` |
| ciphertextLen | length of ciphertext | 8 | `0x24 0x00 0x00 0x00 0x00 0x00 0x00 0x00` |
| ciphertext | AES GCM encrypted plaintext | ciphertextLen | `0x79 0x64 0x35 ... 0x24 0xc4 0xe6` (36 bytes) |

### Version 3 (AES with GCM with support for recovery, default for encryption in the client)

The ciphertext is the data t encrypted with AES in GCM block mode using a random symmetric key of 256 bits (data key) and a random 128 bit initialisation vector.
The data key is once encrypted with the public key of the donation receiver (e.g. ALP-EU) and sent in the *encKey_alp* part of the message.
For recovery, the data key is also symmetrically encrypted (AES GCM) using the recovery key of the donor using a random 128 bit initialisation vector and sent in
the *encKey_don* part of the message.

| field         | description                                   | size in bytes | example                                        |
|---------------|-----------------------------------------------|---------------|------------------------------------------------|
| version       | version to support new formats                | 1             | `0x03`                                         |
| iv_don        | initialisation vector                         | 16            | `0x00 0x11 0x22 ...` (16 bytes)                |
| encKeyLen_don | length of donor-encrypted data key            | 1             | `0x20` (32)                                    |
| encKey_don    | donor-encrypted data key                      | encKeyLen_don | `0xaa 0xbb ...` (32 bytes)                     |
| encKeyLen_alp | length of ALP-encrypted data key              | 2             | `0x00 0x01` (256)                              |
| encKey_alp    | ALP-encrypted data key                        | encKeyLen_alp | `0x78 0x94 0x13 ...` (256 bytes)               |
| iv            | initialisation vector                         | 16            | `0xb1 0x50 0x4d ...` (16 bytes)                |
| ciphertextLen | length of ciphertext                          | 8             | `0x24 0x00 0x00 0x00 0x00 0x00 0x00 0x00` (36) |
| ciphertext    | AES GCM encrypted data                        | ciphertextLen | `0x79 0x64 0x35 ...` (36 bytes)                |



## Test Fixtures

Given the plaintext:

```json
{"a":"Hello World!"}
```

and the following private key for decryption:

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/6afBSmzhiMEE
NMSKeky8h7SV/sdQfSnb1PKGzycqUuUlOWlmsoc27WhSL6pgcQpvyRwU3pkhQlAO
vko3Y684dRQVDWA12ehHOAvRu6Edup/dvsN42nHFTbFqCAJ+zYHAVraPibXxNSzE
8OKBezRjiySu2zATmjmRGA0P7ALEH/kuMdUTD/cZGb9eKEWDQ9JACADFgwzbab7t
da8+eqTj85rxBVSRZgoTtakZyanYSesyS8jvcuugX/lDpfsRhe2AbnPI0wJVEBDe
jUobaOd3AuTowMXGhJU9gPYOrTb6YmEuyE9FZ9F57wah+pEEl3o6+4OXflqB2ZMT
SWXNYnQhAgMBAAECggEAVjufbXMLyauxTzqGtdKOeIhh1KRO2xPioyzkbT7X0mS9
IiTR/5totn2myocwf3VLwz8Spy3+kLtDTdyjbJAWQ8AX7f28pXXssVO1u+AbXUhm
XTVCkCNXy9hFR+ehd2jQTKSqE4VFg8TpAPVcUeISgEgdi5Rh3e0GwPOVqvnZpFYS
TXpsl8GOhStNdrMv+0pOBfYBcqTWxnzaPOmnbg7kRIRk3lA6C//gtBMczPynVV3J
Omh7DjRPfsEHhjhNipKC38HE+PH+KH5MuNMqMlLC5G5i3/2kyqD3ou5SYERK10tH
bFfNKb6s9SCEAkRkRdwpKdzvhqGrBDOtRx+fqP55gQKBgQDk3YbZ4SOEiQehB4Ti
jSug1lBAKyWD+GHJKtinIf3L4orcKduMTLB8g1JtNcTUGd74mS1brMMZRsckybks
CTPPPUcKovRpJ1TyoLonzjXsT7aCWqkKrODV47Y2UiHW30LNUOYD2HsB2cEE7DWr
zs1yA6ACdzRSNtXyan1GZ9LelQKBgQDWqozZhAEeJQXszdW/42+rvhyrUPB5R5BD
tM801QI3oN+EruqzXiV7TvsdkVDPvspgnmO3jCIbNTg+v+PfxKbZC0SUPjhAWKv7
MqD2/vxpUmfubUMn3kQ9nOwD+UUbSyBsXiJVbT1Jk67viMTodY80U2awdMcP9i3U
TtTTlfs4XQKBgQDWY+5/C7gJ35OV9UU2NKg58okak1CBX5u6prhtWBo3c/BAbbWM
qAprmVkNlODdD58fod4rkprwgqzqeU1NQxGVgQGbpSrvljitUIMR5sn8pG+DjQnt
RiUYOEfoeufYMSySyMWvtIsGIMX/poZge0lZFKw/owsQOO4SOE9CNOAEQQKBgGci
s99Bs8PG5+zZDAxQenOaOG36yj6Kqn5NHYx1lsYhTaKS44JgBkQTM0UGbzwQn20C
TEiAVFacIDTNvu7grYT0C/PpXN9VevOKZJmm8qCrjfGYnz5FZKXxgdd66L/vPVmz
dG10uZBjGxZMsMY6zR3HwDuhL460qVoqscgic/ulAoGBANwfwagDk7yUG3rOulRk
cy9494j/TV5hlKiPNWuIhNvCNjKqo5sUysxVRp5zc162B7+SplOmctbJ2CZtO5ug
djMbbsWWf7k8verVb+MgPqO1Grhm87uPwRvZGC2GEG6BknnqMdxOggsBW0hVz9og
+dFwONWN+SFj+uKbzizx1yuf
-----END PRIVATE KEY-----
```

### Version 1

A hex encoded hybrid-encrypted message version 1 looks as follows:

```hex
0100017be8d6dcd3ccf781b9d7d8452b2ce93266f5ae25a48f807daecc7e4275
0479f57af999614fe7e4b5d093552aa5b2a11489e4b37786533350c251cd287e
5761f936dbcf53f5b2f308ddeae666c476c797139705701c7a21f66b0893b804
576eac89d69ab7847c01c77044f414959926b92786d5a0d980abd8a0c3b333ae
a3ca017875d317a49ba2260324f3c8fea5306e27bd3a068a4184508332d6be5e
1397a4fb3a020a3522b1cf722db18293eec67f553bcfea502c7df8ef84caaf71
003d3f3ba3eb700176c05febf77ade48cfe2e5cfa7864d528d1364f5325f582b
05c446b2323d191c734961de8125da61dcaf4f70e9e5e39cc53f4228847059cb
b156501400000000000000b493af01514c3a1646e32f16ce20f84abc37f8d739
c88d1caaa8594b6583010537bba048881b2ca355904559201ec738
```

### Version 2

A hex encoded hybrid-encrypted message version 2 looks as follows:

```hex
02000178941374f21d384b111bd301c74b3d831d83d942b81b15edb4e7f6b1a9
b652f5380e55a0ad6597ee6a11d410f18555c2d79de2ff77068907ed57269064
a47305f86dae206065da5d155ec6a0bccc66b928d71694ffbb4b082103b47bd8
a65787e2c2f82b2afe5f1a871c3b504be17f55b19db2dbeb7275141ceb63389e
6da0b82cf29cfca5a6a2c1385ffee9af98483b6deae18d0aaf07e0a030d34820
8e9b58a62b177b9266bb10ef03bf0d292e256d92d697fe48de8cc6641b3465ac
aad11ad87a4d5ddc83e482734dd81e80ae6009cde60e083e0f96eeac8af74b1b
23c60f9d985d85eec37553c17371b258cc658da376fdac35d91203ed267d9d1f
da76f0b1504dba800b3deea0d21a92481b662d2400000000000000796435ab01
175a78f5efa9dfade1537c0552ec7be7e2453b8b9eaca461443784f624c4e6
```

### Version 3

A hex encoded hybrid-encrypted message version 3 looks as follows:

```hex
03dcd9feae8f14d5db54075a287e68f6fa30fe210105d97a4a9dd61cc49093d2
e20e3a2339592a94937f4e69354dc4cb083d51f0c684a622a5ca35e80d9b9353
0dce0001819c34744e473926db31d6511727b655a33e536359d959852fdb2be5
2a16b0460b074025ed69c2c36973301e217f202a1e1d69b345962003b60a3ecd
e9ae3d617dce39c89641284255caa0ea441b67acf28a504049f4a3c3937f90cf
50e5392b337941a11f2a6df4da03a60349eaa92cc64148e399ce503daa5c4d39
a1413ec4d12859849725e95ce976a661b24a9462a86630de0c97f38f105d04f3
a45310f25a82e4fba1d25448eed522517370e1a9331ab2b5916501423d3d8be0
03a0ac9c6f6db2e2f18e23a83c8ff49615f34eb5e8be405b55379b23f6002b7e
d2d0a9d770d5417d766128c48d2b2288529fc910b02ca11902c826693d3835a1
2c20ed26c345b12282d37e79cc8cc8cc0b94bd602400000000000000763de4e1
51c695c03f80e88740066dd9a11519e05a78f82f8ebde6e74f839daeb092851c
00
```

## License

(c) 2020 D4L data4life gGmbH / All rights reserved. Please refer to our [License](./LICENSE) for further details.

## Code of conduct

[Contributor Code of Conduct](./CODE-OF-CONDUCT.md). By participating in this project, you agree to abide by its terms.
