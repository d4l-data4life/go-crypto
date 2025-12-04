package d4lcrypto_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d4l-data4life/go-crypto/d4lcrypto"
)

const (
	encPrivateKey1 = `
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
-----END PRIVATE KEY-----`

	encPrivateKey2 = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLj2jn162CIGTe
OimvL1ULQa5VjEs8GXU1srven25eHM0T2yDHt+XEcs3v6uzAoYvR64JknmR1xKqC
j0LBD/RO0VWQ37gMt7JnI0h+eG7JcaxQLjFqv8t8QD8kKKEgmghUtV0LITFB7OD0
+p1ZJ8j2Gy3Ctd5WyOXlP8Bg1lPrpLW9rk5x4iKr+gnk2hhRixvEG/OEaKmN98MO
Bi3NK2brsLcRS3Jo0VSb1Ckk1yvah+vg95aKsaBlzCF0oN5YSm7FZe4iTUURJbvp
B0IjQT2wbeFGcyu+7KF9xWSaexgkkxW9pdMoUqV6ngtxbg+8CzgnffJFuxp0OTXc
Ib6cVMK/AgMBAAECggEAcwj8U+jCmQMNfbiIzgOFn/LiPl4mNjR81HfJS6n1iSHl
kw8Gm1cFddsbHjY4zTN9/IeHDK2mQBd/9IBZTRljCxepr1F+hVFadIav9SjCEv02
T6mLK7RvniwAgsKjK/VgN962Ug/T8lmXV1o5iaS+ILaDScHVgF3P7Zn1ccQtcMCF
y0+FWrE5NKFEkavEMqYk+zMT0a7NMShlgwWf5vY9Iz+yWQT5SBnsasJnvHyZMSYA
IaWgWWknoIdKBycwm6bbKJWCaNS5YHgIcoFVMdWr5KSmPRWLSVSLYDS16slO6wp4
eReF+KY9YlJn08u3dHejJYIm7JlOkgie4VGSbMXoIQKBgQDwNwjB+UP7XdIKiCg0
JB+TwO6gdzb/X8K7NDZ4OkNC5LZ/uEmbgtosBR90GzI3pX/0MrGfNsAJf2+1bjGW
JXxbAOsqCk8KKmJbA83e1Rg3XujBQKZI8BEibM7rt7HF6QihTdFWi6D82PlhwdMa
DqwxtA8eZnQSI/lSVLEa7uNOCwKBgQDY78Ia9She1sBxzsV7O88Rxub+IwvLMYOX
DD+qpgZjRwGWXx9MEP4RMW/C8+HoaqziMzlfRCxrOxWYhdTyvn2EVFvxzwGdmWt6
CcqLyfOfegWPtjN12hyTobsttlw1Fp7AnLtOIiAhEMrxCEAcaXHGE572DgCW0d9j
ZCgzi6dynQKBgAGusP4Cy+oXxx/Rwk5TLnFveXxgOV9igU+kVvlSlyQBzBFq7gEL
0pFaW9UJV7myDApezIWr8X5fiR3BLtG5Y3yTrhH2ToVotJWkmi2EWo4QuRqZZFDA
da5DCtP1zmXvcuMGU4ACrFb5Ag4gOGVHUwdqFm0FFK0H2XgtJaxlnevvAoGAMk3e
h9vDgcJwm7Nj7cCfsrKZy+KakIKpzfPkK5EWOB02DAWAv2XNVHVPQjjFcNyTvFw+
eI3ZcwAfcN/P0n5DotThAUCMUlxKJOFyW1n4KUnlUj7gzfpG2CEPw3jfBtx48Zcm
g+a75o77UEsmerAk1taj7NCwaEjAcU6/V7yRlq0CgYEA6rdieEblgL9ujV1v1kVd
+n6gPoFI9/h+IroxWFwySlPCnvpj8MRCayAKJop2P/lSOjRjUbtHDfFhA/+wumDg
Ft3LIvc5XifxHyovESF/tiqTKTU5bWbAJOzLQWLm17E+MTTqK/4+fLxTKrYZiyLL
NKo1UTaQHv8duhtZnDVq/y4=
-----END PRIVATE KEY-----`
)

//nolint:gochecknoglobals
var encPrivateKeys, _ = d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey1, encPrivateKey2)

//nolint:gochecknoglobals
var encPublicKey = d4lcrypto.NewPublicKeyFromString(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv+mnwUps4YjBBDTEinpM
vIe0lf7HUH0p29Tyhs8nKlLlJTlpZrKHNu1oUi+qYHEKb8kcFN6ZIUJQDr5KN2Ov
OHUUFQ1gNdnoRzgL0buhHbqf3b7DeNpxxU2xaggCfs2BwFa2j4m18TUsxPDigXs0
Y4skrtswE5o5kRgND+wCxB/5LjHVEw/3GRm/XihFg0PSQAgAxYMM22m+7XWvPnqk
4/Oa8QVUkWYKE7WpGcmp2EnrMkvI73LroF/5Q6X7EYXtgG5zyNMCVRAQ3o1KG2jn
dwLk6MDFxoSVPYD2Dq02+mJhLshPRWfRee8GofqRBJd6OvuDl35agdmTE0llzWJ0
IQIDAQAB
-----END PUBLIC KEY-----`)

func TestEncrypterVersion(t *testing.T) {
	t.Run("verify default version", func(t *testing.T) {
		encrypter := d4lcrypto.NewEncrypter(encPublicKey)
		assert.Equal(t, byte(d4lcrypto.HybridEncryptionAESWithGCM), encrypter.Version())
	})
}

func BenchmarkCreateTestFixtures(b *testing.B) {
	msg := []byte(`{"a":"Hello World!"}`)
	b.Run("test fixture version 1", func(b *testing.B) {
		encrypter := d4lcrypto.NewEncrypterWithVersion(encPublicKey, d4lcrypto.HybridEncryptionAESWithCBC)
		ciphertext, err := encrypter.Encrypt(msg)
		if err != nil {
			b.Errorf("error when encrypting message: %v", err)
		}
		b.Logf("Test fixture version 1: %s", hex.EncodeToString(ciphertext))
	})
	b.Run("test fixture version 2", func(b *testing.B) {
		encrypter := d4lcrypto.NewEncrypterWithVersion(encPublicKey, d4lcrypto.HybridEncryptionAESWithGCM)
		ciphertext, err := encrypter.Encrypt(msg)
		if err != nil {
			b.Errorf("error when encrypting message: %v", err)
		}
		b.Logf("Test fixture version 2: %s", hex.EncodeToString(ciphertext))
	})
}

func TestFixtures(t *testing.T) {
	pks1, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey1)
	pks21, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey2, encPrivateKey1)
	tests := []struct {
		name      string
		hexmsg    string
		plaintext string
		keys      *d4lcrypto.PrivateKeys
		err       error
	}{
		{
			"V1 - test fixture from README.md",
			`0100017be8d6dcd3ccf781b9d7d8452b2ce93266f5ae25a48f807daecc7e4275
			0479f57af999614fe7e4b5d093552aa5b2a11489e4b37786533350c251cd287e
			5761f936dbcf53f5b2f308ddeae666c476c797139705701c7a21f66b0893b804
			576eac89d69ab7847c01c77044f414959926b92786d5a0d980abd8a0c3b333ae
			a3ca017875d317a49ba2260324f3c8fea5306e27bd3a068a4184508332d6be5e
			1397a4fb3a020a3522b1cf722db18293eec67f553bcfea502c7df8ef84caaf71
			003d3f3ba3eb700176c05febf77ade48cfe2e5cfa7864d528d1364f5325f582b
			05c446b2323d191c734961de8125da61dcaf4f70e9e5e39cc53f4228847059cb
			b156501400000000000000b493af01514c3a1646e32f16ce20f84abc37f8d739
			c88d1caaa8594b6583010537bba048881b2ca355904559201ec738`,
			`{"a":"Hello World!"}`,
			pks1,
			nil,
		},
		{
			"V2 - test fixture from README.md",
			`02000178941374f21d384b111bd301c74b3d831d83d942b81b15edb4e7f6b1a9
			b652f5380e55a0ad6597ee6a11d410f18555c2d79de2ff77068907ed57269064
			a47305f86dae206065da5d155ec6a0bccc66b928d71694ffbb4b082103b47bd8
			a65787e2c2f82b2afe5f1a871c3b504be17f55b19db2dbeb7275141ceb63389e
			6da0b82cf29cfca5a6a2c1385ffee9af98483b6deae18d0aaf07e0a030d34820
			8e9b58a62b177b9266bb10ef03bf0d292e256d92d697fe48de8cc6641b3465ac
			aad11ad87a4d5ddc83e482734dd81e80ae6009cde60e083e0f96eeac8af74b1b
			23c60f9d985d85eec37553c17371b258cc658da376fdac35d91203ed267d9d1f
			da76f0b1504dba800b3deea0d21a92481b662d2400000000000000796435ab01
			175a78f5efa9dfade1537c0552ec7be7e2453b8b9eaca461443784f624c4e6`,
			`{"a":"Hello World!"}`,
			pks1,
			nil,
		},
		{
			"V2 - test fixture from js-crypto",
			`020001af5d54ac56cc39711e29af335db931eed58c8b1bbf8bbf537cce660a2
			18e0d1ff810a458a08391e6c23b92ba05956127e4f9e891c6faf1c88b4b630a5
			82a4cf822f8a671346672b63581768168e5566f4ca9bb93f83de275f3331a9bb
			cea86b889d63d5673c7c048fa2147641fde4d0d732006218ff76b7b6bbcd82f1
			efc42ab76f8083a3f2c76075e057174f4018fdf8225df093b1077f09be30f8ee
			9e10643524c5459aedb150d70e28345d070a10efeb39316f2daa06d0dfae83f4
			b64dc63a319f21105e159189220587667a1bd03c9a036132b41931ca31218e90
			a8f26f3c11a862ac28c09fdf3652dce90131497a0b4d2684876fdb134c5989b0
			5ff664824af5e6c03640dc9e3e320e7fdf022a82400000000000000c4e72767d
			b5e79ba4b12e7b7d8c1edf496687f29e3cada6096be58815fc149a603a6c01c`,
			`{"a":"Hello World!"}`,
			pks1,
			nil,
		},
		{
			"V2 - test fixture from js-crypto (after key rotation)",
			`020001af5d54ac56cc39711e29af335db931eed58c8b1bbf8bbf537cce660a2
			18e0d1ff810a458a08391e6c23b92ba05956127e4f9e891c6faf1c88b4b630a5
			82a4cf822f8a671346672b63581768168e5566f4ca9bb93f83de275f3331a9bb
			cea86b889d63d5673c7c048fa2147641fde4d0d732006218ff76b7b6bbcd82f1
			efc42ab76f8083a3f2c76075e057174f4018fdf8225df093b1077f09be30f8ee
			9e10643524c5459aedb150d70e28345d070a10efeb39316f2daa06d0dfae83f4
			b64dc63a319f21105e159189220587667a1bd03c9a036132b41931ca31218e90
			a8f26f3c11a862ac28c09fdf3652dce90131497a0b4d2684876fdb134c5989b0
			5ff664824af5e6c03640dc9e3e320e7fdf022a82400000000000000c4e72767d
			b5e79ba4b12e7b7d8c1edf496687f29e3cada6096be58815fc149a603a6c01c`,
			`{"a":"Hello World!"}`,
			pks21,
			nil,
		},
		{
			"V3 - test fixture from js-crypto",
			`03dcd9feae8f14d5db54075a287e68f6fa30fe210105d97a4a9dd61cc49093d
			2e20e3a2339592a94937f4e69354dc4cb083d51f0c684a622a5ca35e80d9b935
			30dce0001819c34744e473926db31d6511727b655a33e536359d959852fdb2be
			52a16b0460b074025ed69c2c36973301e217f202a1e1d69b345962003b60a3ec
			de9ae3d617dce39c89641284255caa0ea441b67acf28a504049f4a3c3937f90c
			f50e5392b337941a11f2a6df4da03a60349eaa92cc64148e399ce503daa5c4d3
			9a1413ec4d12859849725e95ce976a661b24a9462a86630de0c97f38f105d04f
			3a45310f25a82e4fba1d25448eed522517370e1a9331ab2b5916501423d3d8be
			003a0ac9c6f6db2e2f18e23a83c8ff49615f34eb5e8be405b55379b23f6002b7
			ed2d0a9d770d5417d766128c48d2b2288529fc910b02ca11902c826693d3835a
			12c20ed26c345b12282d37e79cc8cc8cc0b94bd602400000000000000763de4e
			151c695c03f80e88740066dd9a11519e05a78f82f8ebde6e74f839daeb092851
			c00`,
			`{"a":"Hello World!"}`,
			pks1,
			nil,
		},
	}
	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decrypter := d4lcrypto.NewDecrypter(tt.keys)
			hexmsg := strings.ReplaceAll(strings.ReplaceAll(tt.hexmsg, "\n", ""), "\t", "")
			msg, err := hex.DecodeString(hexmsg)
			require.NoError(t, err, "DecodeString() failed")
			plaintext, err := decrypter.Decrypt(msg)
			if tt.err == nil {
				require.NoErrorf(t, err, "error when decrypting message")
				assert.Equalf(t, []byte(tt.plaintext), plaintext, "wrong plaintext")
			} else {
				if !errors.Is(err, tt.err) {
					assert.Fail(t, "should fail on expected error")
				}
				assert.Equal(t, []byte(nil), plaintext)
			}
		})
	}
}

func TestEncrypterDecrypter(t *testing.T) {
	msg := []byte("Hello World!")
	pks1, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey1)
	pks2, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey2)
	pks21, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey2, encPrivateKey1)
	tests := []struct {
		name    string
		version byte
		keys    *d4lcrypto.PrivateKeys
		err     error
	}{
		{"V1 - correct private key", d4lcrypto.HybridEncryptionAESWithCBC, pks1, nil},
		{"V1 - wrong private key", d4lcrypto.HybridEncryptionAESWithCBC, pks2, d4lcrypto.ErrDecrypterDecryption},
		{"V1 - private key set", d4lcrypto.HybridEncryptionAESWithCBC, encPrivateKeys, nil},
		{"V1 - reordered private key set", d4lcrypto.HybridEncryptionAESWithCBC, pks21, nil},
		{"V2 - correct private key", d4lcrypto.HybridEncryptionAESWithGCM, pks1, nil},
		{"V2 - wrong private key", d4lcrypto.HybridEncryptionAESWithGCM, pks2, d4lcrypto.ErrDecrypterDecryption},
		{"V2 - private key set", d4lcrypto.HybridEncryptionAESWithGCM, encPrivateKeys, nil},
		{"V2 - reordered private key set", d4lcrypto.HybridEncryptionAESWithGCM, pks21, nil},
	}
	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypter := d4lcrypto.NewEncrypterWithVersion(encPublicKey, tt.version)
			ciphertext, err := encrypter.Encrypt(msg)
			if err != nil {
				t.Errorf("error when encrypting message: %v", err)
			}
			decrypter := d4lcrypto.NewDecrypter(tt.keys)
			plaintext, err := decrypter.Decrypt(ciphertext)
			if tt.err == nil {
				require.NoErrorf(t, err, "error when decrypting message")
				assert.Equalf(t, msg, plaintext, "wrong plaintext")
			} else {
				if !errors.Is(err, tt.err) {
					assert.Fail(t, "should fail on expected error")
				}
				assert.Equal(t, []byte(nil), plaintext)
			}
		})
	}
}

func TestEncrypterDecrypterWithRecovery(t *testing.T) {
	msg := []byte("Hello World!")
	pks1, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey1)
	pks2, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey2)
	pks21, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey2, encPrivateKey1)
	aesKey, _ := d4lcrypto.GenerateRandomBytes(32)
	wrongAesKey, _ := d4lcrypto.GenerateRandomBytes(32)
	tests := []struct {
		name        string
		keys        *d4lcrypto.PrivateKeys
		recoveryKey []byte
		err         error
	}{
		{"V3 - correct private key", pks1, nil, nil},
		{"V3 - wrong private key", pks2, nil, d4lcrypto.ErrDecrypterDecryption},
		{"V3 - private key set", encPrivateKeys, nil, nil},
		{"V3 - reordered private key set", pks21, nil, nil},
		{"V3 - decrypt with recovery key", pks1, aesKey, nil},
		{"V3 - decrypt with wrong recovery key", pks1, wrongAesKey, d4lcrypto.ErrDecrypterDecryption},
	}
	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypter := d4lcrypto.NewEncrypterWithRecoveryKey(encPublicKey, aesKey)
			ciphertext, err := encrypter.Encrypt(msg)
			if err != nil {
				t.Errorf("error when encrypting message: %v", err)
			}
			decrypter := d4lcrypto.NewDecrypterWithRecoveryKey(tt.keys, tt.recoveryKey)
			plaintext, err := decrypter.Decrypt(ciphertext)
			if tt.err == nil {
				require.NoErrorf(t, err, "error when decrypting message")
				assert.Equalf(t, msg, plaintext, "wrong plaintext")
			} else {
				require.Error(t, err, "should fail on expected error")
				if !errors.Is(err, tt.err) {
					assert.Failf(t, "wrong error type: %v", err.Error())
				}
				assert.Equal(t, []byte(nil), plaintext)
			}
		})
	}
}

func TestEncrypterDecrypterWithMarshalling(t *testing.T) {
	cm := d4lcrypto.ConsentMessage{"docKey", "studyID", "signatureType", []byte("payload")}
	encrypter := d4lcrypto.NewEncrypter(encPublicKey)
	ciphertext, err := encrypter.MarshalAndEncrypt(cm)
	if err != nil {
		t.Errorf("error when encrypting message: %v", err)
	}

	t.Parallel()

	t.Run("verify with matching private key", func(t *testing.T) {
		pks, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey1)
		decrypter := d4lcrypto.NewDecrypter(pks)
		plaintext := &d4lcrypto.ConsentMessage{}
		err := decrypter.DecryptAndUnmarshal(ciphertext, plaintext)
		require.NoErrorf(t, err, "error verifying signature")
		assert.Equal(t, &cm, plaintext)
	})

	t.Run("verify with different private key", func(t *testing.T) {
		pks, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey2)
		decrypter := d4lcrypto.NewDecrypter(pks)
		plaintext := &d4lcrypto.ConsentMessage{}
		err := decrypter.DecryptAndUnmarshal(ciphertext, plaintext)
		if !errors.Is(err, d4lcrypto.ErrDecrypterDecryption) {
			assert.Equal(t, d4lcrypto.ErrDecrypterDecryption, err, "should fail on expected error")
		}
		assert.Equal(t, &d4lcrypto.ConsentMessage{}, plaintext)
	})

	t.Run("verify with private key set", func(t *testing.T) {
		decrypter := d4lcrypto.NewDecrypter(encPrivateKeys)
		plaintext := &d4lcrypto.ConsentMessage{}
		err := decrypter.DecryptAndUnmarshal(ciphertext, plaintext)
		require.NoErrorf(t, err, "error verifying signature")
		assert.Equal(t, &cm, plaintext)
	})

	t.Run("verify with private key set - different order", func(t *testing.T) {
		var encPrivateKeys2, _ = d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey2, encPrivateKey1)
		decrypter := d4lcrypto.NewDecrypter(encPrivateKeys2)
		plaintext := &d4lcrypto.ConsentMessage{}
		err := decrypter.DecryptAndUnmarshal(ciphertext, plaintext)
		require.NoErrorf(t, err, "error verifying signature")
		assert.Equal(t, &cm, plaintext)
	})

	t.Run("marshal error", func(t *testing.T) {
		encrypter := d4lcrypto.NewEncrypter(encPublicKey)
		_, err := encrypter.MarshalAndEncrypt(make(chan int))
		if !errors.Is(err, d4lcrypto.ErrEncrypterJSONMarshal) {
			assert.Equal(t, d4lcrypto.ErrEncrypterJSONMarshal, err, "should fail on expected error")
		}
	})

	t.Run("unmarshal error - invalid JSON", func(t *testing.T) {
		msg := []byte("Hello World!")
		encrypter := d4lcrypto.NewEncrypter(encPublicKey)
		ciphertext, _ := encrypter.Encrypt(msg)
		pks, _ := d4lcrypto.NewPrivateKeysFromStrings(encPrivateKey1)
		decrypter := d4lcrypto.NewDecrypter(pks)
		cm := &d4lcrypto.ConsentMessage{}
		err = decrypter.DecryptAndUnmarshal(ciphertext, cm)
		t.Log(cm)
		if !errors.Is(err, d4lcrypto.ErrDecrypterJSONUnmarshal) {
			assert.Equal(t, d4lcrypto.ErrDecrypterJSONUnmarshal, err, "should fail on expected error")
		}
	})
}
