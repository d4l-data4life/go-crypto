package d4lcrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// Cross-language vector: a donation produced by collect-lib's encryptV4 (see
// hybridEncryption.spec.ts). go-crypto must decode BOTH slots — the RSA target slot with the
// data receiver's RSA key, and the AES recovery slot with the recovery key — proving the v4
// wire format matches across languages. Regenerate via collect-lib's _xlanggen if the format
// intentionally changes.
const (
	//nolint:lll // pinned cross-language donation ciphertext; must stay byte-for-byte
	xlangDonationVectorB64 = "BAACAAA8ALp+PEhpw3xAFeGO2HTSeyTBtJOzvda2dcz8mpnPG9w062fBM8iITZRslVPnCFEdqFRy34QmXInEMpc0SwEBAAF+WnF0WIvGqJsE2cnEDyVWPSoJPD/+WjxT57wFK4JDceWoxSOcxyavFYEE+k4Aa/+ntmPTezSuHiZP78hEM7r1UYKKFpusyQbNeVjSeCXg1QwBG7k5rvvGDiVI6gpe/NqLEixtHswh/DVeerkoo00jx6BWa6coXRp+5R6EGMghWUdpprwYeGJCFGm+ZhFjYPh+XC7xLIrVw+Q9q803MHZhqkmvAsGpKc5WRcXV0iUCfzE27qQ4ODjFR60M80AS6f8iADCuhOwLLKdJ4Z4MuZ/fAf3PlnS2D02gqA5tU6RCEoLybt182fxRprnzCFnJmOUPnaZoR3AZXjZSa2LHyMnZnEciAECZBHJeVZkmOAAAAAAAAADcN4brlUVR1kdL05+eug6TPl+rs1Mf+Q/HYIrjekaYvnb0QyOQtbYZqrAgJnwhoVwSpRLd9VSuuA=="
	xlangDonationPlaintext = `{"donation":"cross-language","steps":42}`
	xlangRecoveryKeyB64    = "TjYtXohpnhir+vUlv8UsUFAE+MNdazJb1psp4UZ2mic="
)

const xlangRSAPrivateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDWRWCyAh+SsUnu
fBuv3y8X6GgIHu3TSDAmIjICn+HkqvNidHyAbt5gn0k0Et6wqTRoFgZlzqOz1+VK
maDLq49E3PRmQm50w4FAWFnN4maIjbcb0ZoYzVEqd89cTKPIbocBrqsHoj1Qnv5M
nOv1eOK31r0OdxCVj3mBzNjxxdOH5q9MutfC9I+qXAqErFQaPZ6uRrH9mFoHA03L
kTIEALKAQgMsvCdXoDTxdv3lHynUP5r31Os8d4aoQdhPHUqwQZr09PSCIpQjMAam
j3o7Bvi9ykN3MB9iv4BcsASStTu75xIkpCaaGrGJLW/bKIWnr6v0fDT18LD5eC4o
5JjHSN5FAgMBAAECggEABooXnVjHiwDUEcFiAyNW3g4tNKHX0ZtLp7JJLL+hhr4G
T3XG9SpND6coD9aLZNosW9V5cwLhB9fAN/j9CXinyfexxTgxHYLeldUZQoyur+uE
g3njAwkRhjzU8r5x2WfKje09Ue5fgpXwcWw9nrns6de8LXrKFW8+sfMx5AKzX47T
51iRnW+ZzwbZUFy4cchzutVqaZIOxie4Mn+83YRvvCag5VcAy5T2Feb6pgahlhAJ
Ce8GNRhWoIiPAZ2o0rQfojZAXNqs/BEOHfb9Vz8s0KhiuIMSmrfQzMKPRfE8iwu6
sZDOI7Efkpmgy/MU34fFQwG2abfDBt59HtB1d7VvkQKBgQD/HOK48rA5V78KfktZ
Dpt76yfHx8iBNXfmjKjSxA0ntVuhdNbHp8ibMO4OS0rEeZE1Opo+0ZdQt77Co854
yplwCbUyMtjqh+YtjbJSOFa/qaj+WkKG1ajX14T76TOCFpOmKTszUetA6w+x9aAZ
tbG8nSShLZtPwg5eUJfYI9qKMQKBgQDXBCHzQf9H2ZC9ZEZLNjdYaUQDbra/rFUI
XTR3iQviuT3vGBzngX1YjvZceay3o9nBBP3itwY1TZuSDbLQVyCR4fcbx9suwYiG
6xf63ro5UU8tLdlqhudtcwfYU4jKx5K/FJril6clwMhDiMSrlKFQ0K/Kyff3dd7i
1PfkCc28VQKBgHmTSnjZLyIkruZRSZcnXvGvH0YV73ekA3/biJjo1VwXEZPgGnsL
eo56wvgM6ZS4WnsDcn59Y58T8dTQO5VU98ps1e0WTkl2ejs7S7/jGXQ9ZkvQt+OJ
7uztyHJEsEdOew60l4HdiD9nxhMI+0NFU26PdOVa1qkr0a0guzxF2eABAoGBAKa/
nLizgQ+uqbJHNsCTbj6RfF6RGQby1gsjhVICpYYSFPb8o0XixVvNmz/CWPEeD/zC
K0cMm7Lw2epd10P9ndOlA2e3CcNr8b54SeOToaZb6WRnP0p/DrFx2S6qMdbZCXRI
vYlnBQihRm4hfix2mtg6z2ocUcLG1bDiatCdzcD1AoGAb6XcTJ+dmMpeG0DlUOfb
RdsmANhN/L9OIAElTqVRvTZ4FT/IQ/zOpCEwVg89Gy5Kd+QRA2vkrecP27ETeVOr
dzVP4WA/cdNXNf6DyLBFbCXAvhxi4Yxh8LDG5HHBikzsW0o5GA/ysMfLy7ihc8wi
Ejd/krhk4b98j7cY9gacOSM=
-----END PRIVATE KEY-----
`

func TestHybridV4_CrossLanguage_DecryptsCollectLibDonation(t *testing.T) {
	ciphertext, err := base64.StdEncoding.DecodeString(xlangDonationVectorB64)
	require.NoError(t, err)

	// The data receiver opens the RSA target slot with its RSA private key.
	block, _ := pem.Decode([]byte(xlangRSAPrivateKeyPEM))
	require.NotNil(t, block)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	rsaPriv, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok)

	viaRSA, err := NewDecrypter(NewPrivateKeys(rsaPriv)).Decrypt(ciphertext)
	require.NoError(t, err)
	require.JSONEq(t, xlangDonationPlaintext, string(viaRSA))

	// The donor opens the AES recovery slot with the recovery key.
	recoveryKey, err := base64.StdEncoding.DecodeString(xlangRecoveryKeyB64)
	require.NoError(t, err)
	viaRecovery, err := NewDecrypterWithRecoveryKey(NewPrivateKeys(), recoveryKey).Decrypt(ciphertext)
	require.NoError(t, err)
	require.JSONEq(t, xlangDonationPlaintext, string(viaRecovery))
}
