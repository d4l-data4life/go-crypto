package d4lcrypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d4l-data4life/go-crypto/d4lcrypto"
)

//nolint:gochecknoglobals
var sigPrivateKey = d4lcrypto.NewPrivateKeyFromString(`
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC8sPa4DPmUrHTx
maXE2iSERwWvLG/cfH0hmAxD6Nu/f+13wskWQSnOvN9qbocq9KCXGiaz4z+dX6ZO
Lj1tzqA8k4o1AkOkU43z5JcSdyVLZ7noGY7n0tKpQz57cTSrDMr5oRGf0wDMZ4ba
aV+DNXk7jM908RT/un4JT0jVeiHhlVGsJPSHZGC6FIaFNZmGl6ZG8EfGwmY+ihDN
n48MeOdKjPBAyrBYettnI+Qs2y/6bBMLTYURcaLyF0CGPjeZtilNuMXRdhsDOaCZ
BtUSjfldwM13rTGIdpICt4hr4NRRTv1gv18NWhQBYRGcTsXy9X8mBXB7ypHbYUv9
vAlpXmr3AgMBAAECggEAKUUTUUIVPH1Tvpv6c8m6fuwBxESV2sWnoLdex2Og3Iug
ZrdFwAZUnJEW1HKEQdLrZOElYebsPQF0oFjguqmcxmMGsX1jSge0Xom6uSEyGQIA
2VDtvqqPxNGeUuV5vYe4xUyDTE+cNxjVl+PALjR95ZZwsYUhMKWbd3HN3lMuIeZk
Erv2QBbQZ1Q/da+KdXwbbrbU1kj708lvsInc5eu3SpV2xZabykSTqsCGJNTAPOWh
L0JZrZqBrBYN9OHki/UNDEro8bFTEuunOQn5wEP8Xt6EiHUFNjcE9ZKwld8O2Wq0
3pa2S2x9I2wvTatfP1/XFY0NK5Q5LKn4obHdJLd7IQKBgQD1YgbO/WDHuBbUCjkL
EEjJpjUGtRKpSvzSL/gzOtNKGAiVMzSysEQEu4wgOwW8n53dVLO7TZCvNVVWDEhX
WT53mvtLOP2Yq2TR17NXg4k51e5i8+PLaNMxd4lN4MCr+eXqlYY1+Io7xIhcRzFr
vW63JEaqPuTAyx8OfKvpHMTmvwKBgQDE2v6WxK6KkxtUgROg6SKpJEfjkmLeQ4Eu
SuZy7uPZ4Qciq1VQeXN9tKBblaBaSTvm+N5H7Sq5rtT0Gpe67Yjbbhal10KqoUr2
5CqvWNZNP9TtVknQy4PjMbXHzZsE3R2X7qDov5uBg0wIawjC/v/chULZ8ZOc+A5s
lo6g/EGByQKBgQDBhavk9wOqv06Rr/ZI+XDOR9yuC4RKK6+0fMx8arpURxwNvzKi
ck1Shi7/BE2D80ZnVfPhlkyzQZappEoxSVrwrTPeoXWvQAzlSf5Q2JYTHNtDAyH2
PBfDfYi1+Lk7aHyhQ4dzbS5n8JmyXRtm4yE8IsnwXmW+fvNhU4Wo9V18tQKBgQC2
niYBvbHh0fhPm3KXGs/Rs1uRbRKU+HCVflxskNsFG7Ff4yvA/Po7yl3cuGDKgRe1
/HdQqF6zZNIfJbBOc987GNSfwqMQ4ZJGmYJTqokbnrSr/Bl8PeA62rm1AjLl/y5d
7LyPTnk3W5MkWA8HvkGj1GghAO+cda4D5GOqSnmGqQKBgQDZZmpZLRZrmYGWKk1p
1HcjOQXgI53u+CbwNL/uKBi6Ex4QmAsoAjQ2DT97sI5Syrlqfm86LI7ROmCUS/fY
Qvs8+iZq8zbVslSRDIR/dIJ1nDuXtGtwvWwsDY2kK0pQpbKML+LgffyXRc/bITZk
v7OtkSAzPia72+/DXGej51tukA==
-----END PRIVATE KEY-----`)

//nolint:gochecknoglobals
var sigPublicKeys, _ = d4lcrypto.NewPublicKeysFromStrings(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvLD2uAz5lKx08ZmlxNok
hEcFryxv3Hx9IZgMQ+jbv3/td8LJFkEpzrzfam6HKvSglxoms+M/nV+mTi49bc6g
PJOKNQJDpFON8+SXEnclS2e56BmO59LSqUM+e3E0qwzK+aERn9MAzGeG2mlfgzV5
O4zPdPEU/7p+CU9I1Xoh4ZVRrCT0h2RguhSGhTWZhpemRvBHxsJmPooQzZ+PDHjn
SozwQMqwWHrbZyPkLNsv+mwTC02FEXGi8hdAhj43mbYpTbjF0XYbAzmgmQbVEo35
XcDNd60xiHaSAreIa+DUUU79YL9fDVoUAWERnE7F8vV/JgVwe8qR22FL/bwJaV5q
9wIDAQAB
-----END PUBLIC KEY-----`)

//
//nolint:lll
const sigStrippedPublicKey = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvLD2uAz5lKx08ZmlxNokhEcFryxv3Hx9IZgMQ+jbv3/td8LJFkEpzrzfam6HKvSglxoms+M/nV+mTi49bc6gPJOKNQJDpFON8+SXEnclS2e56BmO59LSqUM+e3E0qwzK+aERn9MAzGeG2mlfgzV5O4zPdPEU/7p+CU9I1Xoh4ZVRrCT0h2RguhSGhTWZhpemRvBHxsJmPooQzZ+PDHjnSozwQMqwWHrbZyPkLNsv+mwTC02FEXGi8hdAhj43mbYpTbjF0XYbAzmgmQbVEo35XcDNd60xiHaSAreIa+DUUU79YL9fDVoUAWERnE7F8vV/JgVwe8qR22FL/bwJaV5q9wIDAQAB`

//nolint:gochecknoglobals
var sigPublicKeys2, _ = d4lcrypto.NewPublicKeysFromStrings(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpKo7Xt5yJxT2os5mzEo
C3N/pKXXno7UV0EWq8FCfthRi4/DMRGzs/EGwnfMwWtVXX2wEa8rli33vBah1peM
l78LS0TKjRNO6CurS5uVHG7jtgSK6YfrbqQHbbYEfYwuMtxrC7uxAT1JyTMfEDix
CKw/GtKMZR2HV80N8nUtDsbdkjq01uA2iok0rprjxBErZ/p95qXE/nKK1IN+w1nF
Sh81b6p5DoF0PxGuvI1SaB0pWTpM80eddPkh+5C8oNWXzEfepC6KJLF5sDWJGwX3
fkZ0bvhSZHPuIxiw3WCo1PCr191KMtqefegHxhS2HkGvbSZbmbZX/s/mJfDjimfU
UQIDAQAB
-----END PUBLIC KEY-----`)

//nolint:gochecknoglobals
var sigPrivateKeyEC1 = d4lcrypto.NewPrivateKeyFromString(`
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIKEwX26vJ8Ne2G/MoZBn6IiPsyfR6md/3wQ/z1/f0PM+oAcGBSuBBAAK
oUQDQgAEW1Twqwa+1ZgBxb1o3jOuIvYPnzuY6AtEIuBlISVEa9kDGEjbcLaFERgA
1xFYO+bF3drsmFKiyzznhx8tscNFZw==
-----END EC PRIVATE KEY-----`)

//nolint:gochecknoglobals
var sigPublicKeysEC1, _ = d4lcrypto.NewPublicKeysFromStrings(`
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEW1Twqwa+1ZgBxb1o3jOuIvYPnzuY6AtE
IuBlISVEa9kDGEjbcLaFERgA1xFYO+bF3drsmFKiyzznhx8tscNFZw==
-----END PUBLIC KEY-----`)

//nolint:gochecknoglobals
var sigTestMessage = []byte("Hello World!")

func TestSign(t *testing.T) {
	signer := d4lcrypto.NewSigner(sigPrivateKey)
	signature, err := signer.Sign(sigTestMessage)
	if err != nil {
		t.Errorf("error when signing message: %v", err)
	}

	t.Parallel()

	t.Run("verify with matching public key", func(t *testing.T) {
		verifier := d4lcrypto.NewVerifier(sigPublicKeys)
		err = verifier.Verify(sigTestMessage, signature)
		require.NoErrorf(t, err, "error verifying signature")

		err = verifier.Verify([]byte("Hallo Welt!"), signature)
		assert.Equal(t, d4lcrypto.ErrVerification, err, "should fail on expected error")
	})

	t.Run("verify with different public key", func(t *testing.T) {
		verifier := d4lcrypto.NewVerifier(sigPublicKeys2)
		err = verifier.Verify(sigTestMessage, signature)
		assert.Equal(t, d4lcrypto.ErrVerification, err, "should fail on expected error")

		err = verifier.Verify([]byte("Hallo Welt!"), signature)
		assert.Equal(t, d4lcrypto.ErrVerification, err, "should fail on expected error")
	})
}

func TestSignElliptic(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"Curve P224", elliptic.P224()},
		{"Curve P256", elliptic.P256()},
		{"Curve P384", elliptic.P384()},
		{"Curve P521", elliptic.P521()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoErrorf(t, err, "Failed to generate private key")
			signer := d4lcrypto.NewSigner(d4lcrypto.NewPrivateKey(pk))

			signature, err := signer.Sign(sigTestMessage)
			if err != nil {
				t.Errorf("error when signing message: %v", err)
			}
			verifier := d4lcrypto.NewVerifier(d4lcrypto.NewPublicKeys(&pk.PublicKey))
			err = verifier.Verify(sigTestMessage, signature)
			require.NoErrorf(t, err, "error verifying signature")

			err = verifier.Verify([]byte("Hallo Welt!"), signature)
			assert.Equal(t, d4lcrypto.ErrVerification, err, "should fail on expected error")
		})
	}
}

func TestSignElliptic256k1(t *testing.T) {
	assert.NotNil(t, sigPrivateKeyEC1, "error parsing private key")
	assert.NotNil(t, sigPublicKeysEC1, "error parsing public key")
	signer := d4lcrypto.NewSigner(sigPrivateKeyEC1)
	signature, err := signer.Sign(sigTestMessage)
	if err != nil {
		t.Errorf("error when signing message: %v", err)
	}

	t.Run("verify with EC public key", func(t *testing.T) {
		verifier := d4lcrypto.NewVerifier(sigPublicKeysEC1)
		err = verifier.Verify(sigTestMessage, signature)
		require.NoErrorf(t, err, "error verifying signature")

		err = verifier.Verify([]byte("Hallo Welt!"), signature)
		assert.Equal(t, d4lcrypto.ErrVerification, err, "should fail on expected error")
	})
}

func TestVerifyElliptic256k1Simple(t *testing.T) {
	authMessage := `hello`
	signatureBase64 := `QiuYRs6vf/ge5wGwBYlwDjh8UsHMtXKjHukKNK3up/1ag7d8SshboLjGf/Wv8XtS3+J+TZcZ0g93bhqLWNqlUw==`
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	require.NoErrorf(t, err, "error decoding base64 signature")
	sigPublicKeysEC2, err := d4lcrypto.NewPublicKeysFromStrings(`
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1BKVypDKKW/7d3HpLbZTtIOSHfpS6SOr
rE64OxFgxFgb9YM485J6B9LcZQXufIgp11iBG4lo1BnUsZOjiYH9Pw==
-----END PUBLIC KEY-----`)
	assert.NotNil(t, sigPrivateKeyEC1, "error parsing private key")

	t.Run("verify auth token with EC public key", func(t *testing.T) {
		verifier := d4lcrypto.NewVerifier(sigPublicKeysEC2)
		assert.NotNil(t, sigPublicKeysEC2, "error parsing public key")
		err = verifier.Verify([]byte(authMessage), signature)
		require.NoErrorf(t, err, "error verifying signature")

		err = verifier.Verify([]byte("Hallo Welt!"), signature)
		assert.Equal(t, d4lcrypto.ErrVerification, err, "should fail on expected error")
	})
}

func TestVerifyElliptic256k1Token(t *testing.T) {
	//nolint:lll
	authMessage := `{"token":"top-secret-random-token-from-the-api","pub":"-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEAs4O+DFKRFPwWM+IEzucmdiF/1tgM30O\n7HUgQV3wFozjyWYZEcmOpn9LzxkdBqATr2ooqwL04jDwSbK6nxthvg==\n-----END PUBLIC KEY-----\n"}`
	signatureBase64 := `fgX2ogP53kO/BJXTm7A28HvSk1aJsild0mgSTEtHybEAKUfQcl8Kv08ARU+aI7XN2DcvPFMdeCf+899S+GEFRA==`
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	require.NoErrorf(t, err, "error decoding base64 signature")

	sigPublicKeysEC3, err := d4lcrypto.NewPublicKeysFromStrings(`
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEAs4O+DFKRFPwWM+IEzucmdiF/1tgM30O
7HUgQV3wFozjyWYZEcmOpn9LzxkdBqATr2ooqwL04jDwSbK6nxthvg==
-----END PUBLIC KEY-----`)
	require.NoErrorf(t, err, "error parsing public key")

	t.Run("verify auth token with EC public key", func(t *testing.T) {
		verifier := d4lcrypto.NewVerifier(sigPublicKeysEC3)
		err = verifier.Verify([]byte(authMessage), signature)
		require.NoErrorf(t, err, "error verifying signature")

		err = verifier.Verify([]byte("Hallo Welt!"), signature)
		assert.Equal(t, d4lcrypto.ErrVerification, err, "should fail on expected error")
	})
}
