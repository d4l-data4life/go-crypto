package d4lcrypto_test

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d4l-data4life/go-crypto/d4lcrypto"
)

const (
	pubKeyPath        = "../test_keys/public_key.pem"
	pubKeyPathBase64  = "../test_keys/public_key.spki"
	privkeyPath       = "../test_keys/private_key.pem"
	privkeyPathBase64 = "../test_keys/private_key.pkcs8"
)

func TestReadPubKeyFromFile(t *testing.T) {
	pubKey := &d4lcrypto.PublicKey{}
	err := pubKey.ReadFromFile("notexisting.pem")
	if err == nil {
		t.Fatal(err)
	}

	err = pubKey.ReadFromFile(pubKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	err = pubKey.ReadFromFile(pubKeyPathBase64)
	if err != nil {
		t.Fatal(err)
	}

	err = pubKey.ReadFromFile(privkeyPath)
	if !errors.Is(err, d4lcrypto.ErrPublicKeyDecodePEM) {
		t.Fatal(err)
	}

	err = pubKey.ReadFromFile(privkeyPathBase64)
	if !errors.Is(err, d4lcrypto.ErrPublicKeyParse) {
		t.Fatal(err)
	}
}

func TestReadPrivKeyFromFile(t *testing.T) {
	privKey := &d4lcrypto.PrivateKey{}
	err := privKey.ReadFromFile(privkeyPath)
	if err != nil {
		t.Fatal(err)
	}

	err = privKey.ReadFromFile(privkeyPathBase64)
	if err != nil {
		t.Fatal(err)
	}

	err = privKey.ReadFromFile(pubKeyPath)
	if !errors.Is(err, d4lcrypto.ErrPrivateKeyDecodePEM) {
		t.Fatal(err)
	}

	err = privKey.ReadFromFile(pubKeyPathBase64)
	if !errors.Is(err, d4lcrypto.ErrPrivateKeyParse) {
		t.Fatal(err)
	}
}

func TestPubKeyStringer(t *testing.T) {
	keyBytes, _ := os.ReadFile(pubKeyPath)

	pubKey := &d4lcrypto.PublicKey{}
	err := pubKey.ReadFromFile(pubKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	s := pubKey.String()
	assert.Equal(t, string(keyBytes), s)
}

func TestPrivKeyStringer(t *testing.T) {
	keyBytes, _ := os.ReadFile(privkeyPath)

	privKey := &d4lcrypto.PrivateKey{}
	err := privKey.ReadFromFile(privkeyPath)
	if err != nil {
		t.Fatal(err)
	}
	s := privKey.String()
	assert.Equal(t, string(keyBytes), s)
}

func TestNewPublicKeysOldInterface(t *testing.T) {
	pubKeys := d4lcrypto.NewPublicKeys(4)
	assert.Equal(t, 4, pubKeys.Cap())
}

func TestRead4PubKeysFromFiles(t *testing.T) {
	pubKeys := d4lcrypto.NewEmptyPublicKeys(4)
	err := pubKeys.ReadFromFiles(pubKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 3, pubKeys.Count())
	assert.Equal(t, 4, pubKeys.Cap())
}

func TestRead2PubKeysFromFiles(t *testing.T) {
	pubKeys := d4lcrypto.NewEmptyPublicKeys(2)
	err := pubKeys.ReadFromFiles(pubKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2, pubKeys.Count())
	assert.Equal(t, 2, pubKeys.Cap())
}

func TestReadBase64PubKeyFromString(t *testing.T) {
	ecPubKey := `MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEW1Twqwa+1ZgBxb1o3jOuIvYPnzuY6AtEIuBlISVEa9kDGEjbcLaFERgA1xFYO+bF3drsmFKiyzznhx8tscNFZw==`
	k := &d4lcrypto.PublicKey{}
	err := k.Read([]byte(ecPubKey))
	require.NoError(t, err, "error reading public key")

	ecPubKey = `MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE1BKVypDKKW/7d3HpLbZTtIOSHfpS6SOrrE64OxFgxFgb9YM485J6B9LcZQXufIgp11iBG4lo1BnUsZOjiYH9Pw==`
	err = k.Read([]byte(ecPubKey))
	require.NoError(t, err, "error reading public key")

	rsaPubKey := `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu9VBX7lskqmGksu3s5Pxvtc8JV+YpCsCDVadizejZJjxXmNW9BcU0s2ag1i6vch77MCvui7gOg
baUE/IUrMk5acMEde2kpjb82sWSNT/K9ILpiD/RCQJzupcwWeoUmeZPVx0XYiEB5O5oclxPuHhzqsMlsL5dNNqMAXUGB/VnA0c/QlC1MtbLMEDT1pzX/ds+XhYQlLj29An
VjsUmaXX9CdCFn4sFoyYqguiRIKXrEZU2wjSgh3aKg0dZ8quvj84c7EVQ249YvwzSqiDNW9m2K+cAtA42lvngi9zcgys9Ox4lFPrTN6/U7iu9Z6Fp/FyReYtCIVGxj3e6H
AUlFGMRQIDAQAB`
	err = k.Read([]byte(rsaPubKey))
	require.NoError(t, err, "error reading public key")
}

func TestReadBase64PrivKeyFromString(t *testing.T) {
	ecPrivKey := `MHQCAQEEIKEwX26vJ8Ne2G/MoZBn6IiPsyfR6md/3wQ/z1/f0PM+oAcGBSuBBAAKoUQDQgAEW1Twqwa+1ZgBxb1o3jOuIvYPnzuY6AtEIuBlISVEa9kDGEj
bcLaFERgA1xFYO+bF3drsmFKiyzznhx8tscNFZw==`
	k := &d4lcrypto.PrivateKey{}
	err := k.Read([]byte(ecPrivKey))
	require.NoError(t, err, "error reading public key")
}

func TestReadPubKeysFromStrings(t *testing.T) {
	keyBytes1, _ := os.ReadFile(pubKeyPath)
	keyBytes2, _ := os.ReadFile(pubKeyPath + ".1")
	keyBytes3, _ := os.ReadFile(pubKeyPath + ".2")

	pubKeys := d4lcrypto.NewEmptyPublicKeys(4)
	err := pubKeys.ReadFromStrings(string(keyBytes1), string(keyBytes2), string(keyBytes3))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 3, pubKeys.Count())
	assert.Equal(t, 4, pubKeys.Cap())

	keyBytes1[3] = '.'
	err = pubKeys.ReadFromStrings(string(keyBytes1))
	if !errors.Is(err, d4lcrypto.ErrPublicKeyDecodeBase64) {
		t.Fatal(err)
	}
}

func TestNewPubKeysFromStrings(t *testing.T) {
	keyBytes1, _ := os.ReadFile(pubKeyPath)
	keyBytes2, _ := os.ReadFile(pubKeyPath + ".1")
	keyBytes3, _ := os.ReadFile(pubKeyPath + ".2")

	pubKeys, err := d4lcrypto.NewPublicKeysFromStrings(string(keyBytes1), string(keyBytes2), string(keyBytes3))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 3, pubKeys.Count())
	assert.Equal(t, 3, pubKeys.Cap())
}

func TestNewPrivateKeysOldInterface(t *testing.T) {
	privKeys := d4lcrypto.NewPrivateKeys(4)
	assert.Equal(t, 4, privKeys.Cap())
}

func TestRead4PrivKeysFromFiles(t *testing.T) {
	privKeys := d4lcrypto.NewEmptyPrivateKeys(4)
	err := privKeys.ReadFromFiles(privkeyPath)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 3, privKeys.Count())
	assert.Equal(t, 4, privKeys.Cap())
}

func TestRead2PrivKeysFromFiles(t *testing.T) {
	privKeys := d4lcrypto.NewEmptyPrivateKeys(2)
	err := privKeys.ReadFromFiles(privkeyPath)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2, privKeys.Count())
	assert.Equal(t, 2, privKeys.Cap())
}

func TestReadPrivKeysFromStrings(t *testing.T) {
	keyBytes1, _ := os.ReadFile(privkeyPath)
	keyBytes2, _ := os.ReadFile(privkeyPath + ".1")
	keyBytes3, _ := os.ReadFile(privkeyPath + ".2")

	privKeys := d4lcrypto.NewEmptyPrivateKeys(4)
	err := privKeys.ReadFromStrings(string(keyBytes1), string(keyBytes2), string(keyBytes3))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 3, privKeys.Count())
	assert.Equal(t, 4, privKeys.Cap())

	keyBytes1[3] = '.'
	err = privKeys.ReadFromStrings(string(keyBytes1))
	if !errors.Is(err, d4lcrypto.ErrPrivateKeyDecodeBase64) {
		t.Fatal(err)
	}
}

func TestNewPrivKeysFromStrings(t *testing.T) {
	keyBytes1, _ := os.ReadFile(privkeyPath)
	keyBytes2, _ := os.ReadFile(privkeyPath + ".1")
	keyBytes3, _ := os.ReadFile(privkeyPath + ".2")

	privKeys, err := d4lcrypto.NewPrivateKeysFromStrings(string(keyBytes1), string(keyBytes2), string(keyBytes3))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 3, privKeys.Count())
	assert.Equal(t, 3, privKeys.Cap())
}
