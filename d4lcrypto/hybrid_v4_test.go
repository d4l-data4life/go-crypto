package d4lcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
)

// phoneKeysFromScalar builds a secp256k1 keypair from a fixed 32-byte scalar.
func phoneKeysFromScalar(t *testing.T, scalarHex string) (*PublicKey, *PrivateKey) {
	t.Helper()
	scalar, err := hex.DecodeString(scalarHex)
	require.NoError(t, err)

	priv := new(ecdsa.PrivateKey)
	priv.Curve = secp256k1.S256()
	priv.D = new(big.Int).SetBytes(scalar)
	priv.X, priv.Y = secp256k1.S256().ScalarBaseMult(scalar)
	return NewPublicKey(&priv.PublicKey), NewPrivateKey(priv)
}

func TestHybridV4_RoundTrip(t *testing.T) {
	pub, priv := phoneKeysFromScalar(t, "1111111111111111111111111111111111111111111111111111111111111111")
	plaintext := []byte(`{"dailies":[{"summaryId":"x","steps":1234}]}`)

	ciphertext, err := EncryptHybridV4(plaintext, ECSlot(DecrypterMobileApp, pub))
	require.NoError(t, err)

	got, err := NewDecrypterFromKeys(ECKey(DecrypterMobileApp, priv)).Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestHybridV4_WrongDecrypterID(t *testing.T) {
	pub, priv := phoneKeysFromScalar(t, "1111111111111111111111111111111111111111111111111111111111111111")
	ciphertext, err := EncryptHybridV4([]byte("hello"), ECSlot(DecrypterMobileApp, pub))
	require.NoError(t, err)

	_, err = NewDecrypterFromKeys(ECKey(DecrypterDataReceiver, priv)).Decrypt(ciphertext)
	require.ErrorIs(t, err, ErrHybridV4NoSlot)
}

const (
	// Canonical wire-format vector. Client implementations of this format pin the same bytes,
	// so a drift on either side shows up as a failure here.
	vectorScalarHex = "c87509a1c067115d2a8f8e7c1f3a9b6d4e2f0a1b3c5d7e9f00112233445566aa"
	vectorPlaintext = `{"hello":"garmin","spo2":97}`
	//nolint:lll // pinned cross-language ciphertext vector, must stay byte-for-byte identical
	vectorCiphertextB64 = "BAABAAJ9AAQ8cq3bT98Jr5TwyU1/6So4an5wz4odhZFjhrslNcexsTswaw/ghWZdj8GyiuFnbNOtbgjq7aIl/jjQ2k3lVwPgRERERERERERERERE39swXW9F+dlAkGVh6h3GKlmYupkDAyD9uDDG1thiFXwuBD2b4nXat0+xDtoLKGluVVVVVVVVVVVVVVVVLAAAAAAAAAAiML/XtYqK2tHnBJiG/TF4aUypAIwbZsnv8NGcW5rVCnt+r8MhJETi4OQIWQ=="
)

// fixedV4Randomness returns deterministic randomness for the canonical vector.
func fixedV4Randomness() v4Randomness {
	rep := func(b byte) []byte {
		out := make([]byte, 0)
		for i := 0; i < 32; i++ {
			out = append(out, b)
		}
		return out
	}
	return v4Randomness{
		dataKey:   rep(0x22),
		ephPriv:   rep(0x33),
		ecNonce:   rep(0x44)[:12],
		payloadIV: rep(0x55)[:12],
	}
}

func TestHybridV4_DeterministicVector(t *testing.T) {
	pub, priv := phoneKeysFromScalar(t, vectorScalarHex)

	ciphertext, err := encryptHybridV4ForEC([]byte(vectorPlaintext), DecrypterMobileApp, pub, fixedV4Randomness())
	require.NoError(t, err)

	b64 := base64.StdEncoding.EncodeToString(ciphertext)
	// Pin the exact bytes so the wire format cannot drift out of sync with client implementations.
	require.Equal(t, vectorCiphertextB64, b64)

	// Round-trips with the matching private key.
	got, err := NewDecrypterFromKeys(ECKey(DecrypterMobileApp, priv)).Decrypt(ciphertext)
	require.NoError(t, err)
	require.JSONEq(t, vectorPlaintext, string(got))

	// Determinism: same inputs -> same bytes.
	again, err := encryptHybridV4ForEC([]byte(vectorPlaintext), DecrypterMobileApp, pub, fixedV4Randomness())
	require.NoError(t, err)
	require.True(t, bytes.Equal(ciphertext, again))
}

func TestHybridV4_RSASlot(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	plaintext := []byte(`{"donation":"target"}`)

	ciphertext, err := EncryptHybridV4(plaintext, RSASlot(DecrypterDataReceiver, NewPublicKey(&rsaKey.PublicKey)))
	require.NoError(t, err)

	got, err := NewDecrypter(NewPrivateKeys(rsaKey)).Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestHybridV4_AESSlot(t *testing.T) {
	recoveryKey := bytes.Repeat([]byte{0x2a}, 32)
	plaintext := []byte(`{"donation":"recovery"}`)

	ciphertext, err := EncryptHybridV4(plaintext, AESSlot(DecrypterMobileApp, recoveryKey))
	require.NoError(t, err)

	got, err := NewDecrypterWithRecoveryKey(NewPrivateKeys(), recoveryKey).Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// During migration a data receiver gets both pre-v4 (v3) and v4 donations. A single Decrypter
// (its RSA key) must transparently decode both — v3 via the legacy target branch, v4 via the
// DataReceiver+RSA slot — so the reader can be deployed before the phone switches to v4.
func TestHybridV4_Decrypter_HandlesV3AndV4(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := NewPublicKey(&rsaKey.PublicKey)
	decrypter := NewDecrypter(NewPrivateKeys(rsaKey)) // RSA only, no recovery key

	// A pre-v4 (v3, GCM+recovery) donation, decrypted via its RSA target branch.
	v3, err := NewEncrypterWithRecoveryKey(pub, bytes.Repeat([]byte{0x2a}, 32)).Encrypt([]byte("v3 payload"))
	require.NoError(t, err)
	got3, err := decrypter.Decrypt(v3)
	require.NoError(t, err)
	require.Equal(t, "v3 payload", string(got3))

	// A v4 donation with a DataReceiver+RSA slot, decrypted by the same Decrypter.
	v4, err := EncryptHybridV4([]byte("v4 payload"), RSASlot(DecrypterDataReceiver, pub))
	require.NoError(t, err)
	got4, err := decrypter.Decrypt(v4)
	require.NoError(t, err)
	require.Equal(t, "v4 payload", string(got4))
}

// Strict decrypterID matching: a v4 slot must be addressed to the Decrypter's identity. The
// data receiver refuses a slot tagged for the mobile app even though its RSA key could open it.
func TestHybridV4_Decrypter_RejectsWrongDecrypterID(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := NewPublicKey(&rsaKey.PublicKey)

	// An RSA slot tagged for the mobile app, not the data receiver.
	ciphertext, err := EncryptHybridV4([]byte("secret"), RSASlot(DecrypterMobileApp, pub))
	require.NoError(t, err)

	_, err = NewDecrypter(NewPrivateKeys(rsaKey)).Decrypt(ciphertext)
	require.ErrorIs(t, err, ErrHybridV4NoSlot)
}

// Key rotation: a v4 slot encrypted to an older key still decrypts as long as that key stays
// in the keychain alongside the new one — every matching key is tried.
func TestHybridV4_Decrypter_KeyRotation(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	plaintext := []byte("encrypted to the old key")

	// Encrypted to the OLD key only.
	ciphertext, err := EncryptHybridV4(plaintext, RSASlot(DecrypterDataReceiver, NewPublicKey(&oldKey.PublicKey)))
	require.NoError(t, err)

	// A keychain holding the new key first and the old key second still opens it via the old key.
	got, err := NewDecrypter(NewPrivateKeys(newKey, oldKey)).Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// A hand-built keychain (NewDecrypterFromKeys) opens a donation via whichever slot its keys
// match — here the RSA target and the AES recovery slot are both present.
func TestHybridV4_Decrypter_CustomKeychain(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	recoveryKey := bytes.Repeat([]byte{0x2a}, 32)
	plaintext := []byte(`{"steps":99}`)

	ciphertext, err := EncryptHybridV4(plaintext,
		AESSlot(DecrypterMobileApp, recoveryKey),
		RSASlot(DecrypterDataReceiver, NewPublicKey(&rsaKey.PublicKey)),
	)
	require.NoError(t, err)

	d := NewDecrypterFromKeys(
		RSAKey(DecrypterDataReceiver, NewPrivateKey(rsaKey)),
		AESKey(DecrypterMobileApp, recoveryKey),
	)
	got, err := d.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// A donation carries two slots for one payload: the data receiver opens the RSA slot, the
// donor opens the AES recovery slot — both recover the identical data key.
func TestHybridV4_Donation_BothRecipients(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	recoveryKey := bytes.Repeat([]byte{0x2a}, 32)
	plaintext := []byte(`{"steps":1234}`)

	ciphertext, err := EncryptHybridV4(plaintext,
		AESSlot(DecrypterMobileApp, recoveryKey),
		RSASlot(DecrypterDataReceiver, NewPublicKey(&rsaKey.PublicKey)),
	)
	require.NoError(t, err)

	viaRSA, err := NewDecrypter(NewPrivateKeys(rsaKey)).Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, viaRSA)

	viaRecovery, err := NewDecrypterWithRecoveryKey(NewPrivateKeys(), recoveryKey).Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, viaRecovery)
}
