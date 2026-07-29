package d4lcrypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// This file pins the compatibility contract of Decrypter.Decrypt across every hybrid
// encryption version:
//
//   - backward: v1–v3 ciphertexts must keep decrypting through the keychain Decrypter,
//     however it was built;
//   - forward: v4 ciphertexts must open through Decrypters built with the pre-v4
//     constructors (NewDecrypter / NewDecrypterWithRecoveryKey), whose keychains are
//     created transparently;
//   - robustness: corrupt, truncated or malicious records must fail with a clean error —
//     never panic, never allocate absurd amounts, never return wrong plaintext.

// version names used across the compatibility tests
const (
	compatV1         = "v1"
	compatV2         = "v2"
	compatV3         = "v3"
	compatV4RSA      = "v4-rsa"
	compatV4Recovery = "v4-recovery"
	compatV4Both     = "v4-both"
	compatV4EC       = "v4-ec"
)

// compatFixtures is one key universe shared by the compatibility tests: the data receiver's
// RSA key pair, the donor's recovery key and the phone's EC key pair.
type compatFixtures struct {
	rsaKey      *rsa.PrivateKey
	rsaPub      *PublicKey
	recoveryKey []byte
	ecPub       *PublicKey
	ecPriv      *PrivateKey
	plaintext   []byte
}

func newCompatFixtures(t *testing.T) compatFixtures {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecPub, ecPriv := phoneKeysFromScalar(t, "2222222222222222222222222222222222222222222222222222222222222222")
	return compatFixtures{
		rsaKey:      rsaKey,
		rsaPub:      NewPublicKey(&rsaKey.PublicKey),
		recoveryKey: bytes.Repeat([]byte{0x2a}, 32),
		ecPub:       ecPub,
		ecPriv:      ecPriv,
		plaintext:   []byte(`{"hello":"compat"}`),
	}
}

func (f compatFixtures) rsaOnly() *Decrypter { return NewDecrypter(NewPrivateKeys(f.rsaKey)) }

func (f compatFixtures) rsaAndRecovery() *Decrypter {
	return NewDecrypterWithRecoveryKey(NewPrivateKeys(f.rsaKey), f.recoveryKey)
}

func (f compatFixtures) recoveryOnly() *Decrypter {
	return NewDecrypterWithRecoveryKey(NewPrivateKeys(), f.recoveryKey)
}

func (f compatFixtures) ecPhone() *Decrypter {
	return NewDecrypterFromKeys(ECKey(DecrypterMobileApp, f.ecPriv))
}

// encryptCompat produces one ciphertext of the named version / slot layout.
func encryptCompat(t *testing.T, f compatFixtures, version string) []byte {
	t.Helper()
	var blob []byte
	var err error
	switch version {
	case compatV1:
		blob, err = NewEncrypterWithVersion(f.rsaPub, HybridEncryptionAESWithCBC).Encrypt(f.plaintext)
	case compatV2:
		blob, err = NewEncrypter(f.rsaPub).Encrypt(f.plaintext)
	case compatV3:
		blob, err = NewEncrypterWithRecoveryKey(f.rsaPub, f.recoveryKey).Encrypt(f.plaintext)
	case compatV4RSA:
		blob, err = EncryptHybridV4(f.plaintext, RSASlot(DecrypterDataReceiver, f.rsaPub))
	case compatV4Recovery:
		blob, err = EncryptHybridV4(f.plaintext, AESSlot(DecrypterMobileApp, f.recoveryKey))
	case compatV4Both:
		blob, err = EncryptHybridV4(f.plaintext,
			AESSlot(DecrypterMobileApp, f.recoveryKey),
			RSASlot(DecrypterDataReceiver, f.rsaPub))
	case compatV4EC:
		blob, err = EncryptHybridV4(f.plaintext, ECSlot(DecrypterMobileApp, f.ecPub))
	default:
		t.Fatalf("unknown version %q", version)
	}
	require.NoError(t, err)
	return blob
}

// TestDecrypt_CompatibilityMatrix runs every ciphertext version against every common way a
// Decrypter is built and pins exactly which combinations open. In particular: keychain
// decrypters keep opening v1–v3 (backward), and decrypters built with the pre-v4
// constructors transparently open v4 records addressed to the keys they hold (forward).
func TestDecrypt_CompatibilityMatrix(t *testing.T) {
	f := newCompatFixtures(t)
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	versions := []string{compatV1, compatV2, compatV3, compatV4RSA, compatV4Recovery, compatV4Both, compatV4EC}
	wantVersionByte := map[string]byte{
		compatV1:         HybridEncryptionAESWithCBC,
		compatV2:         HybridEncryptionAESWithGCM,
		compatV3:         HybridEncryptionAESWithGCMWithRecovery,
		compatV4RSA:      HybridEncryptionV4,
		compatV4Recovery: HybridEncryptionV4,
		compatV4Both:     HybridEncryptionV4,
		compatV4EC:       HybridEncryptionV4,
	}

	opens := func(vs ...string) map[string]bool {
		m := make(map[string]bool, len(vs))
		for _, v := range vs {
			m[v] = true
		}
		return m
	}
	decrypters := []struct {
		name  string
		build func() *Decrypter
		opens map[string]bool
	}{
		{"NewDecrypter/rsa", f.rsaOnly,
			opens(compatV1, compatV2, compatV3, compatV4RSA, compatV4Both)},
		{"NewDecrypterWithRecoveryKey/rsa+recovery", f.rsaAndRecovery,
			opens(compatV1, compatV2, compatV3, compatV4RSA, compatV4Recovery, compatV4Both)},
		{"NewDecrypterWithRecoveryKey/recovery-only", f.recoveryOnly,
			opens(compatV3, compatV4Recovery, compatV4Both)},
		{"NewDecrypterFromKeys/rsa", func() *Decrypter {
			return NewDecrypterFromKeys(RSAKey(DecrypterDataReceiver, NewPrivateKey(f.rsaKey)))
		}, opens(compatV1, compatV2, compatV3, compatV4RSA, compatV4Both)},
		{"NewDecrypterFromKeys/recovery", func() *Decrypter {
			return NewDecrypterFromKeys(AESKey(DecrypterMobileApp, f.recoveryKey))
		}, opens(compatV3, compatV4Recovery, compatV4Both)},
		{"NewDecrypterFromKeys/ec-phone", f.ecPhone, opens(compatV4EC)},
		{"NewDecrypter/wrong-rsa", func() *Decrypter {
			return NewDecrypter(NewPrivateKeys(otherRSA))
		}, opens()},
		{"NewDecrypter/nil-keys", func() *Decrypter { return NewDecrypter(nil) }, opens()},
	}

	for _, version := range versions {
		blob := encryptCompat(t, f, version)
		require.Equal(t, wantVersionByte[version], blob[0], "unexpected on-wire version byte")
		for _, d := range decrypters {
			t.Run(version+"/"+d.name, func(t *testing.T) {
				got, err := d.build().Decrypt(blob)
				if d.opens[version] {
					require.NoError(t, err)
					require.Equal(t, f.plaintext, got)
				} else {
					require.Error(t, err)
					require.Nil(t, got)
				}
			})
		}
	}
}

// TestDecrypt_CorruptedBytesNeverYieldWrongPlaintext flips each byte of a ciphertext in turn
// and decrypts: the result must be an error or the exact original plaintext (a flipped byte
// the taken decryption path never consumes, e.g. the RSA branch of a v3 record opened via its
// recovery key) — never silently wrong data. For single-slot v4 records every byte is
// load-bearing, so every flip must fail outright. (v1 is unauthenticated AES-CBC and
// inherently cannot make this promise — the reason it was deprecated.)
func TestDecrypt_CorruptedBytesNeverYieldWrongPlaintext(t *testing.T) {
	f := newCompatFixtures(t)
	cases := []struct {
		name     string
		version  string
		decrypt  *Decrypter
		failOnly bool // every flip must fail: no byte of the record is ignorable
	}{
		{"v2 via RSA key", compatV2, f.rsaOnly(), false},
		{"v3 via recovery key", compatV3, f.recoveryOnly(), false},
		{"v4 AES slot via recovery key", compatV4Recovery, f.recoveryOnly(), true},
		{"v4 EC slot via phone key", compatV4EC, f.ecPhone(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := encryptCompat(t, f, tc.version)
			for i := range blob {
				mutated := append([]byte(nil), blob...)
				mutated[i] ^= 0x01
				got, err := tc.decrypt.Decrypt(mutated)
				if tc.failOnly {
					require.Errorf(t, err, "flipping byte %d must fail decryption", i)
					continue
				}
				if err == nil {
					require.Equalf(t, f.plaintext, got, "flipping byte %d yielded wrong plaintext", i)
				}
			}
		})
	}
}

// TestDecrypt_TruncatedCiphertextsFail feeds every strict prefix of a valid record to a
// matching Decrypter: all must fail with an error rather than panic or succeed.
func TestDecrypt_TruncatedCiphertextsFail(t *testing.T) {
	f := newCompatFixtures(t)
	cases := []struct {
		name    string
		version string
		decrypt *Decrypter
	}{
		{"v1", compatV1, f.rsaOnly()},
		{"v2", compatV2, f.rsaOnly()},
		{"v3", compatV3, f.rsaAndRecovery()},
		{"v4", compatV4Both, f.rsaAndRecovery()},
		{"v4-ec", compatV4EC, f.ecPhone()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob := encryptCompat(t, f, tc.version)
			for cut := 0; cut < len(blob); cut++ {
				_, err := tc.decrypt.Decrypt(blob[:cut])
				require.Errorf(t, err, "prefix of %d/%d bytes must fail", cut, len(blob))
			}
		})
	}
}

// TestDecrypt_ImplausibleLengthFieldsRejected sets on-wire length fields to absurd values:
// Decrypt must reject them with a clean error before allocating anything of that size (a
// corrupt record must not be able to OOM the service, and the v1 length must not overflow
// the block-size round-up into a slicing panic).
func TestDecrypt_ImplausibleLengthFieldsRejected(t *testing.T) {
	f := newCompatFixtures(t)

	t.Run("v4 payload length", func(t *testing.T) {
		blob := encryptCompat(t, f, compatV4Recovery)
		// header(3) + slot header(4) + AES slot blob(60) + payload IV(12) → payload length field
		off := 3 + 4 + 60 + 12
		binary.LittleEndian.PutUint64(blob[off:off+8], 1<<62)
		_, err := f.recoveryOnly().Decrypt(blob)
		require.ErrorIs(t, err, ErrHybridV4Malformed)
	})

	t.Run("v2 ciphertext length", func(t *testing.T) {
		blob := encryptCompat(t, f, compatV2)
		encKeyLen := int(binary.LittleEndian.Uint16(blob[1:3]))
		// version(1) + key length(2) + encrypted key + IV(16) → ciphertext length field
		off := 3 + encKeyLen + 16
		binary.LittleEndian.PutUint64(blob[off:off+8], 1<<62)
		_, err := f.rsaOnly().Decrypt(blob)
		require.ErrorIs(t, err, ErrDecrypterPrematureEnd)
	})

	t.Run("v1 plaintext length overflow", func(t *testing.T) {
		blob := encryptCompat(t, f, compatV1)
		encKeyLen := int(binary.LittleEndian.Uint16(blob[1:3]))
		// version(1) + key length(2) + encrypted key → plaintext length field; 2^64-1 overflows
		// the block-size round-up and panicked the tail slicing before the bound check
		off := 3 + encKeyLen
		binary.LittleEndian.PutUint64(blob[off:off+8], ^uint64(0))
		_, err := f.rsaOnly().Decrypt(blob)
		require.ErrorIs(t, err, ErrDecrypterPrematureEnd)
	})
}

// TestHybridV4_UnknownSlotsAreSkipped: a v4 record may carry slots this decrypter cannot use —
// a future recipient/algorithm it doesn't know, or a matching slot whose bytes are garbled.
// Both must be skipped and the record must still open through the slot the keychain matches.
func TestHybridV4_UnknownSlotsAreSkipped(t *testing.T) {
	f := newCompatFixtures(t)
	dataKey, err := GenerateRandomBytes(hybridV4DataKeyLen)
	require.NoError(t, err)
	payloadIV, err := GenerateRandomBytes(hybridV4PayloadIVLen)
	require.NoError(t, err)
	recoveryBlob, err := aesSymWrap(f.recoveryKey, dataKey)
	require.NoError(t, err)
	payload, err := gcmSeal(dataKey, payloadIV, f.plaintext)
	require.NoError(t, err)

	blob, err := encodeHybridV4([]v4Slot{
		{decrypterID: 250, keyAlg: 250, blob: []byte("slot of a future recipient")},
		{decrypterID: DecrypterDataReceiver, keyAlg: HybridV4KeyAlgRSAOAEP, blob: bytes.Repeat([]byte{0x11}, 256)},
		{decrypterID: DecrypterMobileApp, keyAlg: HybridV4KeyAlgAESSym, blob: recoveryBlob},
	}, payloadIV, payload)
	require.NoError(t, err)

	// The recovery-key holder skips the unknown and RSA slots and opens its own.
	got, err := f.recoveryOnly().Decrypt(blob)
	require.NoError(t, err)
	require.Equal(t, f.plaintext, got)

	// A matching-but-garbled slot (the fake RSA one) must not block the working AES slot.
	got, err = f.rsaAndRecovery().Decrypt(blob)
	require.NoError(t, err)
	require.Equal(t, f.plaintext, got)

	// Whoever matches only the garbled slot gets a clean error.
	_, err = f.rsaOnly().Decrypt(blob)
	require.ErrorIs(t, err, ErrHybridV4NoSlot)
}

// TestHybridV4_ZeroSlotRecordFailsCleanly: a structurally valid record that offers no slots
// at all cannot be opened by anyone.
func TestHybridV4_ZeroSlotRecordFailsCleanly(t *testing.T) {
	f := newCompatFixtures(t)
	dataKey, err := GenerateRandomBytes(hybridV4DataKeyLen)
	require.NoError(t, err)
	payloadIV, err := GenerateRandomBytes(hybridV4PayloadIVLen)
	require.NoError(t, err)
	payload, err := gcmSeal(dataKey, payloadIV, f.plaintext)
	require.NoError(t, err)

	blob := []byte{HybridEncryptionV4, hybridV4PayloadAlgAESGCM, 0}
	blob = append(blob, payloadIV...)
	var lenField [8]byte
	binary.LittleEndian.PutUint64(lenField[:], uint64(len(payload)))
	blob = append(blob, lenField[:]...)
	blob = append(blob, payload...)

	_, err = f.rsaAndRecovery().Decrypt(blob)
	require.ErrorIs(t, err, ErrHybridV4NoSlot)
}

// TestDecrypt_UnknownVersionsFailClosed: bytes that are neither v1–v3 nor v4 — including a
// hypothetical future v5 — are rejected up front with ErrDecrypterInvalidVersion.
func TestDecrypt_UnknownVersionsFailClosed(t *testing.T) {
	f := newCompatFixtures(t)
	blob := encryptCompat(t, f, compatV4Both)
	for _, version := range []byte{0x00, 0x05, 0x06, 0x2a, 0xff} {
		mutated := append([]byte(nil), blob...)
		mutated[0] = version
		_, err := f.rsaAndRecovery().Decrypt(mutated)
		require.ErrorIs(t, err, ErrDecrypterInvalidVersion, "version byte 0x%02x", version)
	}
}

// TestDecrypt_DegenerateInputs: nil, empty and header-only inputs err cleanly on every
// decrypter shape, including one built with nil keys or an empty keychain.
func TestDecrypt_DegenerateInputs(t *testing.T) {
	f := newCompatFixtures(t)
	decrypters := map[string]*Decrypter{
		"rsa":            f.rsaOnly(),
		"recovery":       f.recoveryOnly(),
		"nil-keys":       NewDecrypter(nil),
		"empty-keychain": NewDecrypterFromKeys(),
	}
	inputs := [][]byte{nil, {}, {0x01}, {0x02}, {0x03}, {0x04}, {0x04, 0x00}, {0x04, 0x00, 0x02}}
	for name, d := range decrypters {
		for _, in := range inputs {
			_, err := d.Decrypt(in)
			require.Errorf(t, err, "decrypter %q, input %v must fail", name, in)
		}
	}
}

// TestHybridV4_PlaintextExtremes: empty and megabyte-sized payloads round-trip.
func TestHybridV4_PlaintextExtremes(t *testing.T) {
	f := newCompatFixtures(t)

	empty, err := EncryptHybridV4(nil, AESSlot(DecrypterMobileApp, f.recoveryKey))
	require.NoError(t, err)
	got, err := f.recoveryOnly().Decrypt(empty)
	require.NoError(t, err)
	require.Empty(t, got)

	big := make([]byte, 1<<20)
	_, err = rand.Read(big)
	require.NoError(t, err)
	blob, err := EncryptHybridV4(big, ECSlot(DecrypterMobileApp, f.ecPub))
	require.NoError(t, err)
	got, err = f.ecPhone().Decrypt(blob)
	require.NoError(t, err)
	require.True(t, bytes.Equal(big, got), "1 MiB payload must round-trip byte-for-byte")
}

// TestHybridV4_RotatedRecoveryKeySlots: the same recipient identity may appear in several
// slots (e.g. a rotated recovery key); a holder of either key opens the record — a slot that
// fails to open with the held key falls through to the next one — and a stranger cannot.
func TestHybridV4_RotatedRecoveryKeySlots(t *testing.T) {
	f := newCompatFixtures(t)
	keyA := bytes.Repeat([]byte{0x0a}, 32)
	keyB := bytes.Repeat([]byte{0x0b}, 32)
	blob, err := EncryptHybridV4(f.plaintext,
		AESSlot(DecrypterMobileApp, keyA),
		AESSlot(DecrypterMobileApp, keyB))
	require.NoError(t, err)

	for _, key := range [][]byte{keyA, keyB} {
		got, err := NewDecrypterWithRecoveryKey(NewPrivateKeys(), key).Decrypt(blob)
		require.NoError(t, err)
		require.Equal(t, f.plaintext, got)
	}
	_, err = NewDecrypterWithRecoveryKey(NewPrivateKeys(), bytes.Repeat([]byte{0x0c}, 32)).Decrypt(blob)
	require.ErrorIs(t, err, ErrHybridV4NoSlot)
}

// TestDecryptAndUnmarshal_V4: the JSON convenience entry point services use handles v4
// records like any other version.
func TestDecryptAndUnmarshal_V4(t *testing.T) {
	f := newCompatFixtures(t)
	blob, err := EncryptHybridV4([]byte(`{"steps":7}`), AESSlot(DecrypterMobileApp, f.recoveryKey))
	require.NoError(t, err)

	var doc struct {
		Steps int `json:"steps"`
	}
	require.NoError(t, f.recoveryOnly().DecryptAndUnmarshal(blob, &doc))
	require.Equal(t, 7, doc.Steps)
}
