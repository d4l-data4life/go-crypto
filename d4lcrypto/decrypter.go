package d4lcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

// define errors
var (
	ErrDecrypterJSONUnmarshal    = errors.New("error decoding JSON")
	ErrDecrypterDecode           = errors.New("error decoding Base64")
	ErrDecrypterDecryption       = errors.New("error decrypting message")
	ErrDecrypterInvalidVersion   = errors.New("unsupported version for hybrid encryption")
	ErrDecrypterInvalidBlockSize = errors.New("unsupported block size for hybrid encryption")
	ErrDecrypterPrematureEnd     = errors.New("unexpected end of hybrid encryption stream")
	ErrDecryption                = rsa.ErrDecryption
)

// KeySlot is one entry of a Decrypter's keychain: the recipient identity and algorithm of the
// slots it can open, plus the key material. Build it with RSAKey, ECKey or AESKey. An asymmetric
// entry holds a set of keys (a rotated key set) and every one is tried, so old payloads keep
// decrypting after a rotation.
type KeySlot struct {
	decrypterID uint8
	keyAlg      uint8
	keys        *PrivateKeys // asymmetric key material (RSA-OAEP or EC), a rotated set
	symKey      []byte       // symmetric key material (AES)
}

// keySlice returns the entry's asymmetric keys, tolerating a nil slice pointer.
func (k *KeySlot) keySlice() PrivateKeys {
	if k.keys == nil {
		return nil
	}
	return *k.keys
}

// RSAKey builds a keychain entry that opens RSA-OAEP slots addressed to decrypterID.
func RSAKey(decrypterID uint8, privateKey *PrivateKey) KeySlot {
	return KeySlot{decrypterID: decrypterID, keyAlg: HybridV4KeyAlgRSAOAEP, keys: &PrivateKeys{*privateKey}}
}

// ECKey builds a keychain entry that opens EC (secp256k1) slots addressed to decrypterID.
func ECKey(decrypterID uint8, privateKey *PrivateKey) KeySlot {
	return KeySlot{decrypterID: decrypterID, keyAlg: HybridV4KeyAlgEC, keys: &PrivateKeys{*privateKey}}
}

// AESKey builds a keychain entry that opens AES-symmetric slots addressed to decrypterID.
func AESKey(decrypterID uint8, symKey []byte) KeySlot {
	return KeySlot{decrypterID: decrypterID, keyAlg: HybridV4KeyAlgAESSym, symKey: symKey}
}

// NewDecrypterFromKeys creates a Decrypter from an explicit keychain — e.g. several recovery
// keys, EC entries, or custom decrypter ids. Build entries with RSAKey, ECKey or AESKey.
func NewDecrypterFromKeys(keys ...KeySlot) *Decrypter {
	return &Decrypter{keychain: keys}
}

// Decrypter decrypts hybrid ciphertexts using a keychain of keys. Each key is tagged with the
// recipient identity and algorithm of the slot it opens; a v4 slot is matched on its
// (decrypterID, keyAlg) and every matching key is tried, so rotated keys keep decrypting.
type Decrypter struct {
	keychain []KeySlot
}

// receiverRSASlot is the keychain entry every backend Decrypter holds: the data-receiver's
// RSA-OAEP keys (a rotated set), which open both v4 DataReceiver slots and v1-3 targets.
func receiverRSASlot(privateKeys *PrivateKeys) KeySlot {
	return KeySlot{decrypterID: DecrypterDataReceiver, keyAlg: HybridV4KeyAlgRSAOAEP, keys: privateKeys}
}

// NewDecrypter creates a new Decrypter instance for the given RSA private key in PEM format
func NewDecrypter(privateKeys *PrivateKeys) *Decrypter {
	return &Decrypter{keychain: []KeySlot{receiverRSASlot(privateKeys)}}
}

// NewDecrypterWithRecoveryKey creates a new Decrypter instance for the given RSA private key in PEM format and recovery key as byte slice
func NewDecrypterWithRecoveryKey(privateKeys *PrivateKeys, recoveryKey []byte) *Decrypter {
	keychain := []KeySlot{receiverRSASlot(privateKeys)}
	if len(recoveryKey) > 0 {
		keychain = append(keychain, AESKey(DecrypterMobileApp, recoveryKey))
	}
	return &Decrypter{keychain: keychain}
}

// rsaUnwrap decrypts a data key wrapped with RSA-OAEP/SHA-256 using pk.
func rsaUnwrap(pk PrivateKey, ciphertext, label []byte) ([]byte, error) {
	rsaPk, ok := pk.key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPk, ciphertext, label)
}

// decrypt decrypts the message by trying every RSA-OAEP key in the keychain.
func (d *Decrypter) decrypt(ciphertext []byte, label []byte) ([]byte, error) {
	for i := range d.keychain {
		k := &d.keychain[i]
		if k.keyAlg != HybridV4KeyAlgRSAOAEP {
			continue
		}
		for _, pk := range k.keySlice() {
			if plaintext, err := rsaUnwrap(pk, ciphertext, label); err == nil {
				return plaintext, nil
			}
		}
	}
	return nil, ErrDecrypterDecryption
}

// legacyRecoveryKey returns the symmetric recovery key from the keychain (v1-3 use a single
// AES-CBC recovery key); nil when none is configured.
func (d *Decrypter) legacyRecoveryKey() []byte {
	for i := range d.keychain {
		k := &d.keychain[i]
		if k.decrypterID == DecrypterMobileApp && k.keyAlg == HybridV4KeyAlgAESSym {
			return k.symKey
		}
	}
	return nil
}

// decryptWithRecoveryKey decrypts the message by using AES-CBC with the keychain recovery key
func (d *Decrypter) decryptWithRecoveryKey(iv []byte, ciphertext []byte) ([]byte, error) {
	// The length is untrusted wire data: CBC needs whole blocks (CryptBlocks panics otherwise).
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrDecrypterInvalidBlockSize
	}

	// Create AES block cipher
	aesCipher, err := aes.NewCipher(d.legacyRecoveryKey())
	if err != nil {
		return nil, errors.Wrap(err, "recovery key is invalid")
	}

	// Create CBC mode decrypter
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(aesCipher, iv).CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// readAndCheckVersion reads version from buffer and checks whether it is set to 'HybridEncryptionAESWithCBC' (part of Decrypt)
func readAndCheckVersion(buf io.ByteReader) (byte, error) {
	version, err := buf.ReadByte()
	if err != nil {
		return 0, errors.Wrap(err, "couldn't read version")
	}
	if version != HybridEncryptionAESWithCBC && version != HybridEncryptionAESWithGCM && version != HybridEncryptionAESWithGCMWithRecovery {
		return 0, ErrDecrypterInvalidVersion
	}
	return version, nil
}

// readEncKey reads encrypted key from buffer (part of Decrypt)
func readEncKey(buf io.Reader) ([]byte, error) {
	var encryptedKeyLen uint16
	if err := binary.Read(buf, binary.LittleEndian, &encryptedKeyLen); err != nil {
		return nil, errors.Wrap(err, "couldn't read encrypted key length")
	}

	encryptedKey := make([]byte, encryptedKeyLen)
	n, err := buf.Read(encryptedKey)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't read encryped data key")
	}
	if n < int(encryptedKeyLen) {
		return nil, ErrDecrypterPrematureEnd
	}
	return encryptedKey, nil
}

// readIV reads initialisation vector from buffer (part of Decrypt)
func readIV(buf io.Reader) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	n, err := buf.Read(iv)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't read initialisation vector")
	}
	if n < aes.BlockSize {
		return nil, ErrDecrypterPrematureEnd
	}
	return iv, err
}

// readCiphertext reads ciphertext from buffer (part of Decrypt). The length is untrusted
// wire data, so it is bounded by the bytes actually present before allocating.
func readCiphertext(buf *bytes.Buffer, ciphertextLen uint64) ([]byte, error) {
	if ciphertextLen > uint64(buf.Len()) { // nolint: gosec // buf.Len() is a non-negative int
		return nil, ErrDecrypterPrematureEnd
	}
	ciphertext := make([]byte, ciphertextLen)
	n, err := buf.Read(ciphertext)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't read ciphertext")
	}
	// nolint: gosec
	if uint64(n) < ciphertextLen {
		return nil, ErrDecrypterPrematureEnd
	}
	return ciphertext, err
}

func readEncKeyForRecovery(buf *bytes.Buffer) (iv []byte, encKeyDon []byte, err error) {
	// Read IV
	if iv, err = readIV(buf); err != nil {
		return nil, nil, err
	}

	// Read encKeyLen_don
	var encKeyLenDon uint8
	if err = binary.Read(buf, binary.LittleEndian, &encKeyLenDon); err != nil {
		return nil, nil, errors.Wrap(err, "couldn't read length of donor-encrypted data key")
	}

	// Read encKey_don
	encKeyDon, err = readCiphertext(buf, uint64(encKeyLenDon))
	if err != nil {
		return nil, nil, err
	}
	return iv, encKeyDon, nil
}

func readAndDecryptCiphertextCBC(buf *bytes.Buffer, key []byte) ([]byte, error) {
	// 4. Plaintext length
	var plaintextLen uint64
	if err := binary.Read(buf, binary.LittleEndian, &plaintextLen); err != nil {
		return nil, errors.Wrap(err, "couldn't read plaintext length")
	}
	// plaintextLen is untrusted wire data: bound it by the bytes actually present before
	// deriving the block-aligned ciphertext length (also rules out overflow in the round-up).
	if plaintextLen > uint64(buf.Len()) { // nolint: gosec // buf.Len() is a non-negative int
		return nil, ErrDecrypterPrematureEnd
	}

	// 5. Initialisation vector
	iv, err := readIV(buf)
	if err != nil {
		return nil, err
	}

	// 6. Ciphertext
	ciphertextLen := ((plaintextLen + aes.BlockSize - 1) / aes.BlockSize) * aes.BlockSize
	ciphertext, err := readCiphertext(buf, ciphertextLen)
	if err != nil {
		return nil, err
	}

	// Create AES block cipher
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "data key is invalid")
	}

	// Create CBC mode decrypter
	// len(ciphertext) == len(padded(plaintext))
	// len(ciphertext) >= len(plaintext)
	plaintext := make([]byte, ciphertextLen)
	cipher.NewCBCDecrypter(aesCipher, iv).CryptBlocks(plaintext, ciphertext)

	return plaintext[:plaintextLen], nil
}

func readAndDecryptCiphertextGCM(buf *bytes.Buffer, key []byte) ([]byte, error) {
	// 4. Initialisation vector
	iv, err := readIV(buf)
	if err != nil {
		return nil, err
	}

	// 5. Ciphertext length
	var ciphertextLen uint64
	if err = binary.Read(buf, binary.LittleEndian, &ciphertextLen); err != nil {
		return nil, errors.Wrap(err, "couldn't read ciphertext length")
	}

	// 6. Ciphertext
	ciphertext, err := readCiphertext(buf, ciphertextLen)
	if err != nil {
		return nil, err
	}

	// Create AES block cipher
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "data key is invalid")
	}
	// Create GCM mode encrypter
	aesgcm, err := cipher.NewGCMWithNonceSize(aesCipher, aes.BlockSize)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create AES GCM cipher")
	}
	// Decrypt
	plaintext, err := aesgcm.Open(ciphertext[:0], iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: couldn't decrypt with AES GCM: %w", ErrDecrypterDecryption, err)
	}
	return plaintext, nil
}

// Decrypt decrypts messages that are longer than the asymmetric key length by
// decrypting a symmetric key asymmetrically and decrypting the actual message symmetrically
func (d *Decrypter) Decrypt(hybridCiphertext []byte) ([]byte, error) {
	// v4 is a generic slot-based format; route it before the v1-3 version gate.
	if len(hybridCiphertext) > 0 && hybridCiphertext[0] == HybridEncryptionV4 {
		return d.decryptHybridV4(hybridCiphertext)
	}
	return d.decryptLegacy(hybridCiphertext)
}

//nolint:gocyclo
func (d *Decrypter) decryptLegacy(hybridCiphertext []byte) ([]byte, error) {
	buf := bytes.NewBuffer(hybridCiphertext)

	// 1. Version
	version, err := readAndCheckVersion(buf)
	if err != nil {
		return nil, err
	}

	var key []byte
	if version == HybridEncryptionAESWithGCMWithRecovery {
		iv, encKeyDon, err := readEncKeyForRecovery(buf)
		if err != nil {
			return nil, err
		}

		if len(d.legacyRecoveryKey()) > 0 {
			if key, err = d.decryptWithRecoveryKey(iv, encKeyDon); err != nil {
				return nil, errors.Wrap(err, "couldn't decrypt data key with recovery key")
			}
		}
	}

	// 2 and 3 (or 5 and 6) Length and encrypted symmetric key
	encryptedKey, err := readEncKey(buf)
	if err != nil {
		return nil, err
	}

	if key == nil {
		key, err = d.decrypt(encryptedKey, nil)
		if err != nil {
			return nil, errors.Wrap(err, "couldn't decrypt data key")
		}
	}

	switch version {
	case HybridEncryptionAESWithCBC:
		return readAndDecryptCiphertextCBC(buf, key)

	case HybridEncryptionAESWithGCM, HybridEncryptionAESWithGCMWithRecovery:
		return readAndDecryptCiphertextGCM(buf, key)

	default:
		return nil, ErrDecrypterInvalidVersion
	}
}

// decryptHybridV4 decrypts a v4 record by matching each slot against the keychain: a key opens
// a slot only when their (decrypterID, keyAlg) agree, and every matching key is tried (so a
// rotated key set still decrypts older payloads). v1-3 decryption is untouched.
func (d *Decrypter) decryptHybridV4(ciphertext []byte) ([]byte, error) {
	slots, payloadIV, payload, err := decodeHybridV4(ciphertext)
	if err != nil {
		return nil, err
	}
	dataKey, err := d.unwrapV4DataKey(slots)
	if err != nil {
		return nil, err
	}
	return gcmOpen(dataKey, payloadIV, payload)
}

// unwrapV4DataKey returns the data key from the first slot the keychain can open.
func (d *Decrypter) unwrapV4DataKey(slots []v4Slot) ([]byte, error) {
	for _, slot := range slots {
		if dataKey, ok := d.unwrapSlot(slot); ok {
			return dataKey, nil
		}
	}
	return nil, ErrHybridV4NoSlot
}

// unwrapSlot tries every keychain key whose (decrypterID, keyAlg) match the slot's — so a slot
// addressed to another recipient is refused, and a rotated key set is fully tried.
func (d *Decrypter) unwrapSlot(slot v4Slot) ([]byte, bool) {
	for i := range d.keychain {
		k := &d.keychain[i]
		if k.decrypterID != slot.decrypterID || k.keyAlg != slot.keyAlg {
			continue
		}
		if dataKey, ok := k.unwrapV4Slot(slot.blob); ok {
			return dataKey, true
		}
	}
	return nil, false
}

// unwrapV4Slot opens a v4 slot blob with this keychain entry, dispatching on its alg and trying
// every key in the entry (a rotated set) for the asymmetric algorithms.
func (k *KeySlot) unwrapV4Slot(blob []byte) ([]byte, bool) {
	switch k.keyAlg {
	case HybridV4KeyAlgRSAOAEP:
		return k.unwrapV4RSA(blob)
	case HybridV4KeyAlgAESSym:
		dataKey, err := aesSymUnwrap(k.symKey, blob)
		return dataKey, err == nil
	case HybridV4KeyAlgEC:
		return k.unwrapV4EC(blob)
	default:
		return nil, false
	}
}

// unwrapV4RSA tries each RSA-OAEP key in the entry against an RSA slot blob.
func (k *KeySlot) unwrapV4RSA(blob []byte) ([]byte, bool) {
	for _, pk := range k.keySlice() {
		if dataKey, err := rsaUnwrap(pk, blob, nil); err == nil {
			return dataKey, true
		}
	}
	return nil, false
}

// unwrapV4EC tries each secp256k1 key in the entry against an EC (ECIES) slot blob.
func (k *KeySlot) unwrapV4EC(blob []byte) ([]byte, bool) {
	for _, pk := range k.keySlice() {
		ecPriv, ok := pk.key.(*ecdsa.PrivateKey)
		if !ok {
			continue
		}
		if dataKey, err := ecdhUnwrapDataKey(ecPriv, blob); err == nil {
			return dataKey, true
		}
	}
	return nil, false
}

// DecryptAndUnmarshal decrypts a base64-decoded cyphertext and JSON-decodes into object
func (d *Decrypter) DecryptAndUnmarshal(ciphertext []byte, object interface{}) error {
	plaintext, err := d.Decrypt(ciphertext)
	if err != nil {
		return ErrDecrypterDecryption
	}

	err = json.Unmarshal(plaintext, object)
	if err != nil {
		return ErrDecrypterJSONUnmarshal
	}

	return nil
}
