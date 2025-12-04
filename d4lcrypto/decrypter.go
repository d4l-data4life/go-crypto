package d4lcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

// Decrypter to decrypt messages with a configured RSA private key
type Decrypter struct {
	privateKeys *PrivateKeys // must be a pointer to a slice here, as the key slice might be resized
	recoveryKey []byte       // optional recovery key
}

// NewDecrypter creates a new Decrypter instance for the given RSA private key in PEM format
func NewDecrypter(privateKeys *PrivateKeys) *Decrypter {
	return &Decrypter{
		privateKeys: privateKeys,
	}
}

// NewDecrypterWithRecoveryKey creates a new Decrypter instance for the given RSA private key in PEM format and recovery key as byte slice
func NewDecrypterWithRecoveryKey(privateKeys *PrivateKeys, recoveryKey []byte) *Decrypter {
	return &Decrypter{
		privateKeys: privateKeys,
		recoveryKey: recoveryKey,
	}
}

// decrypt decrypts the message by using RSA-OAEP
func (d *Decrypter) decrypt(ciphertext []byte, label []byte) ([]byte, error) {
	for _, private := range *d.privateKeys {
		rsaPk, ok := private.key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedKey
		}
		plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPk, ciphertext, label)

		if err == nil {
			return plaintext, nil
		}
	}
	return nil, ErrDecrypterDecryption
}

// decryptWithRecoveryKey decrypts the message by using AES-CBC
func (d *Decrypter) decryptWithRecoveryKey(iv []byte, ciphertext []byte) ([]byte, error) {
	// Create AES block cipher
	aesCipher, err := aes.NewCipher(d.recoveryKey)
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

// readCiphertext reads ciphertext from buffer (part of Decrypt)
func readCiphertext(buf io.Reader, ciphertextLen uint64) ([]byte, error) {
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

func readEncKeyForRecovery(buf io.Reader) (iv []byte, encKeyDon []byte, err error) {
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

func readAndDecryptCiphertextCBC(buf io.Reader, key []byte) ([]byte, error) {
	// 4. Plaintext length
	var plaintextLen uint64
	if err := binary.Read(buf, binary.LittleEndian, &plaintextLen); err != nil {
		return nil, errors.Wrap(err, "couldn't read plaintext length")
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

func readAndDecryptCiphertextGCM(buf io.Reader, key []byte) ([]byte, error) {
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
//
//nolint:gocyclo
func (d *Decrypter) Decrypt(hybridCiphertext []byte) ([]byte, error) {
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

		if len(d.recoveryKey) > 0 {
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
