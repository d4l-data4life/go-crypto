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
	"io"

	"github.com/pkg/errors"
)

// define errors
var (
	ErrEncrypterInvalidVersion = errors.New("unsupported version for hybrid encryption")
	ErrEncrypterJSONMarshal    = errors.New("error encoding to JSON")
	ErrEncrypterEncryption     = errors.New("error encrypting message")
)

// define constants
const (
	HybridEncryptionAESWithCBC             = 0x01
	HybridEncryptionAESWithGCM             = 0x02
	HybridEncryptionAESWithGCMWithRecovery = 0x03
)

// Encrypter to encrypt messages with a configured RSA public key
type Encrypter struct {
	public      *PublicKey
	recoveryKey []byte
	version     byte
}

// NewEncrypter creates a new Encrypter instance for the given RSA public key in PEM format
func NewEncrypter(publicKey *PublicKey) *Encrypter {
	return &Encrypter{
		public:  publicKey,
		version: HybridEncryptionAESWithGCM,
	}
}

// NewEncrypterWithRecoveryKey creates a new Encrypter instance for the given RSA public key in PEM format and recovery key as byte slice
func NewEncrypterWithRecoveryKey(publicKey *PublicKey, recoveryKey []byte) *Encrypter {
	return &Encrypter{
		public:      publicKey,
		recoveryKey: recoveryKey,
		version:     HybridEncryptionAESWithGCMWithRecovery,
	}
}

// NewEncrypterWithVersion creates a new Encrypter given a specific format version (only used for testing)
func NewEncrypterWithVersion(publicKey *PublicKey, version byte) *Encrypter {
	return &Encrypter{
		public:  publicKey,
		version: version,
	}
}

// Version returns the format version that should be used for encryption
func (e *Encrypter) Version() byte {
	return e.version
}

// generateDataKey generates random data key
func generateDataKey() (key []byte, err error) {
	key, err = GenerateRandomBytes(32)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't generate data key")
	}
	return key, nil
}

// encryptDataKey encrypts the data key using RSA-OAEP
func encryptDataKey(dataKey []byte, publicKey *PublicKey) (encryptedKey []byte, err error) {
	rsaPk, ok := publicKey.key.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPk, dataKey, nil)

	if err != nil {
		return nil, errors.Wrap(ErrEncrypterEncryption, "couldn't encrypt data key")
	}
	return encryptedKey, nil
}

// encryptDataKeyForRecovery encrypts the data key using AES CBC and a random IV
func encryptDataKeyForRecovery(dataKey, recoveryKey []byte) (iv, encryptedKey []byte, err error) {
	// Generate random IV
	iv, err = GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't generate initialisation vector")
	}

	// Create AES block cipher
	aesCipher, err := aes.NewCipher(recoveryKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "data key is invalid")
	}

	// Create CBC mode encrypter
	encryptedKey = make([]byte, len(dataKey))
	cipher.NewCBCEncrypter(aesCipher, iv).CryptBlocks(encryptedKey, dataKey)
	return iv, encryptedKey, nil
}

// createCiphertext encrypts the plaintext using AES with CBC given a key and initialisation vector
func createCiphertextCBC(key, plaintext, iv []byte) ([]byte, error) {
	// Pad plaintext to a multiple of block size with random bytes
	plaintext, err := padPlainText(plaintext)
	if err != nil {
		return nil, err
	}
	// Create AES block cipher
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "data key is invalid")
	}
	// Create CBC mode encrypter
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(aesCipher, iv).CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// createCiphertext encrypts the plaintext using AES with GCM given a key and initialisation vector
func createCiphertextGCM(key, plaintext, iv []byte) ([]byte, error) {
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
	ciphertext := aesgcm.Seal([]byte{}, iv, plaintext, nil)

	return ciphertext, nil
}

// padPlainText pads the message so that the size fits into natural number of aes blocks
func padPlainText(plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		bytesToPad := aes.BlockSize - (len(plaintext) % aes.BlockSize)
		padding, err := GenerateRandomBytes(bytesToPad)
		if err != nil {
			return nil, errors.Wrap(err, "couldn't generate padding")
		}
		plaintext = append(plaintext, padding...)
	}
	return plaintext, nil
}

// encryptAndWriteKey encrypts the data key asymmetrically and writes it to the buffer
func encryptAndWriteKey(buf io.Writer, key []byte, public *PublicKey) error {
	encryptedKey, err := encryptDataKey(key, public)
	if err != nil {
		return err
	}

	// nolint: gosec
	if err := binary.Write(buf, binary.LittleEndian, uint16(len(encryptedKey))); err != nil {
		return errors.Wrap(err, "couldn't write encrypted key length to buffer")
	}

	// 3. Write encrypted symmetric key
	if _, err = buf.Write(encryptedKey); err != nil {
		return errors.Wrap(err, "couldn't write encrypted key to buffer")
	}
	return nil
}

// encryptAndWriteKeyForRecovery encrypts the data key symmetrically (AES CBC) and writes it to the buffer
func encryptAndWriteKeyForRecovery(buf io.Writer, key []byte, recoveryKey []byte) error {
	iv, encryptedKeyForRecovery, err := encryptDataKeyForRecovery(key, recoveryKey)
	if err != nil {
		return err
	}

	if _, err = buf.Write(iv); err != nil {
		return errors.Wrap(err, "couldn't write initialisation vector for recovery to buffer")
	}

	// nolint: gosec
	if err = binary.Write(buf, binary.LittleEndian, uint8(len(encryptedKeyForRecovery))); err != nil {
		return errors.Wrap(err, "couldn't write encrypted key length for recovery to buffer")
	}

	if _, err = buf.Write(encryptedKeyForRecovery); err != nil {
		return errors.Wrap(err, "couldn't write encrypted key for recovery to buffer")
	}
	return nil
}

func encryptAndWriteCiphertextCBC(buf io.Writer, key, plaintext []byte) error {
	// 4. Write plaintext length
	if err := binary.Write(buf, binary.LittleEndian, uint64(len(plaintext))); err != nil {
		return errors.Wrap(err, "couldn't write plaintext length to buffer")
	}

	// 5. Generate and write Initialisation Vector (IV)
	iv, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return errors.Wrap(err, "couldn't generate initialisation vector")
	}
	if _, err = buf.Write(iv); err != nil {
		return errors.Wrap(err, "couldn't write initialisation vector to buffer")
	}

	// 6. Create and write ciphertext
	ciphertext, err := createCiphertextCBC(key, plaintext, iv)
	if err != nil {
		return err
	}
	if _, err = buf.Write(ciphertext); err != nil {
		return errors.Wrap(err, "couldn't write ciphertext")
	}
	return nil
}

func encryptAndWriteCiphertextGCM(buf io.Writer, key, plaintext []byte) error {
	// 4. Generate and write Initialisation Vector (IV)
	iv, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return errors.Wrap(err, "couldn't generate initialisation vector")
	}
	if _, err = buf.Write(iv); err != nil {
		return errors.Wrap(err, "couldn't write initialisation vector to buffer")
	}

	// 5. Create ciphertext and write length
	ciphertext, err := createCiphertextGCM(key, plaintext, iv)
	if err != nil {
		return err
	}
	if err = binary.Write(buf, binary.LittleEndian, uint64(len(ciphertext))); err != nil {
		return errors.Wrap(err, "couldn't write ciphertext length to buffer")
	}

	// 6. Write ciphertext
	if _, err = buf.Write(ciphertext); err != nil {
		return errors.Wrap(err, "couldn't write ciphertext")
	}
	return nil
}

// Encrypt encrypts messages that are longer than the asymmetric key length by
// using a symmetric algorithm and encrypting the symmetric key asymmetrically.
// If a recovery key is provided, the symmetric key is also encrypted symmetrically
// for data recovery purposes.
func (e *Encrypter) Encrypt(plaintext []byte) ([]byte, error) {
	// buf collects all six parts that build a message
	buf := new(bytes.Buffer)

	// 1. Write version to buffer
	if err := buf.WriteByte(e.version); err != nil {
		return nil, errors.Wrap(err, "couldn't write version to buffer")
	}

	// 2. Generate random data key
	key, err := generateDataKey()
	if err != nil {
		return nil, err
	}

	// 3a. (Optional) Encrypt data key symmetrically using data recovery key
	if e.version == HybridEncryptionAESWithGCMWithRecovery {
		if err := encryptAndWriteKeyForRecovery(buf, key, e.recoveryKey); err != nil {
			return nil, err
		}
	}

	// 3b. Assymetrically encrypt data key and write length of it to buffer
	if err := encryptAndWriteKey(buf, key, e.public); err != nil {
		return nil, err
	}

	switch e.version {
	case HybridEncryptionAESWithCBC:
		if err = encryptAndWriteCiphertextCBC(buf, key, plaintext); err != nil {
			return nil, err
		}

	case HybridEncryptionAESWithGCM, HybridEncryptionAESWithGCMWithRecovery:
		if err = encryptAndWriteCiphertextGCM(buf, key, plaintext); err != nil {
			return nil, err
		}

	default:
		return nil, ErrEncrypterInvalidVersion
	}
	return buf.Bytes(), nil
}

// MarshalAndEncrypt encodes object as JSON, encrypts it
func (e *Encrypter) MarshalAndEncrypt(object interface{}) ([]byte, error) {
	jsonBytes, err := json.Marshal(object)
	if err != nil {
		return nil, ErrEncrypterJSONMarshal
	}

	ciphertext, err := e.Encrypt(jsonBytes)
	if err != nil {
		return nil, ErrEncrypterEncryption
	}
	return ciphertext, nil
}
