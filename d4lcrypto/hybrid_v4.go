package d4lcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

// Hybrid encryption format version 4 (generic, slot-based).
//
// Unlike v1-v3 (which hard-code a recovery branch + a single asymmetric target),
// v4 wraps the random per-payload data key once per recipient "slot", each tagged
// with a decrypter id and a key-wrap algorithm, followed by the AES-256-GCM payload:
//
//	version(1)=0x04 | payloadAlg(1)=0x00 | slotCount(1)
//	  repeat: decrypterId(1) | keyAlg(1) | slotLen(uint16 LE) | slot(slotLen)
//	payloadIv(12) | payloadLen(uint64 LE) | payload(ciphertext||tag)
//
// The EC slot wraps the data key to a phone-held secp256k1 key via ECIES
// (ephemeral ECDH -> HKDF-SHA256 -> AES-256-GCM):
//
//	slot = ephPubUncompressed(65) | nonce(12) | wrappedDataKey||tag(48)
//
// This is the format the collector uses to ship Garmin payloads only the phone can read.
const HybridEncryptionV4 = 0x04

const hybridV4PayloadAlgAESGCM = 0x00

// Decrypter ids (recipient registry — extensible without a new version byte).
const (
	DecrypterMobileApp    uint8 = 0
	DecrypterDataReceiver uint8 = 1
)

// Key-wrap algorithms.
const (
	HybridV4KeyAlgAESSym  uint8 = 0 // AES symmetric (e.g. recovery key)
	HybridV4KeyAlgRSAOAEP uint8 = 1 // RSA-OAEP / SHA-256
	HybridV4KeyAlgEC      uint8 = 2 // ECIES secp256k1
)

const (
	hybridV4DataKeyLen      = 32
	hybridV4PayloadIVLen    = 12
	hybridV4ECNonceLen      = 12
	hybridV4UncompressedLen = 65
	hybridV4GCMTagLen       = 16
	hybridV4SymNonceLen     = 12
)

// hybridV4ECSalt and hybridV4ECInfo bind the HKDF output to this scheme; they MUST be
// byte-identical to the phone-side implementation.
var (
	hybridV4ECSalt = []byte("d4l/hybrid-v4/ec/salt")
	hybridV4ECInfo = []byte("d4l/hybrid-v4/ec/secp256k1/aes256gcm")
)

var (
	ErrHybridV4Malformed = errors.New("malformed v4 hybrid ciphertext")
	ErrHybridV4Version   = errors.New("not a v4 hybrid ciphertext")
	ErrHybridV4NoSlot    = errors.New("no matching slot for the given decrypter id")
	ErrHybridV4KeyType   = errors.New("key is not a secp256k1 EC key")
)

type v4Slot struct {
	decrypterID uint8
	keyAlg      uint8
	blob        []byte
}

// v4Randomness holds the per-message random values; injectable for deterministic tests.
type v4Randomness struct {
	dataKey   []byte // 32
	ephPriv   []byte // 32 (secp256k1 scalar)
	ecNonce   []byte // 12
	payloadIV []byte // 12
}

// newECEphemeral generates a fresh ephemeral secp256k1 scalar and a GCM nonce for an EC slot.
func newECEphemeral() (ephPriv, nonce []byte, err error) {
	eph, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't generate ephemeral key")
	}
	nonce, err = GenerateRandomBytes(hybridV4ECNonceLen)
	if err != nil {
		return nil, nil, err
	}
	return leftPad32(eph.D.Bytes()), nonce, nil
}

// SlotSpec describes one recipient of a v4 record: which decrypter it is for, the wrap
// algorithm, and the key material to wrap the data key with. Build it with ECSlot, RSASlot
// or AESSlot. DecrypterID values are opaque to this package; callers assign their meaning.
type SlotSpec struct {
	decrypterID uint8
	keyAlg      uint8
	pub         *PublicKey
	symKey      []byte
}

// ECSlot wraps the data key to a secp256k1 public key via ECIES.
func ECSlot(decrypterID uint8, publicKey *PublicKey) SlotSpec {
	return SlotSpec{decrypterID: decrypterID, keyAlg: HybridV4KeyAlgEC, pub: publicKey}
}

// RSASlot wraps the data key to an RSA public key via RSA-OAEP (SHA-256).
func RSASlot(decrypterID uint8, publicKey *PublicKey) SlotSpec {
	return SlotSpec{decrypterID: decrypterID, keyAlg: HybridV4KeyAlgRSAOAEP, pub: publicKey}
}

// AESSlot wraps the data key under a symmetric key (e.g. a recovery key) via AES-256-GCM.
func AESSlot(decrypterID uint8, symKey []byte) SlotSpec {
	return SlotSpec{decrypterID: decrypterID, keyAlg: HybridV4KeyAlgAESSym, symKey: symKey}
}

// EncryptHybridV4 encrypts plaintext once under a random data key and wraps that key into one
// slot per recipient, so each can independently recover it and decrypt the shared payload.
func EncryptHybridV4(plaintext []byte, slots ...SlotSpec) ([]byte, error) {
	if len(slots) == 0 {
		return nil, ErrHybridV4Malformed
	}
	dataKey, err := GenerateRandomBytes(hybridV4DataKeyLen)
	if err != nil {
		return nil, err
	}
	payloadIV, err := GenerateRandomBytes(hybridV4PayloadIVLen)
	if err != nil {
		return nil, err
	}
	wrapped := make([]v4Slot, 0, len(slots))
	for _, s := range slots {
		blob, err := wrapV4Slot(s, dataKey)
		if err != nil {
			return nil, err
		}
		wrapped = append(wrapped, v4Slot{decrypterID: s.decrypterID, keyAlg: s.keyAlg, blob: blob})
	}
	return assembleHybridV4(dataKey, payloadIV, plaintext, wrapped)
}

// wrapV4Slot wraps dataKey for one recipient, dispatching on the slot's key algorithm and
// reusing the existing per-algorithm primitives.
func wrapV4Slot(s SlotSpec, dataKey []byte) ([]byte, error) {
	switch s.keyAlg {
	case HybridV4KeyAlgEC:
		return ecWrapV4(s.pub, dataKey)
	case HybridV4KeyAlgRSAOAEP:
		if s.pub == nil {
			return nil, ErrHybridV4KeyType
		}
		return encryptDataKey(dataKey, s.pub)
	case HybridV4KeyAlgAESSym:
		return aesSymWrap(s.symKey, dataKey)
	default:
		return nil, ErrHybridV4Malformed
	}
}

// ecWrapV4 wraps dataKey to a secp256k1 public key with a fresh ephemeral key and nonce.
func ecWrapV4(publicKey *PublicKey, dataKey []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrHybridV4KeyType
	}
	ecPub, ok := publicKey.key.(*ecdsa.PublicKey)
	if !ok || !isSecp256k1(ecPub.Curve) {
		return nil, ErrHybridV4KeyType
	}
	ephPriv, nonce, err := newECEphemeral()
	if err != nil {
		return nil, err
	}
	return ecdhWrapDataKey(ecPub, dataKey, ephPriv, nonce)
}

// aesSymWrap wraps dataKey under a symmetric key with AES-256-GCM. Layout: nonce(12) | ct‖tag.
func aesSymWrap(symKey, dataKey []byte) ([]byte, error) {
	nonce, err := GenerateRandomBytes(hybridV4SymNonceLen)
	if err != nil {
		return nil, err
	}
	wrapped, err := gcmSeal(symKey, nonce, dataKey)
	if err != nil {
		return nil, err
	}
	return append(nonce, wrapped...), nil
}

// aesSymUnwrap reverses aesSymWrap.
func aesSymUnwrap(symKey, blob []byte) ([]byte, error) {
	if len(blob) < hybridV4SymNonceLen {
		return nil, ErrHybridV4Malformed
	}
	return gcmOpen(symKey, blob[:hybridV4SymNonceLen], blob[hybridV4SymNonceLen:])
}

// assembleHybridV4 seals plaintext under dataKey and encodes it with the pre-wrapped slots;
// the shared tail of every v4 encryptor.
func assembleHybridV4(dataKey, payloadIV, plaintext []byte, slots []v4Slot) ([]byte, error) {
	payload, err := gcmSeal(dataKey, payloadIV, plaintext)
	if err != nil {
		return nil, err
	}
	return encodeHybridV4(slots, payloadIV, payload)
}

// encryptHybridV4ForEC builds a single-EC-slot record with caller-supplied randomness; used
// only for the deterministic vector test.
func encryptHybridV4ForEC(plaintext []byte, decrypterID uint8, phonePublicKey *PublicKey, r v4Randomness) ([]byte, error) {
	ecPub, ok := phonePublicKey.key.(*ecdsa.PublicKey)
	if !ok || !isSecp256k1(ecPub.Curve) {
		return nil, ErrHybridV4KeyType
	}
	slotBlob, err := ecdhWrapDataKey(ecPub, r.dataKey, r.ephPriv, r.ecNonce)
	if err != nil {
		return nil, err
	}
	slot := v4Slot{decrypterID: decrypterID, keyAlg: HybridV4KeyAlgEC, blob: slotBlob}
	return assembleHybridV4(r.dataKey, r.payloadIV, plaintext, []v4Slot{slot})
}

// ecdhWrapDataKey wraps dataKey to phonePub via ECIES (ephemeral ECDH -> HKDF -> AES-GCM).
func ecdhWrapDataKey(phonePub *ecdsa.PublicKey, dataKey, ephPriv, nonce []byte) ([]byte, error) {
	curve := secp256k1.S256()
	ephX, ephY := curve.ScalarBaseMult(ephPriv)
	//nolint:staticcheck // elliptic.Marshal mirrors key.go; secp256k1 needs the generic encoding
	ephPubBytes := elliptic.Marshal(curve, ephX, ephY)

	sharedX, _ := curve.ScalarMult(phonePub.X, phonePub.Y, ephPriv)
	wrapKey, err := ecdhDeriveWrapKey(leftPad32(sharedX.Bytes()))
	if err != nil {
		return nil, err
	}

	wrapped, err := gcmSeal(wrapKey, nonce, dataKey)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(ephPubBytes)+len(nonce)+len(wrapped))
	out = append(out, ephPubBytes...)
	out = append(out, nonce...)
	out = append(out, wrapped...)
	return out, nil
}

func ecdhUnwrapDataKey(phonePriv *ecdsa.PrivateKey, blob []byte) ([]byte, error) {
	if len(blob) != hybridV4UncompressedLen+hybridV4ECNonceLen+hybridV4DataKeyLen+hybridV4GCMTagLen {
		return nil, ErrHybridV4Malformed
	}
	ephBytes := blob[:hybridV4UncompressedLen]
	nonce := blob[hybridV4UncompressedLen : hybridV4UncompressedLen+hybridV4ECNonceLen]
	wrapped := blob[hybridV4UncompressedLen+hybridV4ECNonceLen:]

	curve := secp256k1.S256()
	//nolint:staticcheck // elliptic.Unmarshal mirrors key.go for secp256k1
	ephX, ephY := elliptic.Unmarshal(curve, ephBytes)
	if ephX == nil {
		return nil, ErrHybridV4Malformed
	}
	sharedX, _ := curve.ScalarMult(ephX, ephY, phonePriv.D.Bytes())
	wrapKey, err := ecdhDeriveWrapKey(leftPad32(sharedX.Bytes()))
	if err != nil {
		return nil, err
	}
	return gcmOpen(wrapKey, nonce, wrapped)
}

// ecdhDeriveWrapKey derives the AES-256 key that wraps the data key in an EC slot from the
// ECDH shared secret, via HKDF-SHA256 with the fixed v4 salt and info.
func ecdhDeriveWrapKey(sharedSecret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, hybridV4ECSalt, hybridV4ECInfo)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, errors.Wrap(err, "hkdf failed")
	}
	return key, nil
}

// gcmSeal/gcmOpen use AES-256-GCM with the standard 12-byte nonce.
func gcmSeal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "invalid AES key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create AES GCM cipher")
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func gcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "invalid AES key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create AES GCM cipher")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(ErrDecrypterDecryption, err.Error())
	}
	return plaintext, nil
}

func encodeHybridV4(slots []v4Slot, payloadIV, payload []byte) ([]byte, error) {
	if len(slots) == 0 || len(slots) > 255 || len(payloadIV) != hybridV4PayloadIVLen {
		return nil, ErrHybridV4Malformed
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(HybridEncryptionV4)
	buf.WriteByte(hybridV4PayloadAlgAESGCM)
	buf.WriteByte(byte(len(slots))) // nolint: gosec // len(slots) <= 255 checked above
	for _, s := range slots {
		if len(s.blob) > 0xFFFF {
			return nil, ErrHybridV4Malformed
		}
		buf.WriteByte(s.decrypterID)
		buf.WriteByte(s.keyAlg)
		if err := binary.Write(buf, binary.LittleEndian, uint16(len(s.blob))); err != nil { // nolint: gosec // <= 0xFFFF checked above
			return nil, errors.Wrap(err, "couldn't write slot length")
		}
		buf.Write(s.blob)
	}
	buf.Write(payloadIV)
	if err := binary.Write(buf, binary.LittleEndian, uint64(len(payload))); err != nil {
		return nil, errors.Wrap(err, "couldn't write payload length")
	}
	buf.Write(payload)
	return buf.Bytes(), nil
}

func decodeHybridV4(in []byte) (slots []v4Slot, payloadIV, payload []byte, err error) {
	buf := bytes.NewReader(in)

	version, err := buf.ReadByte()
	if err != nil || version != HybridEncryptionV4 {
		return nil, nil, nil, ErrHybridV4Version
	}
	payloadAlg, err := buf.ReadByte()
	if err != nil || payloadAlg != hybridV4PayloadAlgAESGCM {
		return nil, nil, nil, ErrHybridV4Malformed
	}
	slotCount, err := buf.ReadByte()
	if err != nil {
		return nil, nil, nil, ErrHybridV4Malformed
	}

	slots, err = readV4Slots(buf, int(slotCount))
	if err != nil {
		return nil, nil, nil, err
	}

	payloadIV, payload, err = readV4Payload(buf)
	if err != nil {
		return nil, nil, nil, err
	}
	return slots, payloadIV, payload, nil
}

// readV4Slots reads slotCount recipient slots (decrypterID, keyAlg, uint16-len-prefixed blob).
func readV4Slots(buf *bytes.Reader, slotCount int) ([]v4Slot, error) {
	slots := make([]v4Slot, 0, slotCount)
	for i := 0; i < slotCount; i++ {
		decID, derr := buf.ReadByte()
		keyAlg, kerr := buf.ReadByte()
		if derr != nil || kerr != nil {
			return nil, ErrHybridV4Malformed
		}
		var blobLen uint16
		if err := binary.Read(buf, binary.LittleEndian, &blobLen); err != nil {
			return nil, ErrHybridV4Malformed
		}
		blob := make([]byte, blobLen)
		if _, err := io.ReadFull(buf, blob); err != nil {
			return nil, ErrHybridV4Malformed
		}
		slots = append(slots, v4Slot{decrypterID: decID, keyAlg: keyAlg, blob: blob})
	}
	return slots, nil
}

// readV4Payload reads the payload IV followed by the uint64-len-prefixed ciphertext payload.
func readV4Payload(buf *bytes.Reader) (payloadIV, payload []byte, err error) {
	payloadIV = make([]byte, hybridV4PayloadIVLen)
	if _, rerr := io.ReadFull(buf, payloadIV); rerr != nil {
		return nil, nil, ErrHybridV4Malformed
	}
	var payloadLen uint64
	if rerr := binary.Read(buf, binary.LittleEndian, &payloadLen); rerr != nil {
		return nil, nil, ErrHybridV4Malformed
	}
	// payloadLen is untrusted wire data: bound it by the bytes remaining before allocating.
	if payloadLen > uint64(buf.Len()) { // nolint: gosec // buf.Len() is a non-negative int
		return nil, nil, ErrHybridV4Malformed
	}
	payload = make([]byte, payloadLen)
	if _, rerr := io.ReadFull(buf, payload); rerr != nil {
		return nil, nil, ErrHybridV4Malformed
	}
	return payloadIV, payload, nil
}

func isSecp256k1(curve elliptic.Curve) bool {
	return curve != nil && *curve.Params() == *secp256k1.S256().Params()
}

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
