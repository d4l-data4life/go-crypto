package d4lcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"
)

// define errors
var (
	ErrPublicKeyDecodeBase64  = errors.New("failed to decode Base64 containing public key")
	ErrPublicKeyDecodePEM     = errors.New("failed to decode PEM block containing public key")
	ErrPublicKeyParse         = errors.New("failed to parse SPKI public key")
	ErrPrivateKeyDecodeBase64 = errors.New("failed to decode Base64 containing private key")
	ErrPrivateKeyDecodePEM    = errors.New("failed to decode PEM block containing private key")
	ErrPrivateKeyParse        = errors.New("failed to parse PKCS8 private key")
)

// Key is a generic key that can be read from a byte array or a file
type Key interface {
	Read(b []byte) error
	ReadFromFile(path string) error
}

// readFromFile reads a key from a file
func readFromFile(key Key, path string) error {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return errors.Wrapf(err, "failed to read file %s", path)
	}
	return key.Read(keyBytes)
}

// PublicKey represents a single RSA public key
type PublicKey struct {
	key crypto.PublicKey
}

// PrivateKey represents a single RSA private key
type PrivateKey struct {
	key crypto.PrivateKey
}

var _ Key = (*PublicKey)(nil)
var _ Key = (*PrivateKey)(nil)

// decodePublicKey decodes public key from byte representation
func decodePublicKey(key []byte) ([]byte, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		key, err := base64.StdEncoding.DecodeString(string(key))
		if err != nil {
			return nil, ErrPublicKeyDecodeBase64
		}
		return key, nil
	}
	if block.Type != "PUBLIC KEY" {
		return nil, ErrPublicKeyDecodePEM
	}
	return block.Bytes, nil
}

// decodePrivateKey decodes private key from byte representation
func decodePrivateKey(key []byte) ([]byte, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		key, err := base64.StdEncoding.DecodeString(string(key))
		if err != nil {
			return nil, ErrPrivateKeyDecodeBase64
		}
		return key, nil
	}
	if block.Type != "PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return nil, ErrPrivateKeyDecodePEM
	}
	return block.Bytes, nil
}

// parsePKIXPublicKeySecp256k1 parses a secp256k1 public key in PKIX format (necessary as the standard library doesn't support secp256k1)
func parsePKIXPublicKeySecp256k1(derBytes []byte) (pub any, err error) {
	var pki struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	if !pki.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}) {
		return nil, errors.New("x509: algorithm different from ECDSA")
	}

	der := cryptobyte.String(pki.PublicKey.RightAlign())
	paramsDer := cryptobyte.String(pki.Algorithm.Parameters.FullBytes)
	namedCurveOID := new(asn1.ObjectIdentifier)
	if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
		return nil, errors.New("x509: invalid ECDSA parameters")
	}
	if !namedCurveOID.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 10}) {
		return nil, errors.New("x509: curve is not secp256k1")
	}
	namedCurve := secp256k1.S256()
	//nolint: staticcheck
	x, y := elliptic.Unmarshal(namedCurve, der)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub = &ecdsa.PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}

// Read imports a public key in SPKI format
func (p *PublicKey) Read(publicKeySPKI []byte) error {
	pubKeyByte, err := decodePublicKey(publicKeySPKI)
	if err != nil {
		return err
	}
	pk, err := x509.ParsePKIXPublicKey(pubKeyByte)
	if err != nil {
		pk, err = parsePKIXPublicKeySecp256k1(pubKeyByte)
		if err != nil {
			return ErrPublicKeyParse
		}
	}

	_, isRSA := pk.(*rsa.PublicKey)
	_, isEC := pk.(*ecdsa.PublicKey)
	if !isRSA && !isEC {
		return ErrPublicKeyParse
	}

	p.key = pk
	return nil
}

// ReadFromFile reads a public key from a file in PKCS#8 format
func (p *PublicKey) ReadFromFile(path string) error {
	return readFromFile(p, path)
}

// String returns the public key in SPKI format
func (p *PublicKey) String() string {
	bytes, err := x509.MarshalPKIXPublicKey(p.key)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bytes}))
}

// NewPublicKeyFromString creates a new public key from a string in PKCS#8 format
func NewPublicKeyFromString(pkcs8String string) *PublicKey {
	k := &PublicKey{}
	if k.Read([]byte(pkcs8String)) != nil {
		return nil
	}
	return k
}

// parseECPrivateKeySecp256k1 parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKeySecp256k1(der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != 1 {
		return nil, errors.New("x509: unknown EC private key version")
	}

	if !privKey.NamedCurveOID.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 10}) {
		return nil, errors.New("x509: curve is not secp256k1")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curve := secp256k1.S256()
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

// Read imports a private key in PKCS#8 format
func (p *PrivateKey) Read(privateKeyPKCS8 []byte) error {
	privKeyByte, err := decodePrivateKey(privateKeyPKCS8)
	if err != nil {
		return err
	}

	pk, err := x509.ParsePKCS8PrivateKey(privKeyByte)
	if err != nil {
		pk, err = parseECPrivateKeySecp256k1(privKeyByte)
		if err != nil {
			return ErrPrivateKeyParse
		}
	}

	_, isRSA := pk.(*rsa.PrivateKey)
	_, isEC := pk.(*ecdsa.PrivateKey)
	if !isRSA && !isEC {
		return ErrPrivateKeyParse
	}

	p.key = pk
	return nil
}

// ReadFromFile reads a private key from a file in PKCS#8 format
func (p *PrivateKey) ReadFromFile(path string) error {
	return readFromFile(p, path)
}

// String returns the private key in PKCS#8 format
func (p *PrivateKey) String() string {
	bytes, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bytes}))
}

// NewPrivateKey creates a new private key from a crypto.PrivateKey
func NewPrivateKey(pk crypto.PrivateKey) *PrivateKey {
	k := &PrivateKey{
		key: pk,
	}
	return k
}

// NewPrivateKeyFromString creates a new private key from a string in PKCS#8 format
func NewPrivateKeyFromString(pkcs8String string) *PrivateKey {
	k := &PrivateKey{}
	if k.Read([]byte(pkcs8String)) != nil {
		return nil
	}
	return k
}

// Keys represents multiple keys
type Keys interface {
	ReadFromStrings(pkcs8Strings ...string) error
	ReadFromFiles(pathPrefix string) error
	SetCount(int)
	Count() int
	Cap() int
	At(int) Key
}

// readFromFiles loads all keys from files with the same pathPrefix
//
//	The first key uses pathPrefix directly and must always be available
//	The following keys are optional and use pathPrefix+".1", pathPrefix+".2", ...
func readFromFiles(keys Keys, pathPrefix string) error {
	keys.SetCount(keys.Cap())
	for i := 0; i < keys.Count(); i++ {
		path := pathPrefix
		if i > 0 {
			path += "." + strconv.Itoa(i)
		}
		if err := keys.At(i).ReadFromFile(path); err != nil {
			if i == 0 {
				return err
			}
			keys.SetCount(i)
			return nil
		}
	}
	return nil
}

// ReadFromStrings sets all keys from a set of PKCS#8 strings
func readFromStrings(keys Keys, pkcs8Strings ...string) error {
	keys.SetCount(len(pkcs8Strings))
	for i, pkcs := range pkcs8Strings {
		if err := keys.At(i).Read([]byte(pkcs)); err != nil {
			if i == 0 {
				return err
			}
			keys.SetCount(i)
			return nil
		}
	}
	return nil
}

// PublicKeys is a set of public keys
type PublicKeys []PublicKey

var _ Keys = (*PublicKeys)(nil)

// Cap returns the maximal number of public keys that should be used
func (pk PublicKeys) Cap() int {
	return cap(pk)
}

// Count returns the number of public keys in the set
func (pk PublicKeys) Count() int {
	return len(pk)
}

// SetCount changes the number of public keys in the set
func (pk *PublicKeys) SetCount(count int) {
	*pk = (*pk)[:count]
}

// At returns the i'th public keys in the set
func (pk *PublicKeys) At(i int) Key {
	return Key(&(*pk)[i])
}

// ReadFromFiles loads all public keys from files with the same pathPrefix
//
//	The first key uses pathPrefix directly
//	The following keys use pathPrefix+".1", pathPrefix+".2", ...
func (pk *PublicKeys) ReadFromFiles(pathPrefix string) error {
	return readFromFiles(pk, pathPrefix)
}

// ReadFromStrings sets all public keys from a set of PKCS#8 strings
func (pk *PublicKeys) ReadFromStrings(pkcs8Strings ...string) error {
	return readFromStrings(pk, pkcs8Strings...)
}

// NewPublicKey creates a new public key from a crypto.PublicKey
func NewPublicKey(pk crypto.PublicKey) *PublicKey {
	return &PublicKey{
		key: pk,
	}
}

// NewEmptyPublicKeys creates a new public key set given the maximal number of keys allowed to be used in parallel
func NewEmptyPublicKeys(maxCount int) *PublicKeys {
	var pk PublicKeys = make([]PublicKey, 0, maxCount)
	return &pk
}

// NewPublicKeysFromStrings creates a new public key from a set of PKCS#8 strings
func NewPublicKeysFromStrings(pkcs8Strings ...string) (*PublicKeys, error) {
	pk := NewEmptyPublicKeys(len(pkcs8Strings))
	err := readFromStrings(pk, pkcs8Strings...)
	return pk, err
}

// NewPublicKeys creates a new public key set from a set of crypto.PublicKey
func NewPublicKeys(pks ...crypto.PublicKey) *PublicKeys {
	// Unfortunately crypto.PublicKey is of type any, so we need to check the type
	// to avoid surprises when people still use the old interface
	if len(pks) == 1 {
		if size, ok := pks[0].(int); ok {
			return NewEmptyPublicKeys(size)
		}
	}
	pk := NewEmptyPublicKeys(len(pks))
	pk.SetCount(len(pks))
	for i, k := range pks {
		(*pk)[i].key = k
	}
	return pk
}

// PrivateKeys is a set of private keys
type PrivateKeys []PrivateKey

var _ Keys = (*PrivateKeys)(nil)

// Cap returns the maximal number of private keys that should be used
func (pk PrivateKeys) Cap() int {
	return cap(pk)
}

// Count returns the number of public keys in the set
func (pk PrivateKeys) Count() int {
	return len(pk)
}

// SetCount changes the number of public keys in the set
func (pk *PrivateKeys) SetCount(count int) {
	*pk = (*pk)[:count]
}

// At returns the i'th public keys in the set
func (pk *PrivateKeys) At(i int) Key {
	return Key(&(*pk)[i])
}

// ReadFromFiles loads all private keys from files with the same pathPrefix
//
//	The first key uses pathPrefix directly
//	The following keys use pathPrefix+".1", pathPrefix+".2", ...
func (pk *PrivateKeys) ReadFromFiles(pathPrefix string) error {
	return readFromFiles(pk, pathPrefix)
}

// ReadFromStrings sets all private keys from a set of PKCS#8 strings
func (pk *PrivateKeys) ReadFromStrings(pkcs8Strings ...string) error {
	return readFromStrings(pk, pkcs8Strings...)
}

// NewEmptyPrivateKeys creates a new private key set given the maximal number of keys allowed to be used in parallel
func NewEmptyPrivateKeys(maxCount int) *PrivateKeys {
	var pk PrivateKeys = make([]PrivateKey, 0, maxCount)
	return &pk
}

// NewPrivateKeysFromStrings creates a new private key from a set of PKCS#8 strings
func NewPrivateKeysFromStrings(pkcs8Strings ...string) (*PrivateKeys, error) {
	pk := NewEmptyPrivateKeys(len(pkcs8Strings))
	err := readFromStrings(pk, pkcs8Strings...)
	return pk, err
}

// NewPrivateKeys creates a new private key set from a set of crypto.PrivateKey
func NewPrivateKeys(pks ...crypto.PrivateKey) *PrivateKeys {
	// Unfortunately crypto.PrivateKey is of type any, so we need to check the type
	// to avoid surprises when people still use the old interface
	if len(pks) == 1 {
		if size, ok := pks[0].(int); ok {
			return NewEmptyPrivateKeys(size)
		}
	}
	pk := NewEmptyPrivateKeys(len(pks))
	pk.SetCount(len(pks))
	for i, k := range pks {
		(*pk)[i].key = k
	}
	return pk
}
