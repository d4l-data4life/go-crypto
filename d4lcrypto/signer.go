package d4lcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Signer to sign messages with a configured RSA private key
type Signer struct {
	private *PrivateKey
}

// NewSigner creates a new Signer instance for the given RSA private key in PEM format
func NewSigner(privateKey *PrivateKey) *Signer {
	return &Signer{
		private: privateKey,
	}
}

type ECDSASignature struct {
	R *big.Int `asn1:"integer"`
	S *big.Int `asn1:"integer"`
}

func GetECASN1Signature(signature []byte) ([]byte, error) {
	asnSig := ECDSASignature{
		R: new(big.Int).SetBytes(signature[0:32]),
		S: new(big.Int).SetBytes(signature[32:64]),
	}
	return asn1.Marshal(asnSig)
}

// Sign signs the message by
//  1. hashing the message using SHA-256
//  2. signing the hashed message using
//     a. RSA-PSS with a salt length of "32"
//     b. ECDSA
func (s *Signer) Sign(message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	if rsaPk, ok := s.private.key.(*rsa.PrivateKey); ok {
		return rsa.SignPSS(rand.Reader, rsaPk, crypto.SHA256, hashed[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	} else if ecPk, ok := s.private.key.(*ecdsa.PrivateKey); ok {
		// use optimised code for secp256k1 curve
		if *ecPk.Params() == *secp256k1.S256().Params() {
			sigRaw, err := secp256k1.Sign(hashed[:], ecPk.D.Bytes())
			if err != nil {
				return nil, err
			}
			// convert from compressed format to ASN.1 format
			return GetECASN1Signature(sigRaw)
		}
		return ecdsa.SignASN1(rand.Reader, ecPk, hashed[:])
	}
	return nil, ErrUnsupportedKey
}
