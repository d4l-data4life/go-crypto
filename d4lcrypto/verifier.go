package d4lcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/pkg/errors"
)

// define errors
var (
	ErrVerifierNoKeys = errors.New("verification failed - no public keys available")
	ErrVerification   = errors.New("verification error")
	ErrUnsupportedKey = errors.New("unsupported key")
)

// Verifier to verify signed messages with a configured RSA public key
type Verifier struct {
	publicKeys *PublicKeys // must be a pointer to a slice here, as the key slice might be resized
}

// NewVerifier creates a new Verifier instance for the given RSA public key in PEM format
func NewVerifier(publicKeys *PublicKeys) *Verifier {
	return &Verifier{
		publicKeys: publicKeys,
	}
}

// Verify verifies the message by
//  1. hashing the message using SHA-256
//  2. verifying the hashed message using the signature using
//     a. RSA-PSS with a salt length of "32"
//     b. ECDSA
//
// nolint: gocyclo, gocognit
func (v *Verifier) Verify(message []byte, signature []byte) error {
	hashed := sha256.Sum256(message)
	err := ErrVerifierNoKeys
	for _, public := range *v.publicKeys {
		if rsaPk, ok := public.key.(*rsa.PublicKey); ok {
			if rsa.VerifyPSS(rsaPk, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{SaltLength: 32}) == nil {
				return nil
			}
			err = ErrVerification
		} else if ecPk, ok := public.key.(*ecdsa.PublicKey); ok {
			// use optimised code for secp256k1 curve
			if *ecPk.Params() == *secp256k1.S256().Params() {
				if len(signature) > 65 {
					// convert from ASN.1 format to compressed format
					asnSig := &ECDSASignature{}
					_, err := asn1.Unmarshal(signature, asnSig)
					if err != nil {
						return err
					}
					signature = append(asnSig.R.Bytes(), asnSig.S.Bytes()...)
				}

				pubkey := secp256k1.CompressPubkey(ecPk.X, ecPk.Y)
				if secp256k1.VerifySignature(pubkey, hashed[:], signature) {
					return nil
				}
			} else {
				if len(signature) <= 2*((ecPk.Curve.Params().BitSize+7)/8)+1 {
					// convert from compressed format to ASN.1 format
					signature, err = GetECASN1Signature(signature)
					if err != nil {
						return err
					}
				}
				if ecdsa.VerifyASN1(ecPk, hashed[:], signature) {
					return nil
				}
			}
			err = ErrVerification
		}
	}
	return err
}
