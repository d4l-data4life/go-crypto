package d4lcrypto

import (
	"encoding/json"
	"fmt"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/pkg/errors"
)

// Error types
var (
	ErrSignedDeletionJSONUnmarshal = errors.New("error decoding signed deletion message")
	ErrDeletionJSONUnmarshal       = errors.New("error decoding deletion message")
	ErrDeletionParametersWrong     = errors.New("wrong deletion parameters")
	ErrDeletionValidityElapsed     = errors.New("validity of deletion message is elapsed")
	ErrDeletionSignatureInvalid    = errors.New("invalid deletion signature")
)

// DeletionMessage contains the encrypted RegistrationRequest to be signed by the Consent API
type DeletionMessage struct {
	ConsentDocumentKey string        `json:"consentDocumentKey"`
	StudyID            string        `json:"studyID"`
	SignatureType      SignatureType `json:"signatureType"`
	ValidUntil         time.Time     `json:"validUntil"`
	UUID               uuid.UUID     `json:"uuid"`
}

// ParseDeletionMessage parses JSON encoded deletion message and checks for the correct document key and signature type
func ParseDeletionMessage(jsonBytes json.RawMessage, wantedConsentDocumentKey string) (*DeletionMessage, error) {
	deletionMessage := &DeletionMessage{}
	if err := json.Unmarshal(jsonBytes, deletionMessage); err != nil {
		return nil, fmt.Errorf("%w - %v", ErrDeletionJSONUnmarshal, err)
	}

	if deletionMessage.ConsentDocumentKey != wantedConsentDocumentKey {
		return nil, fmt.Errorf(
			"%w - unexpected consent document key %q. must be %q",
			ErrDeletionParametersWrong,
			deletionMessage.ConsentDocumentKey,
			wantedConsentDocumentKey,
		)
	}

	if deletionMessage.SignatureType != SignRevokeOnce {
		return nil, fmt.Errorf(
			"%w - unexpected signature type %q. must be %q",
			ErrDeletionParametersWrong,
			deletionMessage.SignatureType,
			SignRevokeOnce,
		)
	}
	return deletionMessage, nil
}

// Validate validates the lifetime of the deletion message
func (deletionMessage *DeletionMessage) Validate() error {
	// Verify signature from Donation Service
	if time.Now().After(deletionMessage.ValidUntil) {
		return ErrDeletionValidityElapsed
	}
	return nil
}

// SignedDeletionMessage contains the JSON encoded DeletionMessage with signature from the Donation Service
type SignedDeletionMessage struct {
	DeletionMessageJSON string `json:"deletionMessage"`
	Signature           []byte `json:"signature"`
}

// VerifySignature verifies the signature of the signed deletion message
func (signedDeletionMessage *SignedDeletionMessage) VerifySignature(verifier *Verifier) error {
	// Verify signature from Donation Service
	err := verifier.Verify([]byte(signedDeletionMessage.DeletionMessageJSON), signedDeletionMessage.Signature)
	if err != nil {
		return fmt.Errorf("%w - %v", ErrDeletionSignatureInvalid, err)
	}
	return nil
}

// VerifyAndExtractDeletionMessage extracts the deletion proof (DeletionMessage) according to revocation protocol.
// The function extracts a JSON string which is signed by the Donation Service, the signature is verified.
// The JSON string is then unmarshalled and checked for the right signature type.
// Finally, the payload will be decrypted and unmarshalled into the payload object.
func VerifyAndExtractDeletionMessage(
	jsonBytes json.RawMessage,
	wantedConsentDocumentKey string,
	deletionSignatureVerifier *Verifier,
) (*DeletionMessage, error) {
	// Parse signed deletion message
	signedDeletionMessage := &SignedDeletionMessage{}
	err := json.Unmarshal(jsonBytes, signedDeletionMessage)
	if err != nil {
		return nil, fmt.Errorf("%w - %v", ErrSignedDeletionJSONUnmarshal, err)
	}

	// Parse deletion message
	deletionMessage, err := ParseDeletionMessage([]byte(signedDeletionMessage.DeletionMessageJSON), wantedConsentDocumentKey)
	if err != nil {
		return nil, err
	}

	// Verify deletion signature
	if err = signedDeletionMessage.VerifySignature(deletionSignatureVerifier); err != nil {
		return nil, err
	}

	// Validate lifetime
	if err = deletionMessage.Validate(); err != nil {
		return nil, err
	}

	return deletionMessage, nil
}
