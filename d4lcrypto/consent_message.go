package d4lcrypto

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

// Error types
var (
	ErrConsentParametersWrong = errors.New("wrong consent parameters")
	ErrConsentJSONUnmarshal   = errors.New("error decoding consent message")
)

// ConsentMessage contains the encrypted RegistrationRequest to be signed by the Consent API
type ConsentMessage struct {
	ConsentDocumentKey string        `json:"consentDocumentKey"`
	StudyID            string        `json:"studyID"`
	SignatureType      SignatureType `json:"signatureType"`
	Payload            []byte        `json:"payload"`
}

// ParseConsentMessage parses JSON encoded consent message and checks for the correct consent signature type
func ParseConsentMessage(jsonBytes json.RawMessage, wantedSignatureType SignatureType) (*ConsentMessage, error) {
	consentMessage := &ConsentMessage{}
	err := json.Unmarshal(jsonBytes, consentMessage)
	if err != nil {
		return consentMessage, fmt.Errorf("%w - %v", ErrConsentJSONUnmarshal, err)
	}

	if consentMessage.SignatureType != wantedSignatureType {
		return consentMessage, errors.Wrap(ErrConsentParametersWrong, "consent signature type doesn't match")
	}
	return consentMessage, nil
}

// SignedConsentMessage contains the JSON encoded ConsentMessage with signature from Consent API
type SignedConsentMessage struct {
	ConsentMessageJSON string `json:"consentMessageJSON"`
	Signature          []byte `json:"signature"`
}

// VerifySignature verifies the signature of the signed consent message
func (signedConsentMessage *SignedConsentMessage) VerifySignature(verifier *Verifier) error {
	// Verify signature from Consent API
	err := verifier.Verify([]byte(signedConsentMessage.ConsentMessageJSON), signedConsentMessage.Signature)
	if err != nil {
		return errors.Wrap(err, "invalid consent signature")
	}
	return nil
}
