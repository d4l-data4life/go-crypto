package d4lcrypto

import (
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
)

// DonorPayload is the innermost payload of the donor registration and resource donation requests
type DonorPayload struct {
	Token   string `json:"token"`
	DonorID string `json:"donorID"`
}

// RequestValidationContext bundles the crypto objects required to validate Donation API request
type RequestValidationContext struct {
	Decrypter                *Decrypter
	ConsentSignatureVerifier *Verifier
	TokenValidator           *TokenValidator
}

// VerifyAndExtractDonorPayload extracts request payload according to registration/donation protocol.
// The function decrypts a JSON string which is signed by the Consent Service, the signature is verified.
// The JSON string is then unmarshalled and checked for the right consent signature type.
// Finally, the payload will be decrypted and unmarshalled into the payload object.
func VerifyAndExtractDonorPayload(
	jsonBytes json.RawMessage,
	wantedSignatureType SignatureType,
	ctx RequestValidationContext,
) (consentDocumentKey string, studyID string, donorPayload *DonorPayload, err error) {
	donorPayload = &DonorPayload{}

	// Decrypt and parse signed consent message
	signedConsentMessage := SignedConsentMessage{}
	err = ctx.Decrypter.DecryptAndUnmarshal(jsonBytes, &signedConsentMessage)
	if err != nil {
		err = errors.Wrap(err, "error decoding signed consent message")
		return consentDocumentKey, studyID, donorPayload, err
	}

	// Parse consent message
	consentMessage, err := ParseConsentMessage([]byte(signedConsentMessage.ConsentMessageJSON), wantedSignatureType)
	if err != nil {
		return consentDocumentKey, studyID, donorPayload, err
	}

	consentDocumentKey = consentMessage.ConsentDocumentKey
	studyID = consentMessage.StudyID

	// Verify consent signature
	if err = signedConsentMessage.VerifySignature(ctx.ConsentSignatureVerifier); err != nil {
		return consentDocumentKey, studyID, donorPayload, err
	}

	// Decrypt donation request
	if err = ctx.Decrypter.DecryptAndUnmarshal(consentMessage.Payload, &donorPayload); err != nil {
		err = errors.Wrap(err, "error decrypting donation request")
		return consentDocumentKey, studyID, donorPayload, err
	}

	// Validate token
	if err = ctx.TokenValidator.Validate(donorPayload.Token); err != nil {
		err = errors.Wrap(err, "donation token invalid")
		return consentDocumentKey, studyID, donorPayload, err
	}

	return consentDocumentKey, studyID, donorPayload, err
}

// SelfSignedRequestValidationContext bundles the crypto objects required to validate self-signed Donation API requests
type SelfSignedRequestValidationContext struct {
	TokenValidator  *TokenValidator
	SignatureSecret string
}

// SignedDonorPayload is a JSON encoded DonorPayload with signature
type SignedDonorPayload struct {
	MessageJSON string `json:"messageJSON"`
	Signature   []byte `json:"signature"`
}

// VerifySignature verifies the signature of a signed message
func (signedDonorPayload *SignedDonorPayload) VerifySignature(verifier *Verifier, secret string) error {
	// Verify signature
	signatureBase := signedDonorPayload.MessageJSON + secret
	err := verifier.Verify([]byte(signatureBase), signedDonorPayload.Signature)
	if err != nil {
		return errors.Wrap(err, "invalid donor signature")
	}
	return nil
}

// VerifyAndExtractSelfSignedDonorPayload extracts request payload according to response protocol.
// The function decrypts a JSON encoded DonorPayload which is signed by the Donor.
// Donor signature and token are both verified.
func VerifyAndExtractSelfSignedDonorPayload(
	cipherJSON json.RawMessage,
	ctx SelfSignedRequestValidationContext,
) (donorPayload *DonorPayload, err error) {
	donorPayload = &DonorPayload{}

	// Decode base64 encoded cipherJSON
	decodedJSON, err := base64.StdEncoding.DecodeString(string(cipherJSON))
	if err != nil {
		err = errors.Wrap(err, "error decoding self-signed message")
		return donorPayload, err
	}

	// Parse self-signed message
	signedDonorPayload := SignedDonorPayload{}
	err = json.Unmarshal(decodedJSON, &signedDonorPayload)
	if err != nil {
		err = errors.Wrap(err, "error decoding self-signed message")
		return donorPayload, err
	}

	err = json.Unmarshal([]byte(signedDonorPayload.MessageJSON), donorPayload)
	if err != nil || donorPayload.DonorID == "" {
		err = errors.Wrap(err, "error decoding self-signed message")
		return donorPayload, err
	}

	keys, err := NewPublicKeysFromStrings(donorPayload.DonorID)
	if err != nil {
		err = errors.Wrap(err, "error decoding self-signed message")
		return donorPayload, err
	}

	verifier := NewVerifier(keys)

	// Verify donor signature
	if err = signedDonorPayload.VerifySignature(verifier, ctx.SignatureSecret); err != nil {
		return donorPayload, err
	}

	// Validate token
	if err = ctx.TokenValidator.Validate(donorPayload.Token); err != nil {
		err = errors.Wrap(err, "donation token invalid")
		return donorPayload, err
	}

	return donorPayload, err
}
