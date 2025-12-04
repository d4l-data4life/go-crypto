package d4lcrypto_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/d4l-data4life/go-crypto/d4lcrypto"
)

func TestVerifyAndExtractDonorPayload(t *testing.T) {
	const myDonorID = "myDonorID"
	const mystudyID = "studyID1"
	tokenGen := d4lcrypto.NewTokenGenerator(d4lcrypto.NewTokenSecretFromString("SuperSecret"))
	token, err := tokenGen.Generate()
	if err != nil {
		t.Fatal(err)
	}

	payload := d4lcrypto.DonorPayload{Token: token, DonorID: myDonorID}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	encrypt := d4lcrypto.NewEncrypter(encPublicKey)
	payloadCipher, err := encrypt.Encrypt(payloadJSON)
	if err != nil {
		t.Fatal(err)
	}

	cm := d4lcrypto.ConsentMessage{
		ConsentDocumentKey: "test",
		StudyID:            mystudyID,
		SignatureType:      d4lcrypto.SignConsentOnce,
		Payload:            payloadCipher}
	cmJSON, err := json.Marshal(cm)
	if err != nil {
		t.Fatal(err)
	}

	signer := d4lcrypto.NewSigner(sigPrivateKey)
	signature, err := signer.Sign(cmJSON)
	if err != nil {
		t.Fatal(err)
	}

	scm := d4lcrypto.SignedConsentMessage{ConsentMessageJSON: string(cmJSON), Signature: signature}
	scmJSON, err := json.Marshal(scm)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := encrypt.Encrypt(scmJSON)
	if err != nil {
		t.Fatal(err)
	}

	decrypt := d4lcrypto.NewDecrypter(encPrivateKeys)
	cV := d4lcrypto.NewVerifier(sigPublicKeys)
	tV := d4lcrypto.NewTokenValidator(d4lcrypto.NewTokenSecretsFromStrings("SuperSecret"))
	ctx := d4lcrypto.RequestValidationContext{Decrypter: decrypt, ConsentSignatureVerifier: cV, TokenValidator: tV}

	dk, studyID, p, err := d4lcrypto.VerifyAndExtractDonorPayload(ciphertext, d4lcrypto.SignConsentOnce, ctx)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "test", dk)
	assert.Equal(t, mystudyID, studyID)
	assert.Equal(t, myDonorID, p.DonorID)
	t.Log(p)
}

func TestVerifyAndExtractSelfSignedDonorPayload(t *testing.T) {
	tV := d4lcrypto.NewTokenValidator(d4lcrypto.NewTokenSecretsFromStrings("SuperSecret"))
	tokenGen := d4lcrypto.NewTokenGenerator(d4lcrypto.NewTokenSecretFromString("SuperSecret"))
	tests := []struct {
		name string
		ctx  d4lcrypto.SelfSignedRequestValidationContext
	}{
		{"default", d4lcrypto.SelfSignedRequestValidationContext{tV, ""}},
		{"with secret", d4lcrypto.SelfSignedRequestValidationContext{tV, "Extremely Secret"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const myDonorID = sigStrippedPublicKey

			token, err := tokenGen.Generate()
			if err != nil {
				t.Fatal(err)
			}

			payload := d4lcrypto.DonorPayload{Token: token, DonorID: myDonorID}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			message := string(payloadJSON)

			signer := d4lcrypto.NewSigner(sigPrivateKey)
			signature, err := signer.Sign([]byte(message + tt.ctx.SignatureSecret))
			if err != nil {
				t.Fatal(err)
			}

			signedDonorPayload := d4lcrypto.SignedDonorPayload{
				MessageJSON: string(payloadJSON),
				Signature:   signature,
			}

			ciphertext, err := json.Marshal(signedDonorPayload)
			if err != nil {
				t.Fatal(err)
			}

			// Base64 encode ciphertext
			encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
			dp, err := d4lcrypto.VerifyAndExtractSelfSignedDonorPayload(json.RawMessage(encodedCiphertext), tt.ctx)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, myDonorID, dp.DonorID)
		})
	}
}
