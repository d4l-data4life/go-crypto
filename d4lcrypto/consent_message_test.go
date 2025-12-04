package d4lcrypto_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d4l-data4life/go-crypto/d4lcrypto"
)

func TestParseConsentMessage(t *testing.T) {
	tests := []struct {
		name           string
		cm             []byte
		wantedST       d4lcrypto.SignatureType
		expectedReturn *d4lcrypto.ConsentMessage
		expectedErr    error
	}{
		{
			"OK",
			must(json.Marshal(d4lcrypto.ConsentMessage{
				ConsentDocumentKey: "testKey", SignatureType: d4lcrypto.SignConsentOnce, Payload: []byte("payload-0")})),
			d4lcrypto.SignConsentOnce,
			&d4lcrypto.ConsentMessage{
				ConsentDocumentKey: "testKey", SignatureType: d4lcrypto.SignConsentOnce, Payload: []byte("payload-0")},
			nil,
		},
		{
			"OK-2",
			must(json.Marshal(d4lcrypto.ConsentMessage{
				ConsentDocumentKey: "testKey", SignatureType: d4lcrypto.SignNormalUse, Payload: []byte("payload-0")})),
			d4lcrypto.SignNormalUse,
			&d4lcrypto.ConsentMessage{
				ConsentDocumentKey: "testKey", SignatureType: d4lcrypto.SignNormalUse, Payload: []byte("payload-0")},
			nil,
		},
		{
			"different signature type",
			must(json.Marshal(d4lcrypto.ConsentMessage{
				ConsentDocumentKey: "testKey", SignatureType: d4lcrypto.SignConsentOnce, Payload: []byte("payload-1")})),
			d4lcrypto.SignNormalUse,
			&d4lcrypto.ConsentMessage{
				ConsentDocumentKey: "testKey", SignatureType: d4lcrypto.SignConsentOnce, Payload: []byte("payload-1")},
			d4lcrypto.ErrConsentParametersWrong,
		},
		{
			"no JSON",
			[]byte("no-valid-json"),
			d4lcrypto.SignConsentOnce,
			&d4lcrypto.ConsentMessage{},
			d4lcrypto.ErrConsentJSONUnmarshal,
		},
	}

	t.Parallel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := d4lcrypto.ParseConsentMessage(tt.cm, tt.wantedST)
			if (err == nil) != (tt.expectedErr == nil) {
				t.Fatalf("error %v, expected %v", err, tt.expectedErr)
			}
			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				assert.Equal(t, tt.expectedErr, err, "should fail on expected error")
			}

			assert.Equal(t, tt.expectedReturn, parsed)
		})
	}
}

func TestVerifySignature(t *testing.T) {
	signer := d4lcrypto.NewSigner(sigPrivateKey)
	signature, err := signer.Sign(sigTestMessage)
	if err != nil {
		t.Errorf("error when signing message: %v", err)
	}
	scm := d4lcrypto.SignedConsentMessage{string(sigTestMessage), signature}

	t.Parallel()

	t.Run("verify with matching public key", func(t *testing.T) {
		verifier := d4lcrypto.NewVerifier(sigPublicKeys)
		err = scm.VerifySignature(verifier)
		require.NoErrorf(t, err, "error verifying signature")
	})

	t.Run("verify with different public key", func(t *testing.T) {
		verifier := d4lcrypto.NewVerifier(sigPublicKeys2)
		err = scm.VerifySignature(verifier)
		if !errors.Is(err, d4lcrypto.ErrVerification) {
			assert.Equal(t, d4lcrypto.ErrVerification, err, "should fail on expected error")
		}
	})
}

func must(byteArray []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return byteArray
}
