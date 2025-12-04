package d4lcrypto_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d4l-data4life/go-crypto/d4lcrypto"
)

func TestNewTokenGenerator(t *testing.T) {
	type fields struct {
		tokenNonceLength int
		tokenTTLSeconds  int
	}
	tests := []struct {
		name     string
		expected fields
		wantErr  bool
	}{
		{"Default parameters", fields{32, 30}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d4lcrypto.NewTokenGenerator(d4lcrypto.NewTokenSecretFromString("AllYourBase"))
			if !tt.wantErr {
				assert.NotEmpty(t, got.Secret)
				assert.Equal(t, tt.expected.tokenNonceLength, got.NonceLength)
				assert.Equal(t, tt.expected.tokenTTLSeconds, got.TTLSeconds)
			}
		})
	}
}

func TestTokenGenerator_Validate(t *testing.T) {
	tr := &d4lcrypto.TokenGenerator{
		Secret:      d4lcrypto.NewTokenSecretFromString("AllYourBase"),
		NonceLength: 32,
		TTLSeconds:  30,
	}
	tv := d4lcrypto.NewTokenValidator(d4lcrypto.NewTokenSecretsFromStrings("AllYourBase"))
	tokenString, err := tr.Generate()
	require.NoError(t, err, "Setup failed")
	now := time.Now()

	tests := []struct {
		name    string
		delay   int
		wantErr bool
		err     string
	}{
		{"Normal case", 0, false, ""},
		{"Almost expired", 29, false, ""},
		{"Expired", 31, true, "Token is expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			At(now.Add(time.Duration(tt.delay)*time.Second), func() {
				err := tv.Validate(tokenString)
				if tt.wantErr {
					require.Error(t, err)
					assert.Equal(t, tt.err, err.Error(), "Test = %v, Msg = Error message should match", tt.name)
				} else {
					require.NoError(t, err)
				}
			})
		})
	}
}
