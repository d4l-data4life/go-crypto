package d4lcrypto_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
		wantErr error
	}{
		{"Normal case", 0, nil},
		{"Almost expired", 29, nil},
		{"Expired", 31, jwt.ErrTokenExpired},
		{"Not yet valid", -5, jwt.ErrTokenNotValidYet},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tv.TimeFunc = func() time.Time { return now.Add(time.Duration(tt.delay) * time.Second) }
			err := tv.Validate(tokenString)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTokenValidator_Secrets(t *testing.T) {
	token, err := d4lcrypto.NewTokenGenerator(d4lcrypto.NewTokenSecretFromString("AllYourBase")).Generate()
	require.NoError(t, err)

	t.Run("unknown secret", func(t *testing.T) {
		tv := d4lcrypto.NewTokenValidator(d4lcrypto.NewTokenSecretsFromStrings("Other"))
		require.ErrorIs(t, tv.Validate(token), jwt.ErrTokenSignatureInvalid)
	})

	t.Run("rotated secret", func(t *testing.T) {
		tv := d4lcrypto.NewTokenValidator(d4lcrypto.NewTokenSecretsFromStrings("Other", "AllYourBase"))
		require.NoError(t, tv.Validate(token))
	})
}
