package d4lcrypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/d4l-data4life/go-crypto/d4lcrypto"
)

func TestGenerateRandomBytes(t *testing.T) {
	tests := []struct {
		name    string
		len     int
		wantErr bool
	}{
		{"standard nonce", 32, false},
		{"empty nonce", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d4lcrypto.GenerateRandomBytes(tt.len)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRandomBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.Len(t, got, tt.len, "Lengths differ")
			}
		})
	}
}
