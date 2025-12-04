package d4lcrypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/d4l-data4life/go-crypto/d4lcrypto"
)

func TestHasher(t *testing.T) {
	h := &d4lcrypto.ScryptHasher{3}
	hash1, err := h.HashWithSalt([]byte("test"), []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}

	h.Complexity = 5
	hash2, err := h.HashWithSalt([]byte("test"), []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, hash1, hash2, "different complexity should result in different hash")

	h.Complexity = 3
	hash3, err := h.HashWithSalt([]byte("test"), []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, hash1, hash3, "same values should result in same hash")

	hash4, err := h.HashWithSalt([]byte("test2"), []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, hash1, hash4, "different string, different hash")

	hash5, err := h.HashWithSalt([]byte("test"), []byte("salt2"))
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, hash1, hash5, "different salt, different hash")
}
