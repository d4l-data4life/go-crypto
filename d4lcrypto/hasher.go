package d4lcrypto

import "golang.org/x/crypto/scrypt"

// Hasher hashes a plaintext with salt
type Hasher interface {
	HashWithSalt(plaintext []byte, salt []byte) ([]byte, error)
}

var _ Hasher = (*ScryptHasher)(nil)

// ScryptHasher satisfies the Hasher interface and uses scrypt algorithm to hash a string with some salt
type ScryptHasher struct {
	// Complexity defines the N complexity (as 1<<N or 2^N) of the scrypt hashing algorithm
	// see https://godoc.org/golang.org/x/crypto/scrypt
	// A good value is something between 14 and 20 (as of writing this doc in 2020 - needs to be adjusted in the future)
	Complexity int
}

// HashWithSalt hashes the given plaintext with some salt
func (h *ScryptHasher) HashWithSalt(plaintext []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(plaintext, salt, 1<<h.Complexity, 8, 1, 32)
}
