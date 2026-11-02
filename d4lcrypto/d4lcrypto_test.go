package d4lcrypto_test

import (
	"os"
	"testing"
)

// Executed before test runs in this package (fails otherwise)
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
