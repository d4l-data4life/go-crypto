package d4lcrypto_test

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// At overrides the time value for tests and restores the default value after.
func At(t time.Time, f func()) {
	jwt.TimeFunc = func() time.Time {
		return t
	}
	f()
	jwt.TimeFunc = time.Now
}

// Executed before test runs in this package (fails otherwise)
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
