package d4lcrypto

import (
	"fmt"

	"github.com/pkg/errors"
)

type SignatureType string

const (
	SignConsentOnce SignatureType = "consentOnce"
	SignNormalUse   SignatureType = "normalUse"
	SignRevokeOnce  SignatureType = "revokeOnce"
)

var (
	ErrInvalidSignatureType = errors.New("invalid signature type")
)

func (st SignatureType) Validate() error {
	switch st {
	case SignConsentOnce, SignNormalUse, SignRevokeOnce:
		return nil
	default:
		return fmt.Errorf("signatureType %q unknown: %w", st, ErrInvalidSignatureType)
	}
}

func (st SignatureType) OneTimeRestricted() bool {
	switch st {
	case SignConsentOnce, SignRevokeOnce:
		return true
	default:
		return false
	}
}
