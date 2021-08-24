package cose

import (
	"errors"
)

var (
	ErrInvalidAlg             = errors.New("invalid algorithm")
	ErrAlgNotFound            = errors.New("error fetching alg")
	ErrECDSAVerification      = errors.New("verification failed ecdsa.Verify")
	ErrRSAPSSVerification     = errors.New("verification failed rsa.VerifyPSS err crypto/rsa: verification error")
	ErrMissingCOSETagForLabel = errors.New("no common COSE tag for label")
	ErrMissingCOSETagForTag   = errors.New("no common COSE label for tag")
	ErrNilSigHeader           = errors.New("signature .headers is nil")
	ErrNilSigProtectedHeaders = errors.New("signature .headers.protected is nil")
	ErrNilSignatures          = errors.New("sign message .signatures is nil. Use AddSignature to add one")
	ErrNoSignatures           = errors.New("no signatures to sign the message. Use AddSignature to add them")
	ErrNoSignerFound          = errors.New("no signer found")
	ErrNoVerifierFound        = errors.New("no verifier found")
	ErrUnavailableHashFunc    = errors.New("hash function is not available")
	ErrUnknownPrivateKeyType  = errors.New("unrecognized private key type")
	ErrUnknownPublicKeyType   = errors.New("unrecognized public key type")
)
