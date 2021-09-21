package cose

import (
	"errors"
)

var (
	// ErrInvalidAlg is returned when the algorithm is not supported
	ErrInvalidAlg = errors.New("invalid algorithm")
	// ErrAlgNotFound is returned when the algorithm is not found in COSE
	ErrAlgNotFound = errors.New("error fetching alg")
	// ErrECDSAVerification is returned when the ECDSA verification fails
	ErrECDSAVerification = errors.New("verification failed ecdsa.Verify")
	// ErrRSAPSSVerification is returned when the RSA-PSS verification fails
	ErrRSAPSSVerification = errors.New("verification failed rsa.VerifyPSS err crypto/rsa: verification error")
	// ErrMissingCOSETagForLabel is returned when the COSE tag is missing for a label
	ErrMissingCOSETagForLabel = errors.New("no common COSE tag for label")
	// ErrMissingCOSETagForTag is returned when the COSE tag is missing for a tag
	ErrMissingCOSETagForTag = errors.New("no common COSE label for tag")
	// ErrNilSigHeader is returned when the signature header is nil
	ErrNilSigHeader = errors.New("signature headers is nil")
	// ErrNilSigProtectedHeaders is returned when the signature protected header is nil
	ErrNilSigProtectedHeaders = errors.New("signature protected headers is nil")
	// ErrNilSignatures is returned when the signatures are nil
	ErrNilSignatures = errors.New("signed message signatures is nil")
	// ErrNoSignatures is returned when the message has no signatures
	ErrNoSignatures = errors.New("no signatures to sign the message")
	// ErrNoSignerFound is returned when no signer is found
	ErrNoSignerFound = errors.New("no signer found")
	// ErrNoVerifierFound is returned when no verifier is found
	ErrNoVerifierFound = errors.New("no verifier found")
	// ErrUnavailableHashFunc is returned when the hash function is not available
	ErrUnavailableHashFunc = errors.New("hash function is not available")
	// ErrUnknownPrivateKeyType is returned when the private key type is unknown
	ErrUnknownPrivateKeyType = errors.New("unrecognized private key type")
	// ErrUnknownPublicKeyType is returned when the public key type is unknown
	ErrUnknownPublicKeyType = errors.New("unrecognized public key type")
)
