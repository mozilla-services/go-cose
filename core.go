package cose

import (
	"encoding/base64"
	"bytes"
	"crypto"
	"fmt"
	"io"
	"math/big"
)

const (
	// text strings identifying the context of the signature
	// https://tools.ietf.org/html/rfc8152#section-4.4

	// ContextSignature for signatures using the COSE_Signature structure
	ContextSignature = "Signature"

	// ContextSignature1 for signatures using the COSE_Sign1 structure
	ContextSignature1 = "Signature1"

	// ContextCounterSignature for signatures used as counter signature attributes
	ContextCounterSignature = "CounterSignature"
)

// ByteSigner creates COSE signatures
type ByteSigner interface {
	// Sign returns the COSE signature as a byte slice
	Sign(rand io.Reader, digest []byte) (signature []byte, err error)
}

// ByteVerifier checks COSE signatures
type ByteVerifier interface {
	// Verify returns nil for a successfully verified signature or an error
	Verify(digest []byte, signature []byte) (err error)
}

// Sign returns the SignatureBytes for each Signer in the same order
// on the digest or the error from the first failing Signer
func Sign(rand io.Reader, digest []byte, signers []ByteSigner) (signatures [][]byte, err error) {
	var signatureBytes []byte

	for _, signer := range signers {
		signatureBytes, err = signer.Sign(rand, digest)
		if err != nil {
			return
		}
		signatures = append(signatures, signatureBytes)
	}
	return
}

// Verify returns nil if all Verifier verify the SignatureBytes or the
// error from the first failing Verifier
func Verify(digest []byte, signatures [][]byte, verifiers []ByteVerifier) (err error) {
	if len(signatures) != len(verifiers) {
		return fmt.Errorf("Wrong number of signatures %d and verifiers %d", len(signatures), len(verifiers))
	}

	for i, verifier := range verifiers {
		err = verifier.Verify(digest, signatures[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// buildAndMarshalSigStructure creates a Sig_structure, populates it
// with the appropriate fields, and marshals it to CBOR bytes
func buildAndMarshalSigStructure(bodyProtected, signProtected, external, payload []byte) (ToBeSigned []byte, err error) {
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	//
	// Sig_structure = [
	//     context : "Signature" / "Signature1" / "CounterSignature",
	//     body_protected : empty_or_serialized_map,
	//     ? sign_protected : empty_or_serialized_map,
	//     external_aad : bstr,
	//     payload : bstr
	// ]
	sigStructure := []interface{}{
		ContextSignature,
		bodyProtected, // message.headers.EncodeProtected(),
		signProtected, // message.signatures[0].headers.EncodeProtected(),
		external,
		payload,
	}

	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned, err = Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("Error marshaling Sig_structure: %s", err)
	}
	return ToBeSigned, nil
}

// hashSigStructure computes the crypto.Hash digest of a byte slice
func hashSigStructure(ToBeSigned []byte, hash crypto.Hash) (digest []byte, err error) {
	if !hash.Available() {
		return []byte(""), ErrUnavailableHashFunc
	}
	hasher := hash.New()
	_, _ = hasher.Write(ToBeSigned) // Write() on hash never fails
	digest = hasher.Sum(nil)
	return digest, nil
}

// I2OSP "Integer-to-Octet-String" converts a nonnegative integer to
// an octet string of a specified length
// https://tools.ietf.org/html/rfc8017#section-4.1
//
// implementation from
// https://github.com/r2ishiguro/vrf/blob/69d5bfb37b72b7b932ffe34213778bdb319f0438/go/vrf_ed25519/vrf_ed25519.go#L206
// (Apache License 2.0)
func I2OSP(b *big.Int, n int) []byte {
	os := b.Bytes()
	if n > len(os) {
		var buf bytes.Buffer
		buf.Write(make([]byte, n-len(os))) // prepend 0s
		buf.Write(os)
		return buf.Bytes()
	}
	return os[:n]
}

// FromBase64Int decodes a base64-encoded string into a big.Int or panics
//
// from https://github.com/square/go-jose/blob/789a4c4bd4c118f7564954f441b29c153ccd6a96/utils_test.go#L45
// Apache License 2.0
func FromBase64Int(data string) *big.Int {
	val, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		panic("Invalid test data")
	}
	return new(big.Int).SetBytes(val)
}
