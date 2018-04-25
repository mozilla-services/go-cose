
package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"fmt"
	"log"
	"io"
)

var (
	supportedECDSAAlgs = []AlgName{
		AlgES256Name,
		AlgES384Name,
		AlgES512Name,
	}
)

// 		Name:               "ES512", // ECDSA w/ SHA-512 from [RFC8152]
// 		expectedKeyBitSize: 521, // P-521

// 		Name:               "ES384", // ECDSA w/ SHA-384 from [RFC8152]
// 		expectedKeyBitSize: 384,

// 		Name:               "ES256", // ECDSA w/ SHA-256 from [RFC8152]
// 		expectedKeyBitSize: 256,

func getCurveForAlgID(id AlgID) (curve elliptic.Curve, err error) {
	switch id {
	case AlgES256ID:
		curve = elliptic.P256()
	case AlgES384ID:
		curve = elliptic.P384()
	case AlgES512ID:
		curve = elliptic.P521()
	default:
		err = ErrAlgNotFound
	}
	return
}

func getKeySizeForAlgID(id AlgID) (keySize int, err error) {
	switch id {
	case AlgES256ID:
		keySize = 32
	case AlgES384ID:
		keySize = 48
	case AlgES512ID:
		keySize = 66
	default:
		err = ErrAlgNotFound
	}
	return
}

type ECDSAImpl struct {
	supportedAlgs []AlgName
}
func (e *ECDSAImpl) SupportsAlgorithm(algName string) bool {
	for _, name := range supportedECDSAAlgs {
		if string(name) == algName {
			return true
		}
	}
	return false
}
func (e *ECDSAImpl) NewSigner(algName string) (signer *ByteSigner, err error) {
	if !e.SupportsAlgorithm(algName) {
		return nil, errors.New("Unsupported ECDSA Algorithm")
	}

	var (
		algID AlgID
		curve elliptic.Curve
		privateKey *ecdsa.PrivateKey
	)

	algID, err = GetAlgIDByName(algName)
	if err != nil {
		return nil, err
	}

	curve, err = getCurveForAlgID(algID)
	if err != nil {
		return nil, err
	}

	privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	signer = &ECDSASigner{
		algID: algID,
		privateKey: privateKey,
	}
	return
}
func (e *ECDSAImpl) NewECDSASignerFromKey(algName string, privateKey *ecdsa.PrivateKey) (signer *ECDSASigner, err error) {
	if !e.SupportsAlgorithm(algName) {
		return nil, errors.New("Unsupported ECDSA Algorithm")
	}

	var (
		algID AlgID
		curve elliptic.Curve
	)

	algID, err = GetAlgIDByName(algName)
	if err != nil {
		return nil, err
	}

	curve, err = getCurveForAlgID(algID)
	if err != nil {
		return nil, err
	}
	if privateKey.Curve != curve {
		return nil, fmt.Errorf("Cannot use key with curve type %+v with algorithm %+v requiring curve of type %+v", privateKey.Curve, algName, curve)
	}

	signer = &ECDSASigner{
		algID: algID,
		privateKey: privateKey,
	}
	return
}


type ECDSASigner struct {
	algID AlgID
	privateKey *ecdsa.PrivateKey
}
func (s *ECDSASigner) Algorithm() (algID AlgID) {
	if s == nil {
		log.Fatalf("Cannot call Algorithm on nil Signer")
	}
	return s.algID
}
func (s *ECDSASigner) Sign(rand io.Reader, digest []byte) (signature []byte, err error) {
	// https://tools.ietf.org/html/rfc8152#section-8.1
	R, S, err := ecdsa.Sign(rand, s.privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.Sign error %s", err)
	}

	// TODO: assert r and s are the same length will be
	// the same length as the length of the key used for
	// the signature process

	// The signature is encoded by converting the integers into
	// byte strings of the same length as the key size.  The
	// length is rounded up to the nearest byte and is left padded
	// with zero bits to get to the correct length.  The two
	// integers are then concatenated together to form a byte
	// string that is the resulting signature.
	curveBits := s.privateKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	n := keyBytes
	sig := make([]byte, 0)
	sig = append(sig, I2OSP(R, n)...)
	sig = append(sig, I2OSP(S, n)...)

	return sig, nil
}
// Verifier returns a Verifier using the Signer's public key and
// provided Algorithm
func (s *ECDSASigner) Verifier() (verifier *ECDSAVerifier) {
	publicKey := s.privateKey.Public().(*ecdsa.PublicKey)

	return &ECDSAVerifier{
		publicKey: *publicKey,
		algID:     s.algID,
	}
}

type ECDSAVerifier struct {
	algID AlgID
	publicKey ecdsa.PublicKey
}
func NewVerifier(algName string) (signer *ECDSASigner, err error) {
	return
}
// func NewVerifierFromKey(algName AlgName, options interface{}) (ECDSASigner, error) {
// 	return
// }
func (s *ECDSAVerifier) Algorithm() (algID AlgID) {
	if s == nil {
		log.Fatalf("Cannot call Algorithm on nil Signer")
	}
	return s.algID
}
func (v *ECDSAVerifier) Verify(digest []byte, signature []byte) (err error) {
	if v == nil {
		return errors.New("Cannot verify with nil ECDSAVerifier")
	}

	keySize, err := getKeySizeForAlgID(v.algID)
	if err != nil {
		return err
	}
	if keySize < 1 {
		return fmt.Errorf("Could not find a keySize for the ecdsa algorithm")
	}

	// r and s from sig
	if len(signature) != 2*keySize {
		return fmt.Errorf("invalid signature length: %d", len(signature))
	}

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])

	ok := ecdsa.Verify(&v.publicKey, digest, r, s)
	if ok {
		return nil
	}
	return ErrECDSAVerification
}
