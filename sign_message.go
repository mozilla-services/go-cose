package cose

import (
	"crypto"
	"fmt"
	"io"
)


// AlgorithmImplementer returns signers and verifiers for a COSE Algorithm
type AlgorithmImplementer interface {
	SupportsAlgorithm(algName string) (bool)
	NewByteSigner(algName string) (signer *ByteSigner, err error)
	NewByteSignerFromKey(algName string, privateKey *crypto.PrivateKey) (signer *ByteSigner, err error)

	NewVerifier(algName string) (verifier *ByteVerifier, err error)
}

// AlgorithmMethodImplementer lets us know which COSE.Algorithm it implements
type AlgorithmMethodImplementer interface {
	Algorithm() AlgID
}

// MessageSigner can Sign SignMessages
type MessageSigner interface {
	AlgorithmMethodImplementer
	ByteSigner
}

// MessageSigner can Verify SignMessages
type MessageVerifier interface {
	AlgorithmMethodImplementer
	ByteVerifier
}

var algImplementors = []AlgorithmImplementer{
	ECDSAImpl{
		supportedECDSAAlgs: supportedECDSAAlgs,
	},
}

func NewSignerFromKey(algName string, privateKey *crypto.PrivateKey) (signer *MessageSigner, err error) {
	var (
		algID AlgID
	)
	algID, err = GetAlgIDByName(algName)
	if err != nil {
		return nil, err
	}

	return
}

// SignMessage represents a COSESignMessage with CDDL fragment:
//
// COSE_Sign = [
//        Headers,
//        payload : bstr / nil,
//        signatures : [+ COSE_Signature]
// ]
//
// https://tools.ietf.org/html/rfc8152#section-4.1
type SignMessage struct {
	Headers    *Headers
	Payload    []byte
	Signatures []Signature
}

// NewSignMessage takes a []byte payload and returns a new SignMessage
// with empty headers and signatures
func NewSignMessage() (msg SignMessage) {
	msg = SignMessage{
		Headers: &Headers{
			Protected:   map[interface{}]interface{}{},
			Unprotected: map[interface{}]interface{}{},
		},
		Payload:    nil,
		Signatures: nil,
	}
	return msg
}

// AddSignature adds a signature to the message signatures creating an
// empty []Signature if necessary
func (m *SignMessage) AddSignature(s *Signature) {
	if m.Signatures == nil {
		m.Signatures = []Signature{}
	}
	m.Signatures = append(m.Signatures, *s)
}

// SigStructure returns the byte slice to be signed
func (m *SignMessage) SigStructure(external []byte, signature *Signature) (ToBeSigned []byte, err error) {
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	//
	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned, err = buildAndMarshalSigStructure(
		m.Headers.EncodeProtected(),
		signature.Headers.EncodeProtected(),
		external,
		m.Payload)
	return
}

// SignatureDigest takes an extra external byte slice and a Signature
// and returns the SigStructure (i.e. ToBeSigned) hashed using the
// algorithm from the signature parameter
//
// TODO: check that signature is in SignMessage?
func (m *SignMessage) SignatureDigest(external []byte, signature *Signature) (digest []byte, err error) {
	ToBeSigned, err := m.SigStructure(external, signature)
	if err != nil {
		return nil, err
	}

	algID, err := signature.Headers.Algorithm()
	if err != nil {
		return nil, err
	}

	hash, err := getSigningAlgHashFuncByID(algID)
	if err != nil {
		return nil, err
	}

	digest, err = hashSigStructure(ToBeSigned, hash)
	if err != nil {
		return nil, err
	}

	return digest, err
}

// Signing and Verification Process
// https://tools.ietf.org/html/rfc8152#section-4.4

// Sign signs a SignMessage i.e. it populates
// signatures[].SignatureBytes using the provided array of Signers
func (m *SignMessage) Sign(rand io.Reader, external []byte, signers []MessageSigner) (err error) {
	if m.Signatures == nil {
		return ErrNilSignatures
	} else if len(m.Signatures) < 1 {
		return ErrNoSignatures
	} else if len(m.Signatures) != len(signers) {
		return fmt.Errorf("%d signers for %d signatures", len(signers), len(m.Signatures))
	}

	for i, signature := range m.Signatures {
		if signature.Headers == nil {
			return ErrNilSigHeader
		} else if signature.Headers.Protected == nil {
			return ErrNilSigProtectedHeaders
		} else if signature.SignatureBytes != nil || len(signature.SignatureBytes) > 0 {
			return fmt.Errorf("SignMessage signature %d already has signature bytes", i)
		}
		// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected

		// TODO: dedup with alg in m.SignatureDigest()?
		algID, err := signature.Headers.Algorithm()
		if err != nil {
			return err
		}
		if algID > -1 { // Negative numbers are used for second layer objects (COSE_Signature and COSE_recipient)
			return ErrInvalidAlg
		}

		digest, err := m.SignatureDigest(external, &signature)
		if err != nil {
			return err
		}

		signer := signers[i]
		if algID != signer.Algorithm() {
			return fmt.Errorf("Signer of type %+v cannot generate a signature of type %+v", signer.Algorithm(), algID)
		}

		// 3.  Call the signature creation algorithm passing in K (the key to
		//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
		//     value to sign).
		signatureBytes, err := signer.Sign(rand, digest)
		if err != nil {
			return err
		}

		// 4.  Place the resulting signature value in the 'signature' field of the array.
		m.Signatures[i].SignatureBytes = signatureBytes
	}
	return nil
}

// Verify verifies all signatures on the SignMessage returning nil for
// success or an error
func (m *SignMessage) Verify(external []byte, verifiers []MessageVerifier) (err error) {
	if m.Signatures == nil || len(m.Signatures) < 1 {
		return nil // Nothing to check
	}
	// TODO: take a func for a signature kid that returns a key or not?

	for i, signature := range m.Signatures {
		if signature.Headers == nil {
			return ErrNilSigHeader
		} else if signature.Headers.Protected == nil {
			return ErrNilSigProtectedHeaders
		} else if signature.SignatureBytes == nil || len(signature.SignatureBytes) < 1 {
			return fmt.Errorf("SignMessage signature %d missing signature bytes to verify", i)
		}
		// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected

		// TODO: dedup with alg in m.SignatureDigest()?
		algID, err := signature.Headers.Algorithm()
		if err != nil {
			return err
		}
		if algID > -1 { // Negative numbers are used for second layer objects (COSE_Signature and COSE_recipient)
			return ErrInvalidAlg
		}

		digest, err := m.SignatureDigest(external, &signature)
		if err != nil {
			return err
		}

		verifier := verifiers[i]
		// if err != nil {
		// 	return fmt.Errorf("Error finding a Verifier for signature %d", i)
		// }
		// if ecdsaKey, ok := verifier.publicKey.(ecdsa.PublicKey); ok {
		// 	curveBits := ecdsaKey.Curve.Params().BitSize
		// 	if alg.expectedKeyBitSize != curveBits {
		// 		return fmt.Errorf("Error verifying signature %d expected %d bit key, got %d bits instead", i, alg.expectedKeyBitSize, curveBits)
		// 	}
		// }

		// 3.  Call the signature creation algorithm passing in K (the key to
		//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
		//     value to sign).
		err = verifier.Verify(digest, signature.SignatureBytes)
		if err != nil {
			return err
		}
	}
	return
}
