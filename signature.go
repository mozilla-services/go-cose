
package cose

import (
	"fmt"
)

// Signature represents a COSE signature with CDDL fragment:
//
// COSE_Signature =  [
//        Headers,
//        signature : bstr
// ]
//
// https://tools.ietf.org/html/rfc8152#section-4.1
type Signature struct {
	Headers        *Headers
	SignatureBytes []byte
}

// NewSignature returns a new COSE Signature with empty headers and
// nil signature bytes
func NewSignature() (s *Signature) {
	return &Signature{
		Headers: &Headers{
			Protected:   map[interface{}]interface{}{},
			Unprotected: map[interface{}]interface{}{},
		},
		SignatureBytes: nil,
	}
}

// Decode updates the signature inplace from its COSE serialization
func (s *Signature) Decode(o interface{}) {
	array, ok := o.([]interface{})
	if !ok {
		panic(fmt.Sprintf("error decoding sigArray; got %T", array))
	}
	if len(array) != 3 {
		panic(fmt.Sprintf("can only decode Signature with 3 items; got %d", len(array)))
	}

	err := s.Headers.Decode(array[0:2])
	if err != nil {
		panic(fmt.Sprintf("error decoding signature header: %+v", err))
	}

	signatureBytes, ok := array[2].([]byte)
	if !ok {
		panic(fmt.Sprintf("unable to decode COSE signature expecting decode from interface{}; got %T", array[2]))
	}
	s.SignatureBytes = signatureBytes
}
