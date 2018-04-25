package cose

import (
	"fmt"
	"log"
	"github.com/pkg/errors"
)


// Headers represents "two buckets of information that are not
// considered to be part of the payload itself, but are used for
// holding information about content, algorithms, keys, or evaluation
// hints for the processing of the layer."
//
// https://tools.ietf.org/html/rfc8152#section-3
//
// It is represented by CDDL fragments:
//
// Headers = (
//     protected : empty_or_serialized_map,
//     unprotected : header_map
// )
//
// header_map = {
//     Generic_Headers,
//     * label => values
// }
//
// empty_or_serialized_map = bstr .cbor header_map / bstr .size 0
//
// Generic_Headers = (
//        ? 1 => int / tstr,  ; algorithm identifier
//        ? 2 => [+label],    ; criticality
//        ? 3 => tstr / int,  ; content type
//        ? 4 => bstr,        ; key identifier
//        ? 5 => bstr,        ; IV
//        ? 6 => bstr,        ; Partial IV
//        ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
// )
//
type Headers struct {
	Protected   map[interface{}]interface{}
	Unprotected map[interface{}]interface{}
}

// MarshalBinary is called by codec to serialize Headers to CBOR bytes
func (h *Headers) MarshalBinary() (data []byte, err error) {
	// TODO: include unprotected?
	return h.EncodeProtected(), nil
}

// UnmarshalBinary is not implemented and panics
func (h *Headers) UnmarshalBinary(data []byte) (err error) {
	panic("Headers.UnmarshalBinary is not implemented")
}

// EncodeUnprotected returns compressed unprotected headers
func (h *Headers) EncodeUnprotected() (encoded map[interface{}]interface{}) {
	return CompressHeaders(h.Unprotected)
}

// EncodeProtected compresses and Marshals protected headers to bytes
// to encode as a CBOR bstr
// TODO: check for dups in maps
func (h *Headers) EncodeProtected() (bstr []byte) {
	if h == nil {
		panic("Cannot encode nil Headers")
	}

	if h.Protected == nil || len(h.Protected) < 1 {
		return []byte("")
	}

	encoded, err := Marshal(CompressHeaders(h.Protected))
	if err != nil {
		log.Fatalf("Marshal error of protected headers %s", err)
	}
	return encoded
}

// DecodeProtected Unmarshals and sets Headers.protected from an interface{}
func (h *Headers) DecodeProtected(o interface{}) (err error) {
	b, ok := o.([]byte)
	if !ok {
		return fmt.Errorf("error casting protected header bytes; got %T", o)
	}
	if len(b) <= 0 {
		return nil
	}

	protected, err := Unmarshal(b)
	if err != nil {
		return fmt.Errorf("error CBOR decoding protected header bytes; got %T", protected)
	}
	protectedMap, ok := protected.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("error casting protected to map; got %T", protected)
	}

	h.Protected = protectedMap
	return nil
}

// DecodeUnprotected Unmarshals and sets Headers.unprotected from an interface{}
func (h *Headers) DecodeUnprotected(o interface{}) (err error) {
	msgHeadersUnprotected, ok := o.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("error decoding unprotected header as map[interface {}]interface {}; got %T", o)
	}
	h.Unprotected = msgHeadersUnprotected
	return nil
}

// Decode loads a two element interface{} slice into Headers.protected
// and unprotected respectively
func (h *Headers) Decode(o []interface{}) (err error) {
	if len(o) != 2 {
		panic(fmt.Sprintf("can only decode headers from 2-item array; got %d", len(o)))
	}
	err = h.DecodeProtected(o[0])
	if err != nil {
		return err
	}
	err = h.DecodeUnprotected(o[1])
	if err != nil {
		return err
	}
	return nil
}

func printMap(headerMap map[interface {}] interface{}) {
	for k, v := range headerMap {
		fmt.Printf("map %T %+v : %T %+v\n", k, k, v, v)
	}
}


// getFromMap returns by label, int, or uint64 tag (as from Unmarshal)
func getFromMap(headerMap map[interface {}] interface{}, key interface{}) (val interface{}, err error) {
	switch k := key.(type) {
	case CommonHeaderID:
		v, ok := headerMap[k]
		fmt.Printf("chid k: %T %+v v: %T %+v ok: %+v\n", k, k, v, v, ok)
		if ok {
			val = v
			return
		}
	case string:
		v, ok := headerMap[k]
		fmt.Printf("str k: %T %+v v: %T %+v ok: %+v\n", k, k, v, v, ok)
		if ok {
			val = v
			return
		}
	// case int:
	// case int64:
	// case uint64:
	default:
		v, ok := headerMap[k]
		fmt.Printf("default k: %T %+v v: %T %+v ok: %+v\n", k, k, v, v, ok)
		if ok {
			val = v
			return
		}
	}
	err = errors.Wrapf(ErrKeyNotFound, "key %T %+v in %T %+v", key, key, headerMap, headerMap)
	return
}

// Get for a key returns a value (if any) from the headers It checks
// the protected then the unprotected headers and returns an error if
// the key is in both duplicate or neither of them
func (h *Headers) Get(key interface{}) (val interface {}, err error) {
	protectedVal, protectedErr := getFromMap(h.Protected, key)
	unprotectedVal, unprotectedErr := getFromMap(h.Unprotected, key)
	proMissing := errors.Cause(protectedErr) == ErrKeyNotFound
	unproMissing := errors.Cause(unprotectedErr) == ErrKeyNotFound

	// fmt.Printf("Get Vals prot %T %+v unprot %T %+v\n", protectedVal, protectedVal, unprotectedVal, unprotectedVal)
	// fmt.Printf("Get Errs prot %T %+v unprot %T %+v\n", protectedErr, protectedErr, unprotectedErr, unprotectedErr)

	if !(protectedErr == nil || proMissing) {
		err = protectedErr
		return
	}
	if !(unprotectedErr == nil || unproMissing) {
		err = unprotectedErr
		return
	}

	if proMissing && unproMissing {
	 	err = errors.Wrapf(ErrKeyNotFound, "Key not found in either map: %+v", key)
	} else if !proMissing && !unproMissing {
		err = fmt.Errorf("Ambiguous key found in protected and unprotected headers: %T %+v", key, key)
	} else if proMissing && !unproMissing {
		val = unprotectedVal
	} else if !proMissing && unproMissing {
		val = protectedVal
	}
	return
}

// Algorithm
func (h *Headers) Algorithm() (id AlgID, err error) {
	if h == nil {
		err = ErrAlgNotFound
		return
	}

	var (
		v interface{}
		types = []interface{}{
			CommonHeaderIDAlg,
			int(CommonHeaderIDAlg),
			uint64(CommonHeaderIDAlg),
		}
	)

	h.Protected = CompressHeaders(h.Protected)
	h.Unprotected = CompressHeaders(h.Unprotected)

	for _, t := range types {
		v, err = h.Get(t)
		// fmt.Printf("for t %T got V %T %+v err %+v\n", t, v, v, err)
		if err == nil {
			break
		}
	}
	switch aid := v.(type) {
	// CommonHeaderID:
	// 	id, ok = v.(AlgID)
	// 	if !ok {
	// 		err = ErrAlgNotFound
	// 	}
	case string:
		id, err = GetAlgIDByName(aid)
		if err != nil {
			err = ErrAlgNotFound
		}
	case uint64:
		id, err = getAlgIDByInt(int(aid))
		if err != nil {
			err = ErrAlgNotFound
		}
	case int64:
		id, err = getAlgIDByInt(int(aid))
		if err != nil {
			err = ErrAlgNotFound
		}
	case int:
		id, err = getAlgIDByInt(aid)
		if err != nil {
			err = ErrAlgNotFound
		}
	default:
		err = ErrAlgNotFound
	}
	fmt.Printf("landed on alg %T %+v\n", v, v)
	return
}

// CompressHeaders replaces string tags with their int values and alg
// tags with their IANA int values. Is the inverse of DecompressHeaders.
func CompressHeaders(headers map[interface{}]interface{}) (compressed map[interface{}]interface{}) {
	compressed = map[interface{}]interface{}{}

	for k, v := range headers {
		kstr, kok := k.(string)
		vstr, vok := v.(string)
		if kok {
			tag, err := GetCommonHeaderIDByName(kstr)
			if err == nil {
				k = tag
				if kstr == "alg" && vok {
					algID, err := GetAlgIDByName(vstr)
					// fmt.Printf("!! kstr %+v vstr %+v alg %+v\n", kstr, vstr, algID)
					if err == nil {
						v = algID
					}
				}
			}
		}
		compressed[k] = v
	}

	// fmt.Printf("!???! compressing:\n%+v\nto:\n%+v\n", headers, compressed)
	return compressed
}

// DecompressHeaders replaces int values with string tags and alg int
// values with their IANA labels. Is the inverse of CompressHeaders.
func DecompressHeaders(headers map[interface{}]interface{}) (decompressed map[interface{}]interface{}) {
	decompressed = map[interface{}]interface{}{}

	for k, v := range headers {
		kint, kok := k.(int)
		vint, vok := v.(CommonHeaderID)
		if kok {
			label, err := GetCommonHeaderNameByID(kint)
			if err == nil {
				k = label
				if vok && label == CommonHeaderNameAlg {
					algName, err := GetAlgNameByID(int64(vint))
					if err == nil {
						v = algName
					}
				}
			}
		}
		decompressed[k] = v
	}

	return decompressed
}
