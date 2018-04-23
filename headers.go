package cose

import (
	"fmt"
	"log"
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

// TODO: check for duplicates

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
					alg, err := GetAlgByName(vstr)
					if err == nil {
						v = alg.Value
					}
				}
			}
		}
		compressed[k] = v
	}

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
					alg, err := GetAlgByValue(int64(vint))
					if err == nil {
						v = alg.Name
					}
				}
			}
		}
		decompressed[k] = v
	}

	return decompressed
}

func getAlgFromMap(headerMap map[interface {}] interface{}) (alg *Algorithm, err error) {
	fmt.Printf("!???! hmap %T %+v\n", headerMap, headerMap)

	if tmp, ok := headerMap[CommonHeaderNameAlg]; ok {
		if algName, ok := tmp.(CommonHeaderName); ok {
			fmt.Printf("!!!! %+v", algName)
		}
	} else if tmp, ok := headerMap[CommonHeaderIDAlg]; ok {
		if algValue, ok := tmp.(CommonHeaderID); ok {
			fmt.Printf("??!! %+v", algValue)
		}
	} else if tmp, ok := headerMap["alg"]; ok {
		if algName, ok := tmp.(string); ok {
			alg, err = GetAlgByName(algName)
			if err != nil {
				return nil, err
			}
			return alg, nil
		}
	} else if tmp, ok := headerMap[uint64(1)]; ok {
		if algValue, ok := tmp.(int64); ok {
			alg, err = GetAlgByValue(algValue)
			if err != nil {
				return nil, err
			}
			return alg, nil
		}
	} else if tmp, ok := headerMap[int(1)]; ok {
		if algValue, ok := tmp.(int); ok {
			alg, err = GetAlgByValue(int64(algValue))
			if err != nil {
				return nil, err
			}
			return alg, nil
		}
	}
	return nil, ErrAlgNotFound
}

// getAlg returns the alg by label, int, or uint64 tag (as from Unmarshal)
func getAlg(h *Headers) (alg *Algorithm, err error) {
	return getAlgFromMap(h.Protected)
}
