
package cose

// CommonHeaderName is a COSE Header name or map label / key e.g. "alg"
//
// From the Name column in: https://tools.ietf.org/html/rfc8152#section-3.1
type CommonHeaderName string

// CommonHeaderID is a COSE Header tag or map value e.g. 1
//
// From the Label column in: https://tools.ietf.org/html/rfc8152#section-3.1
type CommonHeaderID int

const (
	_ = iota
	CommonHeaderIDAlg CommonHeaderID = iota // 1
	CommonHeaderIDCrit CommonHeaderID = iota // 2
	CommonHeaderIDContentType CommonHeaderID = iota // 3
	CommonHeaderIDKeyID CommonHeaderID = iota // 4
	CommonHeaderIDIV CommonHeaderID = iota // 5
	CommonHeaderIDPartialIV CommonHeaderID = iota // 6
	CommonHeaderIDCounterSignature CommonHeaderID = iota // 7

	CommonHeaderNameAlg CommonHeaderName = "alg"
	CommonHeaderNameCrit CommonHeaderName = "crit"
	CommonHeaderNameContentType CommonHeaderName = "content type"
	CommonHeaderNameKeyID CommonHeaderName = "kid"
	CommonHeaderNameIV CommonHeaderName = "IV"
	CommonHeaderNamePartialIV CommonHeaderName = "Partial IV"
	CommonHeaderNameCounterSignature CommonHeaderName = "counter signature"
)

// GetCommonHeaderNameByID returns the CBOR label for the map CommonHeaderID or int
func GetCommonHeaderNameByID(tag interface{}) (name CommonHeaderName, err error) {
	switch t := tag.(type) {
	case CommonHeaderID:
		return getNameByCommonHeaderID(t)
	case int:
		return getNameByIntTag(t)
	default:
		err = ErrMissingCOSETagForTag
	}
	return
}

func getNameByCommonHeaderID(tag CommonHeaderID) (name CommonHeaderName, err error) {
	switch tag {
	case CommonHeaderIDAlg:
		name = CommonHeaderNameAlg
	case CommonHeaderIDCrit:
		name = CommonHeaderNameCrit
	case CommonHeaderIDContentType:
		name = CommonHeaderNameContentType
	case CommonHeaderIDKeyID:
		name = CommonHeaderNameKeyID
	case CommonHeaderIDIV:
		name = CommonHeaderNameIV
	case CommonHeaderIDPartialIV:
		name = CommonHeaderNamePartialIV
	case CommonHeaderIDCounterSignature:
		name = CommonHeaderNameCounterSignature
	default:
		err = ErrMissingCOSETagForTag
	}
	return
}

func getNameByIntTag(tag int) (name CommonHeaderName, err error) {
	switch tag {
	case 1:
		name = CommonHeaderNameAlg
	case 2:
		name = CommonHeaderNameCrit
	case 3:
		name = CommonHeaderNameContentType
	case 4:
		name = CommonHeaderNameKeyID
	case 5:
		name = CommonHeaderNameIV
	case 6:
		name = CommonHeaderNamePartialIV
	case 7:
		name = CommonHeaderNameCounterSignature
	default:
		err = ErrMissingCOSETagForTag
	}
	return
}

// GetCommonHeaderIDByName returns the CBOR tag for the map label
func GetCommonHeaderIDByName(name interface{}) (tag CommonHeaderID, err error) {
	switch n := name.(type) {
	case CommonHeaderName:
		return getIDByCommonHeaderName(n)
	case string:
		return getIDByStringName(n)
	default:
		err = ErrMissingCOSETagForLabel
	}
	return
}

func getIDByCommonHeaderName(name CommonHeaderName) (tag CommonHeaderID, err error) {
	switch name {
	case CommonHeaderNameAlg:
		tag = CommonHeaderIDAlg
	case CommonHeaderNameCrit:
		tag = CommonHeaderIDCrit
	case CommonHeaderNameContentType:
		tag = CommonHeaderIDContentType
	case CommonHeaderNameKeyID:
		tag = CommonHeaderIDKeyID
	case CommonHeaderNameIV:
		tag = CommonHeaderIDIV
	case CommonHeaderNamePartialIV:
		tag = CommonHeaderIDPartialIV
	case CommonHeaderNameCounterSignature:
		tag = CommonHeaderIDCounterSignature
	default:
		err = ErrMissingCOSETagForLabel
	}
	return
}

func getIDByStringName(name string) (tag CommonHeaderID, err error) {
	switch name {
	case "alg":
		tag = CommonHeaderIDAlg
	case "crit":
		tag = CommonHeaderIDCrit
	case "content type":
		tag = CommonHeaderIDContentType
	case "kid":
		tag = CommonHeaderIDKeyID
	case "IV":
		tag = CommonHeaderIDIV
	case "Partial IV":
		tag = CommonHeaderIDPartialIV
	case "counter signature":
		tag = CommonHeaderIDCounterSignature
	default:
		err = ErrMissingCOSETagForLabel
	}
	return
}
