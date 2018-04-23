
package cose

import (
	"fmt"
)


// Entry is a COSE Header name and tag e.g. {Tag="alg", Name=1}
type Entry struct {
	ID CommonHeaderID
	Name CommonHeaderName
}

var (
	Alg = Entry {
		Name: CommonHeaderNameAlg,
		ID: CommonHeaderIDAlg,
	}
	Crit = Entry {
		Name: CommonHeaderNameCrit,
		ID: CommonHeaderIDCrit,
	}
	ContentType = Entry {
		Name: CommonHeaderNameContentType,
		ID: CommonHeaderIDContentType,
	}
	KeyID = Entry {
		Name: CommonHeaderNameKeyID,
		ID: CommonHeaderIDKeyID,
	}
	IV = Entry {
		Name: CommonHeaderNameIV,
		ID: CommonHeaderIDIV,
	}
	PartialIV = Entry {
		Name: CommonHeaderNamePartialIV,
		ID: CommonHeaderIDPartialIV,
	}
	CounterSignature = Entry {
		Name: CommonHeaderNameCounterSignature,
		ID: CommonHeaderIDCounterSignature,
	}
	entries = []Entry{
		Alg,
		Crit,
		ContentType,
		KeyID,
		IV,
		PartialIV,
		CounterSignature,
	}
)

func init() {
	fmt.Printf("common headers: %+v\n", entries)
}
