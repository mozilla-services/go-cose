package cose

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

var CompressionTestCases = []struct {
	name         string
	input        map[interface{}]interface{}
	intermediate map[interface{}]interface{}
}{
	{
		"all empty",
		map[interface{}]interface{}{},
		map[interface{}]interface{}{},
	},
	{
		"all keys",
		map[interface{}]interface{}{
			"counter signature": []int{1, 2, -3},
			"Partial IV":        "foo",
			"alg":               true,
			"IV":                nil,
			"content type":      false,
			"kid":               -1,
			"crit":              true,
		},
		map[interface{}]interface{}{
			3: false,
			1: true,
			2: true,
			4: -1,
			5: nil,
			6: "foo",
			7: []int{1, 2, -3},
		},
	},
	{
		"unknown key",
		map[interface{}]interface{}{
			"unknown": -1,
		},
		map[interface{}]interface{}{
			"unknown": -1,
		},
	},
	{
		"known key wrong case \"ALG\"",
		map[interface{}]interface{}{
			"ALG": 1,
		},
		map[interface{}]interface{}{
			"ALG": 1,
		},
	},
	{
		"supported alg value \"ES256\" compressed",
		map[interface{}]interface{}{
			"alg": "ES256",
		},
		map[interface{}]interface{}{
			1: -7,
		},
	},
	{
		"supported alg value \"PS256\" compressed",
		map[interface{}]interface{}{
			"alg": "PS256",
		},
		map[interface{}]interface{}{
			1: -37,
		},
	},
}

func TestHeaderCompressionRoundTrip(t *testing.T) {
	for _, testCase := range CompressionTestCases {
		assert := assert.New(t)

		CompressHeaders(testCase.input)
		// assert.Equal(
		// 	testCase.intermediate,
		// 	testCase.input,
		// 	fmt.Sprintf("%s: header compression failed", testCase.name))

		assert.Equal(
			testCase.input,
			DecompressHeaders(testCase.input),
			fmt.Sprintf("%s: header compression-decompression roundtrip failed", testCase.name))
	}
}

func TestHeaderCompressionDoesNotDecompressUnknownTag(t *testing.T) {
	assert := assert.New(t)

	compressed := map[interface{}]interface{}{
		777: 1,
	}
	assert.Equal(
		compressed,
		DecompressHeaders(compressed),
		"header decompression modifies unknown tag")
}

func TestHeaderGetFromMap(t *testing.T) {
	assert := assert.New(t)

	m := map[interface{}]interface{}{777: 1}
	v, err := getFromMap(m, 777)
	assert.Nil(err)
	assert.Equal(v, 1)

	m = map[interface{}]interface{}{CommonHeaderIDAlg: 1}
	v, err = getFromMap(m, CommonHeaderIDAlg)
	assert.Nil(err)
	assert.Equal(v, 1)

	m = map[interface{}]interface{}{uint64(1) : int64(-7)}
	v, err = getFromMap(m, uint64(CommonHeaderIDAlg))
	assert.Nil(err)
	assert.Equal(v, int64(-7))
}

func TestHeaderGet(t *testing.T) {
	assert := assert.New(t)

	var (
		h Headers
		v interface{}
		err error
	)

	// duplicate key
	h = Headers{
		Protected: map[interface{}]interface{}{uint64(1) : int64(-7)},
		Unprotected: map[interface{}]interface{}{uint64(1) : int64(-7)},
	}
	v, err = h.Get(uint64(CommonHeaderIDAlg))
	assert.NotNil(err)

	// missing from both
	h = Headers{
		Protected: map[interface{}]interface{}{},
		Unprotected: map[interface{}]interface{}{},
	}
	v, err = h.Get(uint64(CommonHeaderIDAlg))
	assert.NotNil(err)


	// found in protected
	h = Headers{
		Protected: map[interface{}]interface{}{uint64(1) : int64(-7)},
		Unprotected: map[interface{}]interface{}{},
	}
	v, err = h.Get(uint64(CommonHeaderIDAlg))
	assert.Nil(err)
	assert.Equal(v, int64(-7))

	// found in unprotected
	h = Headers{
		Protected: map[interface{}]interface{}{},
		Unprotected: map[interface{}]interface{}{uint64(1) : int64(-7)},
	}
	v, err = h.Get(uint64(CommonHeaderIDAlg))
	assert.Nil(err)
	assert.Equal(v, int64(-7))
}

func TestHeaderAlgorithm(t *testing.T) {
	assert := assert.New(t)

	var (
		h Headers
		v interface{}
		err error
	)

	// from uint64
	h = Headers{
		Protected: map[interface{}]interface{}{uint64(1): int64(-7)},
		Unprotected: map[interface{}]interface{}{},
	}
	v, err = h.Algorithm()
	assert.Nil(err)
	assert.Equal(v, AlgES256ID)

}