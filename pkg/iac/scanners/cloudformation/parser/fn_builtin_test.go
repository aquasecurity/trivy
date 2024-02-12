package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_cidr_generator(t *testing.T) {

	original := &Property{
		ctx:     nil,
		name:    "cidr",
		comment: "",
		Inner: PropertyInner{
			Type:  "",
			Value: nil,
		},
	}

	ranges, err := calculateCidrs("10.1.0.0/16", 4, 4, original)
	require.Nil(t, err)
	require.Len(t, ranges, 4)

	results := make(map[int]string)
	for i, property := range ranges {
		value := property.AsString()
		results[i] = value
	}

	assert.Equal(t, "10.1.0.0/20", results[0])
	assert.Equal(t, "10.1.16.0/20", results[1])
	assert.Equal(t, "10.1.32.0/20", results[2])
	assert.Equal(t, "10.1.48.0/20", results[3])
}

func Test_cidr_generator_8_bits(t *testing.T) {
	original := &Property{
		ctx:     nil,
		name:    "cidr",
		comment: "",
		Inner: PropertyInner{
			Type:  "",
			Value: nil,
		},
	}

	ranges, err := calculateCidrs("10.1.0.0/16", 4, 8, original)
	require.Nil(t, err)
	require.Len(t, ranges, 4)

	results := make(map[int]string)
	for i, property := range ranges {
		value := property.AsString()
		results[i] = value
	}

	assert.Equal(t, "10.1.0.0/24", results[0])
	assert.Equal(t, "10.1.1.0/24", results[1])
	assert.Equal(t, "10.1.2.0/24", results[2])
	assert.Equal(t, "10.1.3.0/24", results[3])
}
