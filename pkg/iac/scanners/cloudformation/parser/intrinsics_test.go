package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func Test_is_intrinsic_returns_expected(t *testing.T) {

	testCases := []struct {
		nodeTag        string
		expectedResult bool
	}{
		{
			nodeTag:        "!Ref",
			expectedResult: true,
		},
		{
			nodeTag:        "!Join",
			expectedResult: true,
		},
		{
			nodeTag:        "!Sub",
			expectedResult: true,
		},
		{
			nodeTag:        "!Equals",
			expectedResult: true,
		},
		{
			nodeTag:        "!Equal",
			expectedResult: false,
		},
	}

	for _, tt := range testCases {
		n := &yaml.Node{
			Tag: tt.nodeTag,
		}
		assert.Equal(t, tt.expectedResult, IsIntrinsicFunc(n))
	}

}
