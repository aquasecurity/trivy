package jdk_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/compare/jdk"
)

func TestComparer_MatchVersion(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		want       bool
	}{
		{name: "older minor vulnerable", version: "17.0.13+11", constraint: ">=17.0.6, <17.0.21.1+2", want: true},
		{name: "patched 4-part version", version: "17.0.21.1+2", constraint: "<17.0.21.1+2", want: false},
		{name: "same release lower build vulnerable", version: "17.0.13+9", constraint: "<17.0.13+11", want: true},
		{name: "same release equal build not vulnerable", version: "17.0.13+11", constraint: "<17.0.13+11", want: false},
		{name: "or constraint matches 21 line", version: "21.0.5+11", constraint: ">=17.0.0, <17.0.21.1+2 || >=21.0.0, <21.0.13.1+2", want: true},
		{name: "different major unaffected", version: "11.0.25+9", constraint: ">=17.0.0, <17.0.21.1+2", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (jdk.Comparer{}).MatchVersion(tt.version, tt.constraint)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
