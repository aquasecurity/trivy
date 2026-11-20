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
		{name: "ea build orders before ga build with same number", version: "17.0.13-ea+8", constraint: "<17.0.13+8", want: true},
		{name: "ea build with higher build number still orders before ga", version: "17.0.13-ea+99", constraint: "<17.0.13+1", want: true},
		{name: "ea build orders before ga without build", version: "17.0.13-ea+8", constraint: "<17.0.13", want: true},
		{name: "ga build does not order before ea build", version: "17.0.13+8", constraint: "<17.0.13-ea+8", want: false},
		{name: "ea build compares build number when pre matches", version: "17.0.13-ea+8", constraint: "<17.0.13-ea+11", want: true},
		{name: "ea without build orders before ea with build", version: "17.0.13-ea", constraint: "<17.0.13-ea+8", want: true},
		{name: "legacy 8 ea orders before 8.0 ga", version: "8.0-ea", constraint: "<8.0", want: true},
		{name: "numeric pre-release compares numerically", version: "17.0.13-2", constraint: "<17.0.13-10", want: true},
		{name: "numeric pre-release orders before alphanumeric pre-release", version: "17.0.13-10", constraint: "<17.0.13-ea", want: true},
		{name: "alphanumeric pre-release compares lexicographically", version: "17.0.13-beta", constraint: "<17.0.13-ea", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (jdk.Comparer{}).MatchVersion(tt.version, tt.constraint)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
