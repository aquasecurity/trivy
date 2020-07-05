package utils

import (
	"testing"

	"github.com/knqyf263/go-version"
	"github.com/stretchr/testify/assert"
)

func TestMatchVersions2(t *testing.T) {
	testCases := []struct {
		name           string
		currentVersion string
		rangeVersion   []string
		expectedCheck  bool
	}{
		{
			name:           "pass: expect true when os/machine is in pre-release",
			currentVersion: "1.9.25-x86-mingw32",
			rangeVersion:   []string{`>= 1.9.24`},
			expectedCheck:  true,
		},
		{
			name:           "pass: expect true when language is in pre-release",
			currentVersion: "1.8.6-java",
			rangeVersion:   []string{`~> 1.5.5`, `~> 1.6.8`, `>= 1.7.7`},
			expectedCheck:  true,
		},
		{
			name:           "expect false",
			currentVersion: "1.9.23-x86-mingw32",
			rangeVersion:   []string{`>= 1.9.24`},
			expectedCheck:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := version.NewVersion(tc.currentVersion)
			assert.Nil(t, err)
			match := MatchVersions(v, tc.rangeVersion)
			assert.Equal(t, tc.expectedCheck, match)
		})
	}
}
