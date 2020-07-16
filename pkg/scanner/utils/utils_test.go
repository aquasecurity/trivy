package utils

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchVersions(t *testing.T) {
	testCases := []struct {
		name           string
		currentVersion string
		rangeVersion   []string
		expectedCheck  bool
	}{
		{
			name:           "pass: expect true when os/machine is in version string",
			currentVersion: "1.9.25-x86-mingw32",
			rangeVersion:   []string{`>= 1.9.24`},
			expectedCheck:  true,
		},
		{
			name:           "pass: expect true when language is in version string",
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
		{
			// passes if (>= 1.2.3, < 2.0.0)
			name:           "expect false",
			currentVersion: "1.2.4",
			rangeVersion:   []string{`^1.2.3`},
			expectedCheck:  true,
		},
		{
			// passes if (>= 1.2.3, < 2.0.0)
			name:           "expect false",
			currentVersion: "2.0.0",
			rangeVersion:   []string{`^1.2.3`},
			expectedCheck:  false,
		},
		{
			// passes if (>= 2.0.18, < 3.0.0) || (>= 3.1.16, < 4.0.0) || (>= 4.0.8, < 5.0.0) || ( >=5.0.0,<6.0.0)
			name:           "expect false",
			currentVersion: "3.1.16",
			rangeVersion:   []string{`^2.0.18 || ^3.1.6 || ^4.0.8 || ^5.0.0-beta.5`},
			expectedCheck:  true,
		},
		{
			// passes if (>= 2.0.18, < 3.0.0) || (>= 3.1.16, < 4.0.0) || (>= 4.0.8, < 5.0.0) || ( >=5.0.0,<6.0.0)
			name:           "expect false",
			currentVersion: "6.0.0",
			rangeVersion:   []string{`^2.0.18 || ^3.1.6 || ^4.0.8 || ^5.0.0-beta.5`},
			expectedCheck:  false,
		},
		{
			// passes if (>= 2.0.18, < 3.0.0) || (>= 3.1.16, < 4.0.0) || (>= 4.0.8, < 5.0.0) || ( >=5.0.0,<6.0.0)
			name:           "expect false",
			currentVersion: "5.0.0-beta.5",
			rangeVersion:   []string{`^2.0.18 || ^3.1.6 || ^4.0.8 || ^5.0.0-beta.5`},
			expectedCheck:  true,
		},
		{
			// Ruby GEM with more dots
			name:           "expect false",
			currentVersion: "1.10.9-java",
			rangeVersion:   []string{`>= 1.6.7.1`},
			expectedCheck:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := semver.NewVersion(tc.currentVersion)
			require.NoError(t, err)
			match := MatchVersions(v, tc.rangeVersion)
			assert.Equal(t, tc.expectedCheck, match)
		})
	}
}

func TestFormatPatchVersio(t *testing.T) {
	testCases := []struct {
		name            string
		currentVersion  string
		expectedVersion string
	}{
		{
			name:            "patch with no dots should return version should be unchanged",
			currentVersion:  "1.2.3-beta",
			expectedVersion: "1.2.3-beta",
		},
		{
			name:            "patch with dots after non-integer patch version should be unchanged",
			currentVersion:  "1.2.3-beta.1",
			expectedVersion: "1.2.3-beta.1",
		},
		{
			name:            "patch with dots after integer patch version should append dash and join rest versions parts",
			currentVersion:  "1.2.3.4",
			expectedVersion: "1.2.3-4",
		},
		{
			name:            "patch with dots after integer patch version should append dash and join extra versions parts",
			currentVersion:  "1.2.3.4.5",
			expectedVersion: "1.2.3-4.5",
		},
		{
			name:            "unchanged case",
			currentVersion:  "1.2.3.4-5",
			expectedVersion: "1.2.3-4-5",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatPatchVersion(tc.currentVersion)
			assert.Equal(t, tc.expectedVersion, got)
		})
	}
}
