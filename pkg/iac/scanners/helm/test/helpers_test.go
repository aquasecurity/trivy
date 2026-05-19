package test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertManifestEqual(t *testing.T, expectedPath, actual string) {
	t.Helper()
	expectedContent, err := os.ReadFile(expectedPath)
	require.NoError(t, err)
	assert.Equal(t, normalizeManifest(string(expectedContent)), normalizeManifest(actual))
}

// normalizeManifest normalizes line endings to LF and strips trailing newlines for cross-platform comparison.
func normalizeManifest(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimRight(s, "\n")
}
