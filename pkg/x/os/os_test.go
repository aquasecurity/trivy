package os

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetForTest resets global variables for testing
func resetForTest() {
	tempDir = ""
	initOnce = sync.Once{}
}

func TestTempDir(t *testing.T) {
	resetForTest()

	dir := TempDir()

	// Should contain process ID
	pid := os.Getpid()
	expected := filepath.Join(os.TempDir(), "trivy-"+strconv.Itoa(pid))
	assert.Equal(t, expected, dir)

	// Directory should exist
	_, err := os.Stat(dir)
	assert.NoError(t, err)

	t.Cleanup(func() {
		Cleanup()
		resetForTest()
	})
}

func TestCreateTemp(t *testing.T) {
	resetForTest()

	testCases := []struct {
		name    string
		pattern string
	}{
		{
			name:    "simple pattern",
			pattern: "test-",
		},
		{
			name:    "empty pattern",
			pattern: "",
		},
		{
			name:    "pattern with extension",
			pattern: "test-*.txt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with empty dir (should use process-specific dir)
			file, err := CreateTemp("", tc.pattern)
			require.NoError(t, err)
			defer file.Close()

			// File should exist
			_, err = os.Stat(file.Name())
			assert.NoError(t, err)

			// File should be in our temp directory
			pid := os.Getpid()
			expectedDir := filepath.Join(os.TempDir(), "trivy-"+strconv.Itoa(pid))
			assert.True(t, strings.HasPrefix(file.Name(), expectedDir))

			// Test with specific dir
			customDir := t.TempDir()
			file2, err := CreateTemp(customDir, tc.pattern)
			require.NoError(t, err)
			defer file2.Close()

			// File should exist and be in custom dir
			_, err = os.Stat(file2.Name())
			assert.NoError(t, err)
			assert.True(t, strings.HasPrefix(file2.Name(), customDir))
		})
	}

	t.Cleanup(func() {
		Cleanup()
		resetForTest()
	})
}

func TestMkdirTemp(t *testing.T) {
	resetForTest()

	testCases := []struct {
		name    string
		pattern string
	}{
		{
			name:    "simple pattern",
			pattern: "test-",
		},
		{
			name:    "empty pattern",
			pattern: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with empty dir (should use process-specific dir)
			dir, err := MkdirTemp("", tc.pattern)
			require.NoError(t, err)

			// Directory should exist
			_, err = os.Stat(dir)
			assert.NoError(t, err)

			// Directory should be in our temp directory
			pid := os.Getpid()
			expectedParent := filepath.Join(os.TempDir(), "trivy-"+strconv.Itoa(pid))
			assert.True(t, strings.HasPrefix(dir, expectedParent))

			// Test with specific dir
			customParent := t.TempDir()
			dir2, err := MkdirTemp(customParent, tc.pattern)
			require.NoError(t, err)

			// Directory should exist and be in custom parent
			_, err = os.Stat(dir2)
			assert.NoError(t, err)
			assert.True(t, strings.HasPrefix(dir2, customParent))
		})
	}

	t.Cleanup(func() {
		Cleanup()
		resetForTest()
	})
}

func TestCleanup(t *testing.T) {
	resetForTest()

	// Create a temp file
	file, err := CreateTemp("", "test-")
	require.NoError(t, err)
	filename := file.Name()
	file.Close()

	// File should exist
	_, err = os.Stat(filename)
	assert.NoError(t, err)

	// Cleanup
	err = Cleanup()
	assert.NoError(t, err)

	// File should be gone
	_, err = os.Stat(filename)
	assert.True(t, os.IsNotExist(err))

	// Directory should be gone
	dir := TempDir()
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err))

	resetForTest()
}
