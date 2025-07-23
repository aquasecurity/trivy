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
	tempDirOnce = sync.OnceValues(initTempDir)
}

func TestTempDir(t *testing.T) {
	resetForTest()
	t.Cleanup(func() {
		_ = Cleanup()
		resetForTest()
	})

	got := TempDir()

	// Should contain process ID
	pid := os.Getpid()
	want := filepath.Join(os.TempDir(), "trivy-"+strconv.Itoa(pid))
	assert.Equal(t, want, got)

	// Directory should exist
	_, err := os.Stat(got)
	require.NoError(t, err)
}

func TestCreateTemp(t *testing.T) {
	resetForTest()

	tests := []struct {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test with empty dir (should use process-specific dir)
			file, err := CreateTemp("", tt.pattern) //nolint: usetesting
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = file.Close()
				_ = Cleanup()
				resetForTest()
			})

			// File should exist
			_, err = os.Stat(file.Name())
			require.NoError(t, err)

			// File should be in our temp directory
			pid := os.Getpid()
			expectedDir := filepath.Join(os.TempDir(), "trivy-"+strconv.Itoa(pid))
			assert.True(t, strings.HasPrefix(file.Name(), expectedDir))

			// Test with specific dir
			customDir := t.TempDir()
			file2, err := CreateTemp(customDir, tt.pattern)
			require.NoError(t, err)
			defer file2.Close()

			// File should exist and be in custom dir
			_, err = os.Stat(file2.Name())
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(file2.Name(), customDir))
		})
	}
}

func TestMkdirTemp(t *testing.T) {
	resetForTest()

	tests := []struct {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() {
				Cleanup()
				resetForTest()
			})

			// Test with empty dir (should use process-specific dir)
			dir, err := MkdirTemp("", tt.pattern) //nolint:usetesting
			require.NoError(t, err)

			// Directory should exist
			_, err = os.Stat(dir)
			require.NoError(t, err)

			// Directory should be in our temp directory
			wantParent := filepath.Join(os.TempDir(), "trivy-"+strconv.Itoa(os.Getpid()))
			assert.True(t, strings.HasPrefix(dir, wantParent))

			// Test with specific dir
			customParent := t.TempDir()
			dir2, err := MkdirTemp(customParent, tt.pattern) //nolint:usetesting
			require.NoError(t, err)

			// Directory should exist and be in custom parent
			_, err = os.Stat(dir2)
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(dir2, customParent))
		})
	}
}

func TestCleanup(t *testing.T) {
	resetForTest()
	t.Cleanup(func() {
		resetForTest()
	})

	// Create a temp file
	file, err := CreateTemp("", "test-") //nolint: usetesting
	require.NoError(t, err)
	filename := file.Name()
	require.NoError(t, file.Close())

	// Directory should exist
	dir := filepath.Join(os.TempDir(), "trivy-"+strconv.Itoa(os.Getpid()))
	_, err = os.Stat(dir)
	require.NoError(t, err)

	// File should exist
	_, err = os.Stat(filename)
	require.NoError(t, err)

	// Cleanup
	err = Cleanup()
	require.NoError(t, err)

	// File should be gone
	_, err = os.Stat(filename)
	require.ErrorIs(t, err, os.ErrNotExist)

	// Directory should be gone
	_, err = os.Stat(dir)
	assert.ErrorIs(t, err, os.ErrNotExist)
}
