package os

import (
	"os"
	"path/filepath"
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

	// Should be under system temp dir with trivy- prefix
	assert.True(t, strings.HasPrefix(got, filepath.Join(os.TempDir(), "trivy-")))

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

			// File should be under a trivy- prefixed temp directory
			assert.True(t, strings.HasPrefix(file.Name(), filepath.Join(os.TempDir(), "trivy-")))

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

			// Directory should be under a trivy- prefixed temp directory
			assert.True(t, strings.HasPrefix(dir, filepath.Join(os.TempDir(), "trivy-")))

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

	// Get the trivy temp directory (parent of the file)
	dir := TempDir()
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

func TestTempDirUniqueness(t *testing.T) {
	// Each call to initTempDir should produce a unique directory
	resetForTest()
	dir1 := TempDir()
	t.Cleanup(func() {
		_ = os.RemoveAll(dir1)
	})

	// Reset and get another dir
	resetForTest()
	initialized.Store(false)
	dir2 := TempDir()
	t.Cleanup(func() {
		_ = os.RemoveAll(dir2)
		resetForTest()
	})

	assert.NotEqual(t, dir1, dir2, "two separate initializations should produce different directories")
}
