package os

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"golang.org/x/xerrors"
)

var (
	tempDirOnce = sync.OnceValues(initTempDir)
	// initialized tracks whether the temp directory has been created.
	// This is used by Cleanup() to avoid creating a directory just to delete it.
	initialized atomic.Bool
)

// initTempDir initializes the process-specific temp directory
func initTempDir() (string, error) {
	pid := os.Getpid()
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("trivy-%d", pid))

	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return "", xerrors.Errorf("failed to create temp dir: %w", err)
	}

	initialized.Store(true)
	return tempDir, nil
}

// CreateTemp creates a temporary file, using the process-specific directory when dir is empty
func CreateTemp(dir, pattern string) (*os.File, error) {
	// If dir is empty, use our process-specific temp directory
	if dir == "" {
		tempDir, err := tempDirOnce()
		if err != nil {
			return nil, err
		}
		dir = tempDir
	}

	return os.CreateTemp(dir, pattern) //nolint: gocritic
}

// MkdirTemp creates a temporary directory, using the process-specific directory as base when dir is empty
func MkdirTemp(dir, pattern string) (string, error) {
	// If dir is empty, use our process-specific temp directory
	if dir == "" {
		tempDir, err := tempDirOnce()
		if err != nil {
			return "", err
		}
		dir = tempDir
	}

	return os.MkdirTemp(dir, pattern) //nolint: gocritic
}

// TempDir returns the process-specific temp directory path
func TempDir() string {
	tempDir, err := tempDirOnce()
	if err != nil {
		return os.TempDir() // fallback
	}
	return tempDir
}

// Cleanup removes the entire process-specific temp directory
// Note: On Windows, directory deletion may fail if files are still open
func Cleanup() error {
	// If temp dir was never initialized, nothing to clean up
	if !initialized.Load() {
		return nil
	}
	
	tempDir, err := tempDirOnce()
	if err != nil || tempDir == "" {
		return nil
	}
	return os.RemoveAll(tempDir)
}
