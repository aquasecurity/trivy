package os

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

var tempDirOnce = sync.OnceValues(initTempDir)

// initTempDir initializes the process-specific temp directory
func initTempDir() (string, error) {
	pid := os.Getpid()
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("trivy-%d", pid))

	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		return "", xerrors.Errorf("failed to create temp dir: %w", err)
	}

	log.Debug("Created process-specific temp directory", log.String("path", tempDir))
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
		log.Debug("Failed to get process-specific temp directory, falling back to system temp", log.Err(err))
		return os.TempDir() // fallback
	}
	return tempDir
}

// Cleanup removes the entire process-specific temp directory
func Cleanup() error {
	tempDir, err := tempDirOnce()
	if err != nil || tempDir == "" {
		return nil
	}
	log.Debug("Cleaning up temp directory", log.String("path", tempDir))
	return os.RemoveAll(tempDir)
}
