package os

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

var (
	tempDir  string
	initOnce sync.Once
)

// initTempDir initializes the process-specific temp directory
func initTempDir() error {
	pid := os.Getpid()
	tempDir = filepath.Join(os.TempDir(), fmt.Sprintf("trivy-%d", pid))

	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return err
	}

	// Setup signal handler for cleanup
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		Cleanup()
		// Let the signal continue - don't call os.Exit(0) here
		// This allows other handlers to run and proper cleanup to occur
	}()

	return nil
}

// CreateTemp creates a temporary file, using the process-specific directory when dir is empty
func CreateTemp(dir, pattern string) (*os.File, error) {
	// If dir is empty, use our process-specific temp directory
	if dir == "" {
		var err error
		initOnce.Do(func() {
			err = initTempDir()
		})
		if err != nil {
			return nil, err
		}
		dir = tempDir
	}

	return os.CreateTemp(dir, pattern)
}

// MkdirTemp creates a temporary directory, using the process-specific directory as base when dir is empty
func MkdirTemp(dir, pattern string) (string, error) {
	// If dir is empty, use our process-specific temp directory
	if dir == "" {
		var err error
		initOnce.Do(func() {
			err = initTempDir()
		})
		if err != nil {
			return "", err
		}
		dir = tempDir
	}

	return os.MkdirTemp(dir, pattern)
}

// TempDir returns the process-specific temp directory path
func TempDir() string {
	var err error
	initOnce.Do(func() {
		err = initTempDir()
	})
	if err != nil {
		return os.TempDir() // fallback
	}
	return tempDir
}

// Cleanup removes the entire process-specific temp directory
func Cleanup() error {
	if tempDir == "" {
		return nil
	}
	return os.RemoveAll(tempDir)
}
