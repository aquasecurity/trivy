//go:build !windows

package daemon_test

const (
	testContextHost = "unix:///tmp/test-context.sock"

	// Test socket paths for Unix systems
	testFlagHost = "unix:///tmp/flag-docker.sock"
	testEnvHost  = "unix:///tmp/env-docker.sock"
)
