//go:build e2e

package e2e

import (
	"flag"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

var update = flag.Bool("update", false, "update golden files")

func TestE2E(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(env *testscript.Env) error {
			return setupTestEnvironment(env)
		},
		UpdateScripts: *update,
	})
}

func setupTestEnvironment(env *testscript.Env) error {
	// Validate Docker availability - fail if not available
	if err := validateDockerAvailability(); err != nil {
		return fmt.Errorf("Docker validation failed: %v", err)
	}

	// Get GOPATH using go/build package (handles all defaults and environment resolution)
	gopath := build.Default.GOPATH

	// Add $GOPATH/bin to PATH
	gopathBin := filepath.Join(gopath, "bin")
	currentPath := env.Getenv("PATH")
	env.Setenv("PATH", gopathBin+string(os.PathListSeparator)+currentPath)

	// Set environment variables for test scripts
	env.Setenv("TRIVY_DB_DIGEST", "sha256:b4d3718a89a78d4a6b02250953e92fcd87776de4774e64e818c1d0e01c928025")
	// Disable VEX notice in test environment
	env.Setenv("TRIVY_DISABLE_VEX_NOTICE", "true")

	// Pass through DOCKER_HOST if set
	if dockerHost := os.Getenv("DOCKER_HOST"); dockerHost != "" {
		env.Setenv("DOCKER_HOST", dockerHost)
	}

	return nil
}

func validateDockerAvailability() error {
	cmd := exec.Command("docker", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Docker is not available or not running: %v", err)
	}
	return nil
}
