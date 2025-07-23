//go:build e2e

package e2e

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

var update = flag.Bool("update", false, "update golden files")

func TestE2E(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(env *testscript.Env) error {
			return setupTestEnvironment(t, env)
		},
		UpdateScripts: *update,
	})
}

func buildTrivy(t *testing.T) string {
	t.Helper()

	tmp := t.TempDir() // Test-specific directory
	exe := filepath.Join(tmp, "trivy")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}

	cmd := exec.Command("go", "build",
		"-o", exe,
		"../cmd/trivy",
	)
	// Prevent environment pollution
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Trivy build failed: %v\n%s", err, out)
	}
	return exe
}

func setupTestEnvironment(t *testing.T, env *testscript.Env) error {
	// Validate Docker availability - fail if not available
	if err := validateDockerAvailability(); err != nil {
		return fmt.Errorf("Docker validation failed: %v", err)
	}

	// Build Trivy once and cache it
	trivyExe := buildTrivy(t)

	// Add directory containing trivy to PATH
	env.Setenv("PATH", filepath.Dir(trivyExe)+string(os.PathListSeparator)+env.Getenv("PATH"))

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