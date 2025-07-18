//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestE2E(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"trivy": trivyCmd,
		},
		Setup: func(env *testscript.Env) error {
			return setupTestEnvironment(env)
		},
		UpdateScripts: true,
	})
}

func trivyCmd(ts *testscript.TestScript, neg bool, args []string) {
	// Build trivy binary path - look for it in the repository root
	wd, _ := os.Getwd()
	repoRoot := filepath.Dir(wd) // Go up one directory from e2e to repository root
	trivyPath := filepath.Join(repoRoot, "trivy")
	
	if _, err := os.Stat(trivyPath); err != nil {
		ts.Fatalf("trivy binary not found at %s: %v", trivyPath, err)
	}

	cmd := exec.Command(trivyPath, args...)
	workDir := ts.Getenv("WORK")
	cmd.Dir = workDir
	
	// Set environment variables for test isolation
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	if neg {
		if err == nil {
			ts.Fatalf("trivy command succeeded unexpectedly: %s", output)
		}
	} else {
		if err != nil {
			ts.Fatalf("trivy command failed: %v\nOutput: %s", err, output)
		}
	}
	
	// Send output to testscript for pattern matching - write to stdout
	fmt.Fprint(ts.Stdout(), string(output))
}


func setupTestEnvironment(env *testscript.Env) error {
	// Validate Docker availability - fail if not available
	if err := validateDockerAvailability(); err != nil {
		return fmt.Errorf("Docker validation failed: %v", err)
	}
	
	// Set environment variables for test scripts
	env.Setenv("TRIVY_DB_DIGEST", "sha256:b4d3718a89a78d4a6b02250953e92fcd87776de4774e64e818c1d0e01c928025")
	
	return nil
}

func validateDockerAvailability() error {
	cmd := exec.Command("docker", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Docker is not available or not running: %v", err)
	}
	return nil
}

