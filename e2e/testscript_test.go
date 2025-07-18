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
			"trivy":        trivyCmd,
			"start-proxy":  startProxyCmd,
			"stop-proxy":   stopProxyCmd,
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
	
	// Validate mitmdump availability for proxy tests - fail if not available
	if err := validateMitmdumpAvailability(); err != nil {
		return fmt.Errorf("mitmdump validation failed: %v", err)
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

func validateMitmdumpAvailability() error {
	// Check if Docker is available (already validated in validateDockerAvailability)
	// Check if mitmproxy image is available or can be pulled
	cmd := exec.Command("docker", "image", "inspect", "mitmproxy/mitmproxy:latest")
	if err := cmd.Run(); err != nil {
		// Try to pull the image
		pullCmd := exec.Command("docker", "pull", "mitmproxy/mitmproxy:latest")
		if pullErr := pullCmd.Run(); pullErr != nil {
			return fmt.Errorf("mitmproxy Docker image not available and cannot be pulled: %v", pullErr)
		}
	}
	return nil
}

func startProxyCmd(ts *testscript.TestScript, neg bool, args []string) {
	port := "8080"
	if len(args) > 0 {
		port = args[0]
	}
	
	workDir := ts.Getenv("WORK")
	containerName := "mitmproxy-e2e-test"
	
	// Remove any existing container with the same name
	stopCmd := exec.Command("docker", "rm", "-f", containerName)
	stopCmd.Run() // Ignore errors if container doesn't exist
	
	// Start mitmproxy container
	cmd := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-p", port+":8080",
		"-v", workDir+"/.mitmproxy:/home/mitmproxy/.mitmproxy",
		"mitmproxy/mitmproxy:latest",
		"mitmdump", "--listen-port", "8080", "--set", "confdir=/home/mitmproxy/.mitmproxy")
	
	output, err := cmd.CombinedOutput()
	if neg {
		if err == nil {
			ts.Fatalf("start-proxy command succeeded unexpectedly: %s", output)
		}
	} else {
		if err != nil {
			ts.Fatalf("start-proxy command failed: %v\nOutput: %s", err, output)
		}
		
		// Wait for proxy to be ready
		waitCmd := exec.Command("sleep", "3")
		waitCmd.Run()
	}
}

func stopProxyCmd(ts *testscript.TestScript, neg bool, args []string) {
	containerName := "mitmproxy-e2e-test"
	
	cmd := exec.Command("docker", "rm", "-f", containerName)
	output, err := cmd.CombinedOutput()
	
	if neg {
		if err == nil {
			ts.Fatalf("stop-proxy command succeeded unexpectedly: %s", output)
		}
	} else {
		if err != nil {
			ts.Fatalf("stop-proxy command failed: %v\nOutput: %s", err, output)
		}
	}
}

