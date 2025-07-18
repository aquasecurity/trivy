//go:build e2e

package e2e

import (
	"encoding/json"
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
			"trivy":         trivyCmd,
			"compare-json":  compareJSONCmd,
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
	cmd.Env = append(os.Environ(),
		"TMPDIR="+workDir,
	)

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

func compareJSONCmd(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("compare-json requires exactly 2 arguments")
	}

	file1, file2 := args[0], args[1]
	
	data1, err := os.ReadFile(file1)
	if err != nil {
		ts.Fatalf("failed to read %s: %v", file1, err)
	}
	
	data2, err := os.ReadFile(file2)
	if err != nil {
		ts.Fatalf("failed to read %s: %v", file2, err)
	}
	
	var result1, result2 interface{}
	if err := json.Unmarshal(data1, &result1); err != nil {
		ts.Fatalf("failed to parse JSON from %s: %v", file1, err)
	}
	
	if err := json.Unmarshal(data2, &result2); err != nil {
		ts.Fatalf("failed to parse JSON from %s: %v", file2, err)
	}
	
	// Simple comparison - in real implementation, you'd compare package counts, etc.
	if fmt.Sprintf("%v", result1) != fmt.Sprintf("%v", result2) {
		if !neg {
			ts.Fatalf("JSON files differ:\nFile1: %s\nFile2: %s", file1, file2)
		}
	} else {
		if neg {
			ts.Fatalf("JSON files are identical, but expected them to differ")
		}
	}
}


func setupTestEnvironment(env *testscript.Env) error {
	// Validate Docker availability - fail if not available
	if err := validateDockerAvailability(); err != nil {
		return fmt.Errorf("Docker validation failed: %v", err)
	}
	
	// Set environment variables for test scripts
	env.Setenv("TRIVY_DB_DIGEST", "sha256:1167abe9bf2e9affdfc189e07808914696d94ad39120a74585ae516d2ba0da4a")
	
	return nil
}

func validateDockerAvailability() error {
	cmd := exec.Command("docker", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Docker is not available or not running: %v", err)
	}
	return nil
}

