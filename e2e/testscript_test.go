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
			"check-docker":  checkDockerCmd,
			"check-internet": checkInternetCmd,
		},
		Setup: func(env *testscript.Env) error {
			return setupTestEnvironment(env)
		},
		Condition: func(cond string) (bool, error) {
			return checkCondition(cond)
		},
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
		"TRIVY_CACHE_DIR="+filepath.Join(workDir, ".cache"),
		"TRIVY_TEMP_DIR="+filepath.Join(workDir, ".tmp"),
		"TRIVY_DB_DIGEST=sha256:1167abe9bf2e9affdfc189e07808914696d94ad39120a74585ae516d2ba0da4a",
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

func checkDockerCmd(ts *testscript.TestScript, neg bool, args []string) {
	cmd := exec.Command("docker", "version")
	err := cmd.Run()
	available := err == nil
	
	if neg {
		if available {
			ts.Fatalf("docker is available but expected it not to be")
		}
	} else {
		if !available {
			ts.Fatalf("docker is not available")
		}
	}
}

func checkInternetCmd(ts *testscript.TestScript, neg bool, args []string) {
	cmd := exec.Command("ping", "-c", "1", "google.com")
	err := cmd.Run()
	available := err == nil
	
	if neg {
		if available {
			ts.Fatalf("internet is available but expected it not to be")
		}
	} else {
		if !available {
			ts.Fatalf("internet is not available")
		}
	}
}

func setupTestEnvironment(env *testscript.Env) error {
	workDir, _ := os.Getwd()
	
	// Create necessary directories
	dirs := []string{".cache", ".tmp"}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(workDir, dir), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	
	return nil
}

func checkCondition(cond string) (bool, error) {
	switch cond {
	case "docker":
		cmd := exec.Command("docker", "version")
		err := cmd.Run()
		return err == nil, nil
	case "internet":
		cmd := exec.Command("ping", "-c", "1", "google.com")
		err := cmd.Run()
		return err == nil, nil
	default:
		return false, fmt.Errorf("unknown condition: %s", cond)
	}
}