//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
)

// TestConfiguration tests the configuration of the CLI flags, environmental variables, and config file.
//
// IMPORTANT: Golden files used in this test cannot be updated with the -update flag
// because the configuration test may apply specific settings that modify the output.
// If golden files need to be updated, they should be generated from TestRepository.
//
// All golden files used in TestConfiguration MUST also be used in TestRepository
// to ensure they can be properly updated when needed.
func TestConfiguration(t *testing.T) {
	type args struct {
		input      string
		flags      map[string]string
		envs       map[string]string
		configFile string
	}
	type test struct {
		name    string
		args    args
		golden  string
		wantErr string
	}

	tests := []test{
		{
			name: "skip files",
			args: args{
				input: "testdata/fixtures/repo/gomod",
				flags: map[string]string{
					"scanners":   "vuln",
					"skip-files": "path/to/dummy,testdata/fixtures/repo/gomod/submod2/go.mod",
				},
				envs: map[string]string{
					"TRIVY_SCANNERS":   "vuln",
					"TRIVY_SKIP_FILES": "path/to/dummy,testdata/fixtures/repo/gomod/submod2/go.mod",
				},
				configFile: `---
scan:
  scanners:
    - vuln
  skip-files:
    - path/to/dummy
    - testdata/fixtures/repo/gomod/submod2/go.mod
`,
			},
			golden: goldenGoModSkip,
		},
		{
			name: "dockerfile with custom file pattern",
			args: args{
				input: "testdata/fixtures/repo/dockerfile_file_pattern",
				flags: map[string]string{
					"scanners":      "misconfig",
					"file-patterns": "dockerfile:Customfile",
					"namespaces":    "testing",
				},
				envs: map[string]string{
					"TRIVY_SCANNERS":      "misconfig",
					"TRIVY_FILE_PATTERNS": "dockerfile:Customfile",
					"TRIVY_NAMESPACES":    "testing",
				},
				configFile: `---
scan:
  scanners:
    - misconfig
  file-patterns:
    - dockerfile:Customfile
rego:
  skip-policy-update: true
  namespaces: 
    - testing
`,
			},
			golden: goldenDockerfileFilePattern,
		},
		{
			name: "key alias", // "--scanners" vs "--security-checks"
			args: args{
				input: "testdata/fixtures/repo/gomod",
				flags: map[string]string{
					"security-checks": "vuln",
				},
				envs: map[string]string{
					"TRIVY_SECURITY_CHECKS": "vuln",
				},
				configFile: `---
scan:
  security-checks:
    - vuln
`,
			},
			golden: goldenGoMod,
		},
		{
			name: "value alias", // "--scanners vuln" vs "--scanners vulnerability"
			args: args{
				input: "testdata/fixtures/repo/gomod",
				flags: map[string]string{
					"scanners": "vulnerability",
				},
				envs: map[string]string{
					"TRIVY_SCANNERS": "vulnerability",
				},
				configFile: `---
scan:
  scanners:
    - vulnerability
`,
			},
			golden: goldenGoMod,
		},
		{
			name: "invalid value",
			args: args{
				input: "testdata/fixtures/repo/gomod",
				flags: map[string]string{
					"scanners": "vulnerability",
					"severity": "CRITICAL,INVALID",
				},
				envs: map[string]string{
					"TRIVY_SCANNERS": "vulnerability",
					"TRIVY_SEVERITY": "CRITICAL,INVALID",
				},
				configFile: `---
scan:
  scanners:
    - vulnerability
severity:
  - CRITICAL
  - INVALID
`,
			},
			wantErr: `invalid argument "[CRITICAL INVALID]" for "--severity" flag`,
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	// Disable Go license detection
	t.Setenv("GOPATH", cacheDir)

	for _, tt := range tests {
		command := "repo"

		t.Run(tt.name+" with CLI flags", func(t *testing.T) {
			osArgs := []string{
				"--format",
				"json",
				"--list-all-pkgs=false",
				"--cache-dir",
				cacheDir,
				"--skip-db-update",
				"--skip-policy-update",
				command,
				tt.args.input,
			}
			for key, value := range tt.args.flags {
				osArgs = append(osArgs, "--"+key, value)
			}

			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			osArgs = append(osArgs, "--output", outputFile)

			runTest(t, osArgs, tt.golden, outputFile, types.FormatJSON, runOptions{
				wantErr:  tt.wantErr,
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				update:   false, // Golden files should be updated via TestRepository, not TestConfiguration
			})
		})

		t.Run(tt.name+" with environmental variables", func(t *testing.T) {
			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")

			t.Setenv("TRIVY_OUTPUT", outputFile)
			t.Setenv("TRIVY_FORMAT", "json")
			t.Setenv("TRIVY_LIST_ALL_PKGS", "false")
			t.Setenv("TRIVY_CACHE_DIR", cacheDir)
			t.Setenv("TRIVY_SKIP_DB_UPDATE", "true")
			t.Setenv("TRIVY_SKIP_POLICY_UPDATE", "true")
			for key, value := range tt.args.envs {
				t.Setenv(key, value)
			}

			osArgs := []string{
				command,
				tt.args.input,
			}

			runTest(t, osArgs, tt.golden, outputFile, types.FormatJSON, runOptions{
				wantErr:  tt.wantErr,
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				update:   false, // Golden files should be updated via TestRepository, not TestConfiguration
			})
		})

		t.Run(tt.name+" with config file", func(t *testing.T) {
			// Set up the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")

			configFile := tt.args.configFile
			configFile += fmt.Sprintf(`
format: json
list-all-pkgs: false
output: %s
cache:
  dir: %s
db:
  skip-update: true
`, outputFile, cacheDir)

			configPath := filepath.Join(t.TempDir(), "trivy.yaml")
			err := os.WriteFile(configPath, []byte(configFile), 0o444)
			require.NoError(t, err)

			osArgs := []string{
				command,
				"--config",
				configPath,
				tt.args.input,
			}

			runTest(t, osArgs, tt.golden, outputFile, types.FormatJSON, runOptions{
				wantErr:  tt.wantErr,
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				update:   false, // Golden files should be updated via TestRepository, not TestConfiguration
			})
		})
	}
}
