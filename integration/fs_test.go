//go:build integration
// +build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestFilesystem(t *testing.T) {
	type args struct {
		scanner        types.Scanner
		severity       []string
		ignoreIDs      []string
		policyPaths    []string
		namespaces     []string
		listAllPkgs    bool
		input          string
		secretConfig   string
		filePatterns   []string
		helmSet        []string
		helmValuesFile []string
		skipFiles      []string
		skipDirs       []string
		ignoreErrors   []string
		command        string
		format         string
	}
	tests := []struct {
		name   string
		args   args
		golden string
	}{
		{
			name: "gomod",
			args: args{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/fs/gomod",
			},
			golden: "testdata/gomod.json.golden",
		},
		{
			name: "gomod with skip files",
			args: args{
				scanner:   types.VulnerabilityScanner,
				input:     "testdata/fixtures/fs/gomod",
				skipFiles: []string{"testdata/fixtures/fs/gomod/submod2/go.mod"},
			},
			golden: "testdata/gomod-skip.json.golden",
		},
		{
			name: "gomod with skip dirs",
			args: args{
				scanner:  types.VulnerabilityScanner,
				input:    "testdata/fixtures/fs/gomod",
				skipDirs: []string{"testdata/fixtures/fs/gomod/submod2"},
			},
			golden: "testdata/gomod-skip.json.golden",
		},
		{
			name: "npm",
			args: args{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/fs/npm",
				listAllPkgs: true,
			},
			golden: "testdata/npm.json.golden",
		},
		{
			name: "yarn",
			args: args{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/fs/yarn",
				listAllPkgs: true,
			},
			golden: "testdata/yarn.json.golden",
		},
		{
			name: "pnpm",
			args: args{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/fs/pnpm",
			},
			golden: "testdata/pnpm.json.golden",
		},
		{
			name: "pip",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/fs/pip",
			},
			golden: "testdata/pip.json.golden",
		},
		{
			name: "ignore analyzer error",
			args: args{
				command:      "rootfs",
				format:       "json",
				ignoreErrors: []string{"not a valid zip file"},
				input:        "testdata/fixtures/fs/ignore-errors",
			},
			golden: "testdata/ignore-errors.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			command := "fs"
			if tt.args.command != "" {
				command = tt.args.command
			}

			format := "json"
			if tt.args.format != "" {
				format = tt.args.format
			}

			osArgs := []string{
				"-q",
				"--cache-dir",
				cacheDir,
				command,
				"--skip-db-update",
				"--skip-policy-update",
				"--format",
				format,
				"--offline-scan",
			}

			if tt.args.scanner != "" {
				osArgs = append(osArgs, "--scanners", string(tt.args.scanner))
			}

			if len(tt.args.policyPaths) != 0 {
				for _, policyPath := range tt.args.policyPaths {
					osArgs = append(osArgs, "--config-policy", policyPath)
				}
			}

			if len(tt.args.namespaces) != 0 {
				for _, namespace := range tt.args.namespaces {
					osArgs = append(osArgs, "--policy-namespaces", namespace)
				}
			}

			if len(tt.args.severity) != 0 {
				osArgs = append(osArgs, "--severity", strings.Join(tt.args.severity, ","))
			}

			if len(tt.args.ignoreIDs) != 0 {
				trivyIgnore := ".trivyignore"
				err := os.WriteFile(trivyIgnore, []byte(strings.Join(tt.args.ignoreIDs, "\n")), 0444)
				assert.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}

			if len(tt.args.filePatterns) != 0 {
				for _, filePattern := range tt.args.filePatterns {
					osArgs = append(osArgs, "--file-patterns", filePattern)
				}
			}

			if len(tt.args.helmSet) != 0 {
				for _, helmSet := range tt.args.helmSet {
					osArgs = append(osArgs, "--helm-set", helmSet)
				}
			}

			if len(tt.args.helmValuesFile) != 0 {
				for _, helmValuesFile := range tt.args.helmValuesFile {
					osArgs = append(osArgs, "--helm-values", helmValuesFile)
				}
			}

			if len(tt.args.skipFiles) != 0 {
				for _, skipFile := range tt.args.skipFiles {
					osArgs = append(osArgs, "--skip-files", skipFile)
				}
			}

			if len(tt.args.skipDirs) != 0 {
				for _, skipDir := range tt.args.skipDirs {
					osArgs = append(osArgs, "--skip-dirs", skipDir)
				}
			}

			if len(tt.args.ignoreErrors) != 0 {
				for _, ignoreError := range tt.args.ignoreErrors {
					osArgs = append(osArgs, "--ignore-errors", ignoreError)
				}
			}

			// Setup the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update {
				outputFile = tt.golden
			}

			if tt.args.listAllPkgs {
				osArgs = append(osArgs, "--list-all-pkgs")
			}

			if tt.args.secretConfig != "" {
				osArgs = append(osArgs, "--secret-config", tt.args.secretConfig)
			}

			osArgs = append(osArgs, "--output", outputFile)
			osArgs = append(osArgs, tt.args.input)

			// Run "trivy fs"
			err := execute(osArgs)
			require.NoError(t, err)

			// Compare want and got
			switch format {
			case "cyclonedx":
				compareCycloneDX(t, tt.golden, outputFile)
			case "spdx-json":
				compareSpdxJson(t, tt.golden, outputFile)
			case "json":
				compareReports(t, tt.golden, outputFile)
			default:
				require.Fail(t, "invalid format", "format: %s", format)
			}
		})
	}
}
