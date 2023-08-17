//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

// TestRepository tests `trivy repo` with the local code repositories
func TestRepository(t *testing.T) {
	type args struct {
		scanner        types.Scanner
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
		command        string
		format         types.Format
		includeDevDeps bool
	}
	tests := []struct {
		name     string
		args     args
		golden   string
		override func(*types.Report)
	}{
		{
			name: "gomod",
			args: args{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gomod",
			},
			golden: "testdata/gomod.json.golden",
		},
		{
			name: "gomod with skip files",
			args: args{
				scanner:   types.VulnerabilityScanner,
				input:     "testdata/fixtures/repo/gomod",
				skipFiles: []string{"testdata/fixtures/repo/gomod/submod2/go.mod"},
			},
			golden: "testdata/gomod-skip.json.golden",
		},
		{
			name: "gomod with skip dirs",
			args: args{
				scanner:  types.VulnerabilityScanner,
				input:    "testdata/fixtures/repo/gomod",
				skipDirs: []string{"testdata/fixtures/repo/gomod/submod2"},
			},
			golden: "testdata/gomod-skip.json.golden",
		},
		{
			name: "npm",
			args: args{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/npm",
				listAllPkgs: true,
			},
			golden: "testdata/npm.json.golden",
		},
		{
			name: "npm with dev deps",
			args: args{
				scanner:        types.VulnerabilityScanner,
				input:          "testdata/fixtures/repo/npm",
				listAllPkgs:    true,
				includeDevDeps: true,
			},
			golden: "testdata/npm-with-dev.json.golden",
		},
		{
			name: "yarn",
			args: args{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/yarn",
				listAllPkgs: true,
			},
			golden: "testdata/yarn.json.golden",
		},
		{
			name: "pnpm",
			args: args{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/pnpm",
			},
			golden: "testdata/pnpm.json.golden",
		},
		{
			name: "pip",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pip",
			},
			golden: "testdata/pip.json.golden",
		},
		{
			name: "pipenv",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pipenv",
			},
			golden: "testdata/pipenv.json.golden",
		},
		{
			name: "poetry",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/poetry",
			},
			golden: "testdata/poetry.json.golden",
		},
		{
			name: "pom",
			args: args{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/pom",
			},
			golden: "testdata/pom.json.golden",
		},
		{
			name: "gradle",
			args: args{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gradle",
			},
			golden: "testdata/gradle.json.golden",
		},
		{
			name: "conan",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/conan",
			},
			golden: "testdata/conan.json.golden",
		},
		{
			name: "nuget",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/nuget",
			},
			golden: "testdata/nuget.json.golden",
		},
		{
			name: "dotnet",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/dotnet",
			},
			golden: "testdata/dotnet.json.golden",
		},
		{
			name: "cocoapods",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/cocoapods",
			},
			golden: "testdata/cocoapods.json.golden",
		},
		{
			name: "pubspec.lock",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pubspec",
			},
			golden: "testdata/pubspec.lock.json.golden",
		},
		{
			name: "mix.lock",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/mixlock",
			},
			golden: "testdata/mix.lock.json.golden",
		},
		{
			name: "composer.lock",
			args: args{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/composer",
			},
			golden: "testdata/composer.lock.json.golden",
		},
		{
			name: "dockerfile",
			args: args{
				scanner:    types.MisconfigScanner,
				input:      "testdata/fixtures/repo/dockerfile",
				namespaces: []string{"testing"},
			},
			golden: "testdata/dockerfile.json.golden",
		},
		{
			name: "dockerfile with custom file pattern",
			args: args{
				scanner:      types.MisconfigScanner,
				input:        "testdata/fixtures/repo/dockerfile_file_pattern",
				namespaces:   []string{"testing"},
				filePatterns: []string{"dockerfile:Customfile"},
			},
			golden: "testdata/dockerfile_file_pattern.json.golden",
		},
		{
			name: "dockerfile with rule exception",
			args: args{
				scanner:     types.MisconfigScanner,
				policyPaths: []string{"testdata/fixtures/repo/rule-exception/policy"},
				input:       "testdata/fixtures/repo/rule-exception",
			},
			golden: "testdata/dockerfile-rule-exception.json.golden",
		},
		{
			name: "dockerfile with namespace exception",
			args: args{
				scanner:     types.MisconfigScanner,
				policyPaths: []string{"testdata/fixtures/repo/namespace-exception/policy"},
				input:       "testdata/fixtures/repo/namespace-exception",
			},
			golden: "testdata/dockerfile-namespace-exception.json.golden",
		},
		{
			name: "dockerfile with custom policies",
			args: args{
				scanner:     types.MisconfigScanner,
				policyPaths: []string{"testdata/fixtures/repo/custom-policy/policy"},
				namespaces:  []string{"user"},
				input:       "testdata/fixtures/repo/custom-policy",
			},
			golden: "testdata/dockerfile-custom-policies.json.golden",
		},
		{
			name: "tarball helm chart scanning with builtin policies",
			args: args{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm",
			},
			golden: "testdata/helm.json.golden",
		},
		{
			name: "helm chart directory scanning with builtin policies",
			args: args{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_testchart",
			},
			golden: "testdata/helm_testchart.json.golden",
		},
		{
			name: "helm chart directory scanning with value overrides using set",
			args: args{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_testchart",
				helmSet: []string{"securityContext.runAsUser=0"},
			},
			golden: "testdata/helm_testchart.overridden.json.golden",
		},
		{
			name: "helm chart directory scanning with value overrides using value file",
			args: args{
				scanner:        types.MisconfigScanner,
				input:          "testdata/fixtures/repo/helm_testchart",
				helmValuesFile: []string{"testdata/fixtures/repo/helm_values/values.yaml"},
			},
			golden: "testdata/helm_testchart.overridden.json.golden",
		},
		{
			name: "helm chart directory scanning with builtin policies and non string Chart name",
			args: args{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_badname",
			},
			golden: "testdata/helm_badname.json.golden",
		},
		{
			name: "secrets",
			args: args{
				scanner:      "vuln,secret",
				input:        "testdata/fixtures/repo/secrets",
				secretConfig: "testdata/fixtures/repo/secrets/trivy-secret.yaml",
			},
			golden: "testdata/secrets.json.golden",
		},
		{
			name: "conda generating CycloneDX SBOM",
			args: args{
				command: "rootfs",
				format:  "cyclonedx",
				input:   "testdata/fixtures/repo/conda",
			},
			golden: "testdata/conda-cyclonedx.json.golden",
		},
		{
			name: "conda generating SPDX SBOM",
			args: args{
				command: "rootfs",
				format:  "spdx-json",
				input:   "testdata/fixtures/repo/conda",
			},
			golden: "testdata/conda-spdx.json.golden",
		},
		{
			name: "gomod with fs subcommand",
			args: args{
				command:   "fs",
				scanner:   types.VulnerabilityScanner,
				input:     "testdata/fixtures/repo/gomod",
				skipFiles: []string{"testdata/fixtures/repo/gomod/submod2/go.mod"},
			},
			golden: "testdata/gomod-skip.json.golden",
			override: func(report *types.Report) {
				report.ArtifactType = ftypes.ArtifactFilesystem
			},
		},
		{
			name: "dockerfile with fs subcommand",
			args: args{
				command:     "fs",
				scanner:     types.MisconfigScanner,
				policyPaths: []string{"testdata/fixtures/repo/custom-policy/policy"},
				namespaces:  []string{"user"},
				input:       "testdata/fixtures/repo/custom-policy",
			},
			golden: "testdata/dockerfile-custom-policies.json.golden",
			override: func(report *types.Report) {
				report.ArtifactType = ftypes.ArtifactFilesystem
			},
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set a temp dir so that modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			command := "repo"
			if tt.args.command != "" {
				command = tt.args.command
			}

			format := types.FormatJSON
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
				string(format),
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

			// Setup the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update && tt.override == nil {
				outputFile = tt.golden
			}

			if tt.args.listAllPkgs {
				osArgs = append(osArgs, "--list-all-pkgs")
			}

			if tt.args.includeDevDeps {
				osArgs = append(osArgs, "--include-dev-deps")
			}

			if tt.args.secretConfig != "" {
				osArgs = append(osArgs, "--secret-config", tt.args.secretConfig)
			}

			osArgs = append(osArgs, "--output", outputFile)
			osArgs = append(osArgs, tt.args.input)

			clock.SetFakeTime(t, time.Date(2020, 9, 10, 14, 20, 30, 5, time.UTC))
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			// Run "trivy repo"
			err := execute(osArgs)
			require.NoError(t, err)

			// Compare want and got
			switch format {
			case types.FormatCycloneDX:
				compareCycloneDX(t, tt.golden, outputFile)
			case types.FormatSPDXJSON:
				compareSpdxJson(t, tt.golden, outputFile)
			case types.FormatJSON:
				compareReports(t, tt.golden, outputFile, tt.override)
			default:
				require.Fail(t, "invalid format", "format: %s", format)
			}
		})
	}
}
