//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type repoTestArgs struct {
	scanner                    types.Scanner
	ignoreIDs                  []string
	policyPaths                []string
	namespaces                 []string
	listAllPkgs                bool
	input                      string
	secretConfig               string
	filePatterns               []string
	helmSet                    []string
	helmValuesFile             []string
	skipFiles                  []string
	skipDirs                   []string
	command                    string
	format                     types.Format
	includeDevDeps             bool
	parallel                   int
	vex                        string
	vulnSeveritySources        []string
	tfExcludeDownloadedModules bool
}

// TestRepository tests `trivy repo` with the local code repositories
func TestRepository(t *testing.T) {
	t.Setenv("NUGET_PACKAGES", t.TempDir())
	tests := []struct {
		name     string
		args     repoTestArgs
		golden   string
		override func(t *testing.T, want, got *types.Report)
	}{
		{
			name: "gomod",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gomod",
			},
			golden: "testdata/gomod.json.golden",
		},
		{
			name: "gomod with skip files",
			args: repoTestArgs{
				scanner:   types.VulnerabilityScanner,
				input:     "testdata/fixtures/repo/gomod",
				skipFiles: []string{"testdata/fixtures/repo/gomod/submod2/go.mod"},
			},
			golden: "testdata/gomod-skip.json.golden",
		},
		{
			name: "gomod with skip dirs",
			args: repoTestArgs{
				scanner:  types.VulnerabilityScanner,
				input:    "testdata/fixtures/repo/gomod",
				skipDirs: []string{"testdata/fixtures/repo/gomod/submod2"},
			},
			golden: "testdata/gomod-skip.json.golden",
		},
		{
			name: "gomod in series",
			args: repoTestArgs{
				scanner:  types.VulnerabilityScanner,
				input:    "testdata/fixtures/repo/gomod",
				parallel: 1,
			},
			golden: "testdata/gomod.json.golden",
		},
		{
			name: "gomod with local VEX file",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gomod",
				vex:     "testdata/fixtures/vex/file/openvex.json",
			},
			golden: "testdata/gomod-vex.json.golden",
		},
		{
			name: "gomod with VEX repository",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gomod",
				vex:     "repo",
			},
			golden: "testdata/gomod-vex.json.golden",
		},
		{
			name: "npm",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/npm",
				listAllPkgs: true,
			},
			golden: "testdata/npm.json.golden",
		},
		{
			name: "npm with severity from ubuntu",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/npm",
				vulnSeveritySources: []string{
					"alpine",
					"ubuntu",
				},
			},
			golden: "testdata/npm-ubuntu-severity.json.golden",
		},
		{
			name: "npm with dev deps",
			args: repoTestArgs{
				scanner:        types.VulnerabilityScanner,
				input:          "testdata/fixtures/repo/npm",
				listAllPkgs:    true,
				includeDevDeps: true,
			},
			golden: "testdata/npm-with-dev.json.golden",
		},
		{
			name: "yarn",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/yarn",
				listAllPkgs: true,
			},
			golden: "testdata/yarn.json.golden",
		},
		{
			name: "pnpm",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/pnpm",
				listAllPkgs: true,
			},
			golden: "testdata/pnpm.json.golden",
		},
		{
			name: "bun",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/bun",
				listAllPkgs: true,
			},
			golden: "testdata/bun.json.golden",
		},
		{
			name: "pip",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pip",
			},
			golden: "testdata/pip.json.golden",
		},
		{
			name: "pipenv",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pipenv",
			},
			golden: "testdata/pipenv.json.golden",
		},
		{
			name: "poetry",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/poetry",
			},
			golden: "testdata/poetry.json.golden",
		},
		{
			name: "uv",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/uv",
			},
			golden: "testdata/uv.json.golden",
		},
		{
			name: "pom",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/pom",
			},
			golden: "testdata/pom.json.golden",
		},
		{
			name: "gradle",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gradle",
			},
			golden: "testdata/gradle.json.golden",
		},
		{
			name: "sbt",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/sbt",
			},
			golden: "testdata/sbt.json.golden",
		},
		{
			name: "conan",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/conan",
			},
			golden: "testdata/conan.json.golden",
		},
		{
			name: "nuget",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/nuget",
			},
			golden: "testdata/nuget.json.golden",
		},
		{
			name: "dotnet",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/dotnet",
			},
			golden: "testdata/dotnet.json.golden",
		},
		{
			name: "packages-props",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/packagesprops",
			},
			golden: "testdata/packagesprops.json.golden",
		},
		{
			name: "swift",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/swift",
			},
			golden: "testdata/swift.json.golden",
		},
		{
			name: "cocoapods",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/cocoapods",
			},
			golden: "testdata/cocoapods.json.golden",
		},
		{
			name: "pubspec.lock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pubspec",
			},
			golden: "testdata/pubspec.lock.json.golden",
		},
		{
			name: "mix.lock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/mixlock",
			},
			golden: "testdata/mix.lock.json.golden",
		},
		{
			name: "composer.lock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/composer",
			},
			golden: "testdata/composer.lock.json.golden",
		},
		{
			name: "cargo.lock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/cargo",
			},
			golden: "testdata/cargo.lock.json.golden",
		},
		{
			name: "multiple lockfiles",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/trivy-ci-test",
			},
			golden: "testdata/test-repo.json.golden",
			override: func(_ *testing.T, want, _ *types.Report) {
				// Clear all metadata as this is a local directory scan without git info
				want.Metadata = types.Metadata{}
			},
		},
		{
			name: "installed.json",
			args: repoTestArgs{
				command:     "rootfs",
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/composer-vendor",
			},
			golden: "testdata/composer.vendor.json.golden",
		},
		{
			name: "dockerfile",
			args: repoTestArgs{
				scanner:    types.MisconfigScanner,
				input:      "testdata/fixtures/repo/dockerfile",
				namespaces: []string{"testing"},
			},
			golden: "testdata/dockerfile.json.golden",
		},
		{
			name: "dockerfile with custom file pattern",
			args: repoTestArgs{
				scanner:      types.MisconfigScanner,
				input:        "testdata/fixtures/repo/dockerfile_file_pattern",
				namespaces:   []string{"testing"},
				filePatterns: []string{"dockerfile:Customfile"},
			},
			golden: "testdata/dockerfile_file_pattern.json.golden",
		},
		{
			name: "dockerfile with custom policies",
			args: repoTestArgs{
				scanner:     types.MisconfigScanner,
				policyPaths: []string{"testdata/fixtures/repo/custom-policy/policy"},
				namespaces:  []string{"user"},
				input:       "testdata/fixtures/repo/custom-policy",
			},
			golden: "testdata/dockerfile-custom-policies.json.golden",
		},
		{
			name: "tarball helm chart scanning with builtin policies",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm",
			},
			golden: "testdata/helm.json.golden",
		},
		{
			name: "helm chart directory scanning with builtin policies",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_testchart",
			},
			golden: "testdata/helm_testchart.json.golden",
		},
		{
			name: "helm chart directory scanning with value overrides using set",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_testchart",
				helmSet: []string{"securityContext.runAsUser=0"},
			},
			golden: "testdata/helm_testchart.overridden.json.golden",
		},
		{
			name: "helm chart directory scanning with value overrides using value file",
			args: repoTestArgs{
				scanner:        types.MisconfigScanner,
				input:          "testdata/fixtures/repo/helm_testchart",
				helmValuesFile: []string{"testdata/fixtures/repo/helm_values/values.yaml"},
			},
			golden: "testdata/helm_testchart.overridden.json.golden",
		},
		{
			name: "helm chart directory scanning with builtin policies and non string Chart name",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_badname",
			},
			golden: "testdata/helm_badname.json.golden",
		},
		{
			name: "terraform config with remote module",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/remote-module",
			},
			golden: "testdata/terraform-remote-module.json.golden",
		},
		{
			name: "terraform config with remote submodule",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/remote-submodule",
			},
			golden: "testdata/terraform-remote-submodule.json.golden",
		},
		{
			name: "terraform config with remote module in child local module",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/remote-module-in-child",
			},
			golden: "testdata/terraform-remote-module-in-child.json.golden",
		},
		{
			name: "exclude misconfigurations for remote module",
			args: repoTestArgs{
				scanner:                    types.MisconfigScanner,
				input:                      "testdata/fixtures/repo/terraform/remote-module",
				tfExcludeDownloadedModules: true,
			},
			golden: "testdata/terraform-exclude-misconfs-remote-module.json.golden",
		},
		{
			name: "module from Terraform registry",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/opentofu-registry",
			},
			golden: "testdata/terraform-terraform-registry.json.golden",
		},
		{
			name: "module from OpenTofu registry",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/opentofu-registry",
			},
			golden: "testdata/terraform-opentofu-registry.json.golden",
		},
		{
			name: "secrets",
			args: repoTestArgs{
				scanner:      "vuln,secret",
				input:        "testdata/fixtures/repo/secrets",
				secretConfig: "testdata/fixtures/repo/secrets/trivy-secret.yaml",
			},
			golden: "testdata/secrets.json.golden",
		},
		{
			name: "conda generating CycloneDX SBOM",
			args: repoTestArgs{
				command: "rootfs",
				format:  "cyclonedx",
				input:   "testdata/fixtures/repo/conda",
			},
			golden: "testdata/conda-cyclonedx.json.golden",
		},
		{
			name: "conda environment.yaml generating CycloneDX SBOM",
			args: repoTestArgs{
				command: "fs",
				format:  "cyclonedx",
				input:   "testdata/fixtures/repo/conda-environment",
			},
			golden: "testdata/conda-environment-cyclonedx.json.golden",
		},
		{
			name: "pom.xml generating CycloneDX SBOM (with vulnerabilities)",
			args: repoTestArgs{
				command: "fs",
				scanner: types.VulnerabilityScanner,
				format:  "cyclonedx",
				input:   "testdata/fixtures/repo/pom",
			},
			golden: "testdata/pom-cyclonedx.json.golden",
		},
		{
			name: "conda generating SPDX SBOM",
			args: repoTestArgs{
				command: "rootfs",
				format:  "spdx-json",
				input:   "testdata/fixtures/repo/conda",
			},
			golden: "testdata/conda-spdx.json.golden",
		},
		{
			name: "gomod with fs subcommand",
			args: repoTestArgs{
				command:   "fs",
				scanner:   types.VulnerabilityScanner,
				input:     "testdata/fixtures/repo/gomod",
				skipFiles: []string{"testdata/fixtures/repo/gomod/submod2/go.mod"},
			},
			golden: "testdata/gomod-skip.json.golden",
			override: func(_ *testing.T, want, _ *types.Report) {
				want.ArtifactType = ftypes.TypeFilesystem
			},
		},
		{
			name: "dockerfile with fs subcommand and an alias scanner",
			args: repoTestArgs{
				command:     "fs",
				scanner:     "config", // for backward compatibility
				policyPaths: []string{"testdata/fixtures/repo/custom-policy/policy"},
				namespaces:  []string{"user"},
				input:       "testdata/fixtures/repo/custom-policy",
			},
			golden: "testdata/dockerfile-custom-policies.json.golden",
			override: func(_ *testing.T, want, _ *types.Report) {
				want.ArtifactType = ftypes.TypeFilesystem
			},
		},
		{
			name: "julia generating SPDX SBOM",
			args: repoTestArgs{
				command: "rootfs",
				format:  "spdx-json",
				input:   "testdata/fixtures/repo/julia",
			},
			golden: "testdata/julia-spdx.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	// Set up VEX
	initVEXRepository(t, cacheDir, cacheDir)

	// Set a temp dir so that the VEX config will be loaded and modules will not be loaded
	t.Setenv("XDG_DATA_HOME", cacheDir)

	// Disable Go license detection
	t.Setenv("GOPATH", cacheDir)

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

			osArgs := buildArgs(t, cacheDir, command, format, tt.args)

			runTest(t, osArgs, tt.golden, "", format, runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				override: tt.override,
			})
		})
	}
}

func buildArgs(t *testing.T, cacheDir, command string, format types.Format, testArgs repoTestArgs) []string {
	// Build base arguments
	osArgs := []string{
		"-q",
		"--cache-dir",
		cacheDir,
		command,
		"--skip-db-update",
		"--skip-policy-update",
		"--format",
		string(format),
		"--parallel",
		strconv.Itoa(testArgs.parallel),
		"--offline-scan",
		testArgs.input,
	}

	if testArgs.scanner != "" {
		osArgs = append(osArgs, "--scanners", string(testArgs.scanner))
	}

	for _, policyPath := range testArgs.policyPaths {
		osArgs = append(osArgs, "--config-policy", policyPath)
	}
	for _, namespace := range testArgs.namespaces {
		osArgs = append(osArgs, "--policy-namespaces", namespace)
	}

	// Handle ignore file using temporary directory
	if len(testArgs.ignoreIDs) != 0 {
		trivyIgnore := filepath.Join(t.TempDir(), ".trivyignore")
		err := os.WriteFile(trivyIgnore, []byte(strings.Join(testArgs.ignoreIDs, "\n")), 0o444)
		require.NoError(t, err, "failed to write .trivyignore")
		osArgs = append(osArgs, "--ignorefile", trivyIgnore)
	}

	for _, filePattern := range testArgs.filePatterns {
		osArgs = append(osArgs, "--file-patterns", filePattern)
	}

	for _, hs := range testArgs.helmSet {
		osArgs = append(osArgs, "--helm-set", hs)
	}
	for _, hvf := range testArgs.helmValuesFile {
		osArgs = append(osArgs, "--helm-values", hvf)
	}

	for _, skipFile := range testArgs.skipFiles {
		osArgs = append(osArgs, "--skip-files", skipFile)
	}
	for _, skipDir := range testArgs.skipDirs {
		osArgs = append(osArgs, "--skip-dirs", skipDir)
	}

	if len(testArgs.vulnSeveritySources) != 0 {
		osArgs = append(osArgs,
			"--vuln-severity-source", strings.Join(testArgs.vulnSeveritySources, ","),
		)
	}
	if !testArgs.listAllPkgs {
		osArgs = append(osArgs, "--list-all-pkgs=false")
	}
	if testArgs.includeDevDeps {
		osArgs = append(osArgs, "--include-dev-deps")
	}
	if testArgs.secretConfig != "" {
		osArgs = append(osArgs, "--secret-config", testArgs.secretConfig)
	}
	if testArgs.vex != "" {
		osArgs = append(osArgs, "--vex", testArgs.vex)
	}
	if testArgs.tfExcludeDownloadedModules {
		osArgs = append(osArgs, "--tf-exclude-downloaded-modules")
	}

	return osArgs
}
