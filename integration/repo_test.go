//go:build integration

package integration

import (
	"cmp"
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

// TestRepository tests `trivy repo` with the local code repositories.
//
// NOTE: This test CAN update golden files with the -update flag.
// This is the canonical source for repository/filesystem scanning golden files.
// Golden files generated here may be shared with other tests like TestRepositoryWithOverride,
// TestConfiguration, and TestClientServerWithRedis (when scanning repositories).
func TestRepository(t *testing.T) {
	t.Setenv("NUGET_PACKAGES", t.TempDir())
	tests := []struct {
		name   string
		args   repoTestArgs
		golden string
	}{
		{
			name: "gomod",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gomod",
			},
			golden: goldenGoMod,
		},
		{
			name: "gomod with skip files",
			args: repoTestArgs{
				scanner:   types.VulnerabilityScanner,
				input:     "testdata/fixtures/repo/gomod",
				skipFiles: []string{"testdata/fixtures/repo/gomod/submod2/go.mod"},
			},
			golden: goldenGoModSkip,
		},
		{
			name: "gomod with skip dirs",
			args: repoTestArgs{
				scanner:  types.VulnerabilityScanner,
				input:    "testdata/fixtures/repo/gomod",
				skipDirs: []string{"testdata/fixtures/repo/gomod/submod2"},
			},
			golden: goldenGoModSkip,
		},
		{
			name: "gomod in series",
			args: repoTestArgs{
				scanner:  types.VulnerabilityScanner,
				input:    "testdata/fixtures/repo/gomod",
				parallel: 1,
			},
			golden: goldenGoMod,
		},
		{
			name: "gomod with local VEX file",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gomod",
				vex:     "testdata/fixtures/vex/file/openvex.json",
			},
			golden: goldenGoModVEX,
		},
		{
			name: "gomod with VEX repository",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gomod",
				vex:     "repo",
			},
			golden: goldenGoModVEX,
		},
		{
			name: "npm",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/npm",
				listAllPkgs: true,
			},
			golden: goldenNPM,
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
			golden: goldenNPMUbuntuSeverity,
		},
		{
			name: "npm with dev deps",
			args: repoTestArgs{
				scanner:        types.VulnerabilityScanner,
				input:          "testdata/fixtures/repo/npm",
				listAllPkgs:    true,
				includeDevDeps: true,
			},
			golden: goldenNPMWithDev,
		},
		{
			name: "yarn",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/yarn",
				listAllPkgs: true,
			},
			golden: goldenYarn,
		},
		{
			name: "pnpm",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/pnpm",
				listAllPkgs: true,
			},
			golden: goldenPnpm,
		},
		{
			name: "bun",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				input:       "testdata/fixtures/repo/bun",
				listAllPkgs: true,
			},
			golden: goldenBun,
		},
		{
			name: "pip",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pip",
			},
			golden: goldenPip,
		},
		{
			name: "pipenv",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pipenv",
			},
			golden: goldenPipenv,
		},
		{
			name: "poetry",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/poetry",
			},
			golden: goldenPoetry,
		},
		{
			name: "uv",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/uv",
			},
			golden: goldenUV,
		},
		{
			name: "pylock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pylock",
			},
			golden: goldenPyLock,
		},
		{
			name: "pom",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/pom",
			},
			golden: goldenPom,
		},
		{
			name: "gradle",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/gradle",
			},
			golden: goldenGradle,
		},
		{
			name: "sbt",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "testdata/fixtures/repo/sbt",
			},
			golden: goldenSBT,
		},
		{
			name: "conan",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/conan",
			},
			golden: goldenConan,
		},
		{
			name: "nuget",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/nuget",
			},
			golden: goldenNuGet,
		},
		{
			name: "dotnet",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/dotnet",
			},
			golden: goldenDotNet,
		},
		{
			name: "packages-props",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/packagesprops",
			},
			golden: goldenPackagesProps,
		},
		{
			name: "swift",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/swift",
			},
			golden: goldenSwift,
		},
		{
			name: "cocoapods",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/cocoapods",
			},
			golden: goldenCocoaPods,
		},
		{
			name: "pubspec.lock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/pubspec",
			},
			golden: goldenPubspecLock,
		},
		{
			name: "mix.lock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/mixlock",
			},
			golden: goldenMixLock,
		},
		{
			name: "composer.lock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/composer",
			},
			golden: goldenComposerLock,
		},
		{
			name: "cargo.lock",
			args: repoTestArgs{
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/cargo",
			},
			golden: goldenCargoLock,
		},
		{
			name: "installed.json",
			args: repoTestArgs{
				command:     "rootfs",
				scanner:     types.VulnerabilityScanner,
				listAllPkgs: true,
				input:       "testdata/fixtures/repo/composer-vendor",
			},
			golden: goldenComposerVendor,
		},
		{
			name: "dockerfile",
			args: repoTestArgs{
				scanner:    types.MisconfigScanner,
				input:      "testdata/fixtures/repo/dockerfile",
				namespaces: []string{"testing"},
			},
			golden: goldenDockerfile,
		},
		{
			name: "dockerfile with custom file pattern",
			args: repoTestArgs{
				scanner:      types.MisconfigScanner,
				input:        "testdata/fixtures/repo/dockerfile_file_pattern",
				namespaces:   []string{"testing"},
				filePatterns: []string{"dockerfile:Customfile"},
			},
			golden: goldenDockerfileFilePattern,
		},
		{
			name: "dockerfile with custom policies",
			args: repoTestArgs{
				scanner:     types.MisconfigScanner,
				policyPaths: []string{"testdata/fixtures/repo/custom-policy/policy"},
				namespaces:  []string{"user"},
				input:       "testdata/fixtures/repo/custom-policy",
			},
			golden: goldenDockerfileCustomPolicies,
		},
		{
			name: "tarball helm chart scanning with builtin policies",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm",
			},
			golden: goldenHelm,
		},
		{
			name: "helm chart directory scanning with builtin policies",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_testchart",
			},
			golden: goldenHelmTestChart,
		},
		{
			name: "helm chart directory scanning with value overrides using set",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_testchart",
				helmSet: []string{"securityContext.runAsUser=0"},
			},
			golden: goldenHelmTestChartOverridden,
		},
		{
			name: "helm chart directory scanning with value overrides using value file",
			args: repoTestArgs{
				scanner:        types.MisconfigScanner,
				input:          "testdata/fixtures/repo/helm_testchart",
				helmValuesFile: []string{"testdata/fixtures/repo/helm_values/values.yaml"},
			},
			golden: goldenHelmTestChartOverridden,
		},
		{
			name: "helm chart directory scanning with builtin policies and non string Chart name",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/helm_badname",
			},
			golden: goldenHelmBadName,
		},
		{
			name: "terraform config with remote module",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/remote-module",
			},
			golden: goldenTerraformRemoteModule,
		},
		{
			name: "terraform config with remote submodule",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/remote-submodule",
			},
			golden: goldenTerraformRemoteSubmodule,
		},
		{
			name: "terraform config with remote module in child local module",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/remote-module-in-child",
			},
			golden: goldenTerraformRemoteModuleInChild,
		},
		{
			name: "exclude misconfigurations for remote module",
			args: repoTestArgs{
				scanner:                    types.MisconfigScanner,
				input:                      "testdata/fixtures/repo/terraform/remote-module",
				tfExcludeDownloadedModules: true,
			},
			golden: goldenTerraformExcludeMisconfigsRemoteModule,
		},
		{
			name: "module from Terraform registry",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/opentofu-registry",
			},
			golden: goldenTerraformTerraformRegistry,
		},
		{
			name: "module from OpenTofu registry",
			args: repoTestArgs{
				scanner: types.MisconfigScanner,
				input:   "testdata/fixtures/repo/terraform/opentofu-registry",
			},
			golden: goldenTerraformOpenTofuRegistry,
		},
		{
			name: "secrets",
			args: repoTestArgs{
				scanner:      "vuln,secret",
				input:        "testdata/fixtures/repo/secrets",
				secretConfig: "testdata/fixtures/repo/secrets/trivy-secret.yaml",
			},
			golden: goldenSecrets,
		},
		{
			name: "conda generating CycloneDX SBOM",
			args: repoTestArgs{
				command: "rootfs",
				format:  "cyclonedx",
				input:   "testdata/fixtures/repo/conda",
			},
			golden: goldenCondaCycloneDX,
		},
		{
			name: "conda environment.yaml generating CycloneDX SBOM",
			args: repoTestArgs{
				command: "fs",
				format:  "cyclonedx",
				input:   "testdata/fixtures/repo/conda-environment",
			},
			golden: goldenCondaEnvironmentCycloneDX,
		},
		{
			name: "pom.xml generating CycloneDX SBOM (with vulnerabilities)",
			args: repoTestArgs{
				command: "fs",
				scanner: types.VulnerabilityScanner,
				format:  "cyclonedx",
				input:   "testdata/fixtures/repo/pom",
			},
			golden: goldenPomCycloneDX,
		},
		{
			name: "conda generating SPDX SBOM",
			args: repoTestArgs{
				command: "rootfs",
				format:  "spdx-json",
				input:   "testdata/fixtures/repo/conda",
			},
			golden: goldenCondaSPDX,
		},
		{
			name: "julia generating SPDX SBOM",
			args: repoTestArgs{
				command: "rootfs",
				format:  "spdx-json",
				input:   "testdata/fixtures/repo/julia",
			},
			golden: goldenJuliaSPDX,
		},
		{
			name: "multiple lockfiles",
			args: repoTestArgs{
				scanner: types.VulnerabilityScanner,
				input:   "https://github.com/knqyf263/trivy-ci-test",
			},
			golden: goldenTestRepo,
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
			command := cmp.Or(tt.args.command, "repo")
			format := cmp.Or(tt.args.format, types.FormatJSON)

			osArgs := buildArgs(t, cacheDir, command, format, tt.args)

			runTest(t, osArgs, tt.golden, format, runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				override: nil, // Do not use overrides - golden files are generated from this test as the canonical source
			})
		})
	}
}

// TestRepositoryWithOverride tests `trivy repo` with override functions for specific edge cases.
//
// IMPORTANT: Golden files used in this test cannot be updated with the -update flag
// because the golden files are shared with TestRepository.
// If golden files need to be updated, they should be generated from TestRepository.
//
// All golden files used in TestRepositoryWithOverride MUST also be used in TestRepository
// to ensure they can be properly updated when needed.
func TestRepositoryWithOverride(t *testing.T) {
	if *update {
		t.Skipf("Skipping TestRepositoryWithOverride when -update flag is set. Golden files should be updated via TestRepository.")
	}

	t.Setenv("NUGET_PACKAGES", t.TempDir())
	tests := []struct {
		name     string
		args     repoTestArgs
		golden   string
		override func(t *testing.T, want, got *types.Report)
	}{
		{
			name: "gomod with fs subcommand",
			args: repoTestArgs{
				command:   "fs",
				scanner:   types.VulnerabilityScanner,
				input:     "testdata/fixtures/repo/gomod",
				skipFiles: []string{"testdata/fixtures/repo/gomod/submod2/go.mod"},
			},
			golden: goldenGoModSkip,
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
			golden: goldenDockerfileCustomPolicies,
			override: func(_ *testing.T, want, _ *types.Report) {
				want.ArtifactType = ftypes.TypeFilesystem
			},
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

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

			runTest(t, osArgs, tt.golden, format, runOptions{
				fakeUUID: "3ff14136-e09f-4df9-80ea-%012d",
				override: overrideFuncs(overrideUID, tt.override),
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
