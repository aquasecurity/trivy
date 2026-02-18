//go:build integration || vm_integration || module_integration || k8s_integration

package integration

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdxlib"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
	"github.com/aquasecurity/trivy/pkg/vex/repo"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"

	_ "modernc.org/sqlite"
)

var update = flag.Bool("update", false, "update golden files")

const SPDXSchema = "https://raw.githubusercontent.com/spdx/spdx-spec/support/v%s/schemas/spdx-schema.json"

// Golden file paths
const (
	// Container image tests (docker_engine_test.go, client_server_test.go, standalone_tar_test.go, registry_test.go)
	goldenAlmaLinux8                  = "testdata/almalinux-8.json.golden"
	goldenAlpine39                    = "testdata/alpine-39.json.golden"
	goldenAlpine39HighCritical        = "testdata/alpine-39-high-critical.json.golden"
	goldenAlpine39IgnoreCVEIDs        = "testdata/alpine-39-ignore-cveids.json.golden"
	goldenAlpine39Skip                = "testdata/alpine-39-skip.json.golden"
	goldenAlpine310JSON               = "testdata/alpine-310.json.golden"
	goldenAlpine310ASFF               = "testdata/alpine-310.asff.golden"
	goldenAlpine310GitLab             = "testdata/alpine-310.gitlab.golden"
	goldenAlpine310GitLabCodeQuality  = "testdata/alpine-310.gitlab-codequality.golden"
	goldenAlpine310GSBOM              = "testdata/alpine-310.gsbom.golden"
	goldenAlpine310HTML               = "testdata/alpine-310.html.golden"
	goldenAlpine310JUnit              = "testdata/alpine-310.junit.golden"
	goldenAlpine310SARIF              = "testdata/alpine-310.sarif.golden"
	goldenAlpineDistroless            = "testdata/alpine-distroless.json.golden"
	goldenAmazon1                     = "testdata/amazon-1.json.golden"
	goldenAmazon2                     = "testdata/amazon-2.json.golden"
	goldenBusyboxWithLockfile         = "testdata/busybox-with-lockfile.json.golden"
	goldenCentOS6                     = "testdata/centos-6.json.golden"
	goldenCentOS7                     = "testdata/centos-7.json.golden"
	goldenCentOS7IgnoreUnfixed        = "testdata/centos-7-ignore-unfixed.json.golden"
	goldenCentOS7Medium               = "testdata/centos-7-medium.json.golden"
	goldenDebianBuster                = "testdata/debian-buster.json.golden"
	goldenDebianBusterIgnoreUnfixed   = "testdata/debian-buster-ignore-unfixed.json.golden"
	goldenDebianStretch               = "testdata/debian-stretch.json.golden"
	goldenDistrolessBase              = "testdata/distroless-base.json.golden"
	goldenDistrolessPython27          = "testdata/distroless-python27.json.golden"
	goldenFluentdGems                 = "testdata/fluentd-gems.json.golden"
	goldenFluentdMultipleLockfilesCDX = "testdata/fluentd-multiple-lockfiles.cdx.json.golden"
	goldenMariner10                   = "testdata/mariner-1.0.json.golden"
	goldenNPM                         = "testdata/npm.json.golden"
	goldenNPMGitLab                   = "testdata/npm.gitlab.golden"
	goldenNPMUbuntuSeverity           = "testdata/npm-ubuntu-severity.json.golden"
	goldenOpenSUSELeap151             = "testdata/opensuse-leap-151.json.golden"
	goldenOpenSUSETumbleweed          = "testdata/opensuse-tumbleweed.json.golden"
	goldenOracleLinux8                = "testdata/oraclelinux-8.json.golden"
	goldenPhoton30                    = "testdata/photon-30.json.golden"
	goldenPom                         = "testdata/pom.json.golden"
	goldenRockyLinux8                 = "testdata/rockylinux-8.json.golden"
	goldenSecrets                     = "testdata/secrets.json.golden"
	goldenSecretsASFF                 = "testdata/secrets.asff.golden"
	goldenSLMicroRancher54            = "testdata/sl-micro-rancher5.4.json.golden"
	goldenTestRepo                    = "testdata/test-repo.json.golden"
	goldenUBI7                        = "testdata/ubi-7.json.golden"
	goldenUBI7Comprehensive           = "testdata/ubi-7-comprehensive.json.golden"
	goldenUbuntu1804                  = "testdata/ubuntu-1804.json.golden"
	goldenUbuntu1804IgnoreUnfixed     = "testdata/ubuntu-1804-ignore-unfixed.json.golden"

	// Repository/Filesystem tests (repo_test.go, config_test.go)
	goldenBun                                    = "testdata/bun.json.golden"
	goldenCargoLock                              = "testdata/cargo.lock.json.golden"
	goldenCocoaPods                              = "testdata/cocoapods.json.golden"
	goldenComposerLock                           = "testdata/composer.lock.json.golden"
	goldenComposerVendor                         = "testdata/composer.vendor.json.golden"
	goldenConan                                  = "testdata/conan.json.golden"
	goldenCondaCycloneDX                         = "testdata/conda-cyclonedx.json.golden"
	goldenCondaEnvironmentCycloneDX              = "testdata/conda-environment-cyclonedx.json.golden"
	goldenCondaSPDX                              = "testdata/conda-spdx.json.golden"
	goldenDockerfile                             = "testdata/dockerfile.json.golden"
	goldenDockerfileCustomPolicies               = "testdata/dockerfile-custom-policies.json.golden"
	goldenDockerfileFilePattern                  = "testdata/dockerfile_file_pattern.json.golden"
	goldenDotNet                                 = "testdata/dotnet.json.golden"
	goldenGoMod                                  = "testdata/gomod.json.golden"
	goldenGoModSkip                              = "testdata/gomod-skip.json.golden"
	goldenGoModVEX                               = "testdata/gomod-vex.json.golden"
	goldenGradle                                 = "testdata/gradle.json.golden"
	goldenHelm                                   = "testdata/helm.json.golden"
	goldenHelmBadName                            = "testdata/helm_badname.json.golden"
	goldenHelmTestChart                          = "testdata/helm_testchart.json.golden"
	goldenHelmTestChartOverridden                = "testdata/helm_testchart.overridden.json.golden"
	goldenJuliaSPDX                              = "testdata/julia-spdx.json.golden"
	goldenMixLock                                = "testdata/mix.lock.json.golden"
	goldenNPMWithDev                             = "testdata/npm-with-dev.json.golden"
	goldenNuGet                                  = "testdata/nuget.json.golden"
	goldenPackagesProps                          = "testdata/packagesprops.json.golden"
	goldenPip                                    = "testdata/pip.json.golden"
	goldenPipenv                                 = "testdata/pipenv.json.golden"
	goldenPnpm                                   = "testdata/pnpm.json.golden"
	goldenPoetry                                 = "testdata/poetry.json.golden"
	goldenPyLock                                 = "testdata/pylock.json.golden"
	goldenPomCycloneDX                           = "testdata/pom-cyclonedx.json.golden"
	goldenPubspecLock                            = "testdata/pubspec.lock.json.golden"
	goldenSBT                                    = "testdata/sbt.json.golden"
	goldenSwift                                  = "testdata/swift.json.golden"
	goldenTerraformExcludeMisconfigsRemoteModule = "testdata/terraform-exclude-misconfs-remote-module.json.golden"
	goldenTerraformOpenTofuRegistry              = "testdata/terraform-opentofu-registry.json.golden"
	goldenTerraformRemoteModule                  = "testdata/terraform-remote-module.json.golden"
	goldenTerraformRemoteModuleInChild           = "testdata/terraform-remote-module-in-child.json.golden"
	goldenTerraformRemoteSubmodule               = "testdata/terraform-remote-submodule.json.golden"
	goldenTerraformTerraformRegistry             = "testdata/terraform-terraform-registry.json.golden"
	goldenUV                                     = "testdata/uv.json.golden"
	goldenYarn                                   = "testdata/yarn.json.golden"

	// SBOM tests (sbom_test.go)
	goldenFluentdMultipleLockfiles         = "testdata/fluentd-multiple-lockfiles.json.golden"
	goldenFluentdMultipleLockfilesShortCDX = "testdata/fluentd-multiple-lockfiles-short.cdx.json.golden"
	goldenLicenseCycloneDX                 = "testdata/license-cyclonedx.json.golden"
	goldenMinikubeKBOM                     = "testdata/minikube-kbom.json.golden"

	// Convert tests (convert_test.go)
	goldenNPMCycloneDX             = "testdata/npm-cyclonedx.json.golden"
	goldenConvertNPMWithSuppressed = "testdata/fixtures/convert/npm-with-suppressed.json.golden"

	// VM tests (vm_test.go)
	goldenAmazonLinux2GP2X86VM = "testdata/amazonlinux2-gp2-x86-vm.json.golden"
	goldenUbuntuGP2X86VM       = "testdata/ubuntu-gp2-x86-vm.json.golden"

	// Module tests (module_test.go)
	goldenSpring4ShellJRE8  = "testdata/spring4shell-jre8.json.golden"
	goldenSpring4ShellJRE11 = "testdata/spring4shell-jre11.json.golden"

	// Plugin tests (plugin_test.go)
	goldenCountPlugin020               = "testdata/count-0.2.0-plugin.txt.golden"
	goldenCountPlugin010WithBeforeFlag = "testdata/count-0.1.0-plugin-with-before-flag.txt.golden"
)

func initDB(t *testing.T) string {
	fixtureDir := filepath.Join("testdata", "fixtures", "db")
	entries, err := os.ReadDir(fixtureDir)
	require.NoError(t, err)

	var fixtures []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fixtures = append(fixtures, filepath.Join(fixtureDir, entry.Name()))
	}

	cacheDir := dbtest.InitDB(t, fixtures)
	defer dbtest.Close()

	err = metadata.NewClient(db.Dir(cacheDir)).Update(metadata.Metadata{
		Version:      db.SchemaVersion,
		NextUpdate:   time.Now().Add(24 * time.Hour),
		UpdatedAt:    time.Now(),
		DownloadedAt: time.Now(),
	})
	require.NoError(t, err)

	dbtest.InitJavaDB(t, cacheDir)
	return cacheDir
}

func initVEXRepository(t *testing.T, homeDir, cacheDir string) {
	t.Helper()

	// Copy config directory
	configSrc := "testdata/fixtures/vex/config/repository.yaml"
	configDst := filepath.Join(homeDir, ".trivy", "vex", "repository.yaml")
	testutil.CopyFile(t, configSrc, configDst)

	// Copy repository directory
	repoSrc := "testdata/fixtures/vex/repositories"
	repoDst := filepath.Join(cacheDir, "vex", "repositories")
	testutil.CopyDir(t, repoSrc, repoDst)

	// Copy VEX file
	vexSrc := "testdata/fixtures/vex/file/openvex.json"
	repoDir := filepath.Join(repoDst, "default")
	vexDst := filepath.Join(repoDir, "0.1", "openvex.json")
	testutil.CopyFile(t, vexSrc, vexDst)

	// Write a dummy cache metadata
	testutil.MustWriteJSON(t, filepath.Join(repoDir, "cache.json"), repo.CacheMetadata{
		UpdatedAt: time.Now(),
	})

	// Verify that necessary files exist
	requiredFiles := []string{
		configDst,
		filepath.Join(repoDir, "vex-repository.json"),
		filepath.Join(repoDir, "0.1", "index.json"),
		filepath.Join(repoDir, "0.1", "openvex.json"),
	}

	for _, file := range requiredFiles {
		require.FileExists(t, file)
	}
}

func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitPort(ctx context.Context, addr string) error {
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil && conn != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		default:
			time.Sleep(1 * time.Second)
		}
	}
}

func readReport(t *testing.T, filePath string) types.Report {
	t.Helper()

	f, err := os.Open(filePath)
	require.NoError(t, err, filePath)
	defer f.Close()

	var report types.Report
	err = json.NewDecoder(f).Decode(&report)
	require.NoError(t, err, filePath)

	// We don't compare history because the nano-seconds in "created" don't match
	report.Metadata.ImageConfig.History = nil

	// We don't compare repo digests because archives don't contain them
	report.Metadata.RepoDigests = nil
	for i := range report.Metadata.Layers {
		report.Metadata.Layers[i].Digest = ""
	}

	for i, result := range report.Results {
		for j := range result.Vulnerabilities {
			report.Results[i].Vulnerabilities[j].Layer.Digest = ""
		}

		sort.Slice(result.CustomResources, func(i, j int) bool {
			if result.CustomResources[i].Type != result.CustomResources[j].Type {
				return result.CustomResources[i].Type < result.CustomResources[j].Type
			}
			return result.CustomResources[i].FilePath < result.CustomResources[j].FilePath
		})
	}

	return report
}

func readCycloneDX(t *testing.T, filePath string) *cdx.BOM {
	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	bom := cdx.NewBOM()
	decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	require.NoError(t, err)

	// Sort components
	if bom.Components != nil {
		sort.Slice(*bom.Components, func(i, j int) bool {
			return (*bom.Components)[i].Name < (*bom.Components)[j].Name
		})
		for i := range *bom.Components {
			sort.Slice(*(*bom.Components)[i].Properties, func(ii, jj int) bool {
				return (*(*bom.Components)[i].Properties)[ii].Name < (*(*bom.Components)[i].Properties)[jj].Name
			})
		}
		sort.Slice(*bom.Vulnerabilities, func(i, j int) bool {
			return (*bom.Vulnerabilities)[i].ID < (*bom.Vulnerabilities)[j].ID
		})
	}

	return bom
}

func readSpdxJson(t *testing.T, filePath string) *spdx.Document {
	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	bom, err := spdxjson.Read(f)
	require.NoError(t, err)

	sort.Slice(bom.Relationships, func(i, j int) bool {
		if bom.Relationships[i].RefA.ElementRefID != bom.Relationships[j].RefA.ElementRefID {
			return bom.Relationships[i].RefA.ElementRefID < bom.Relationships[j].RefA.ElementRefID
		}
		return bom.Relationships[i].RefB.ElementRefID < bom.Relationships[j].RefB.ElementRefID
	})

	sort.Slice(bom.Files, func(i, j int) bool {
		return bom.Files[i].FileSPDXIdentifier < bom.Files[j].FileSPDXIdentifier
	})

	// We don't compare values which change each time an SBOM is generated
	bom.CreationInfo.Created = ""
	bom.DocumentNamespace = ""

	return bom
}

type OverrideFunc func(t *testing.T, want, got *types.Report)
type runOptions struct {
	wantErr  string
	override OverrideFunc
	fakeUUID string
}

// runTest runs Trivy with the given args and compares the output with the golden file.
// The output file is created in a temporary directory, unless -update flag is set, in which case
// the golden file is updated directly.
func runTest(t *testing.T, osArgs []string, wantFile string, format types.Format, opts runOptions) {
	// Ensure that tests updating golden files don't use override functions
	// as overrides would modify the golden file output
	if *update && opts.override != nil {
		require.Fail(t, "invalid test configuration", "cannot use override functions when -update is set")
	}

	if opts.fakeUUID != "" {
		uuid.SetFakeUUID(t, opts.fakeUUID)
	}
	// Set fake UUID v7 for ReportID generation. Format is not configurable.
	uuid.SetFakeUUIDV7(t, "017b7d41-e09f-7000-80ea-%012d")

	// Set up the output file
	outputFile := filepath.Join(t.TempDir(), "output.json")
	if *update {
		outputFile = wantFile
	}
	osArgs = append(osArgs, "--output", outputFile)

	// Run Trivy
	err := execute(osArgs)
	if opts.wantErr != "" {
		require.ErrorContains(t, err, opts.wantErr)
		return
	}
	require.NoError(t, err)

	// Compare want and got
	switch format {
	case types.FormatCycloneDX:
		compareCycloneDX(t, wantFile, outputFile)
	case types.FormatSPDXJSON:
		compareSPDXJson(t, wantFile, outputFile)
	case types.FormatJSON:
		compareReports(t, wantFile, outputFile, opts.override)
	case types.FormatTemplate, types.FormatSarif, types.FormatGitHub:
		compareRawFiles(t, wantFile, outputFile)
	default:
		require.Fail(t, "invalid format", "format: %s", format)
	}
}

func execute(osArgs []string) error {
	// viper.XXX() (e.g. viper.ReadInConfig()) affects the global state, so we need to reset it after each test.
	defer viper.Reset()

	// Set a fake time
	ctx := clock.With(context.Background(), time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))

	// Setup CLI App
	app := commands.NewApp()
	app.SetOut(io.Discard)
	app.SetArgs(osArgs)

	// Run Trivy
	return app.ExecuteContext(ctx)
}

func compareRawFiles(t *testing.T, wantFile, gotFile string) {
	want, err := os.ReadFile(wantFile)
	require.NoError(t, err)
	got, err := os.ReadFile(gotFile)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

func compareReports(t *testing.T, wantFile, gotFile string, override func(t *testing.T, want, got *types.Report)) {
	want := readReport(t, wantFile)
	got := readReport(t, gotFile)
	if override != nil {
		override(t, &want, &got)
	}

	assert.Equal(t, want, got)
}

func compareCycloneDX(t *testing.T, wantFile, gotFile string) {
	want := readCycloneDX(t, wantFile)
	got := readCycloneDX(t, gotFile)
	assert.Equal(t, want, got)

	// Validate CycloneDX output against the JSON schema
	validateReport(t, got.JSONSchema, got)
}

func compareSPDXJson(t *testing.T, wantFile, gotFile string) {
	want := readSpdxJson(t, wantFile)
	got := readSpdxJson(t, gotFile)
	assert.Equal(t, want, got)

	SPDXVersion, ok := strings.CutPrefix(want.SPDXVersion, "SPDX-")
	assert.True(t, ok)

	require.NoError(t, spdxlib.ValidateDocument(got))

	// Validate SPDX output against the JSON schema
	validateReport(t, fmt.Sprintf(SPDXSchema, SPDXVersion), got)
}

func validateReport(t *testing.T, schema string, report any) {
	schemaLoader := gojsonschema.NewReferenceLoader(schema)
	documentLoader := gojsonschema.NewGoLoader(report)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	require.NoError(t, err)

	if valid := result.Valid(); !valid {
		errs := xslices.Map(result.Errors(), func(err gojsonschema.ResultError) string {
			return err.String()
		})
		assert.True(t, valid, strings.Join(errs, "\n"))
	}
}

func overrideFuncs(funcs ...OverrideFunc) OverrideFunc {
	return func(t *testing.T, want, got *types.Report) {
		for _, f := range funcs {
			if f == nil {
				continue
			}
			f(t, want, got)
		}
	}
}

// overrideUID only checks for the presence of the package UID and clears the UID;
// the UID is calculated from the package metadata, but the UID does not match
// as it varies slightly depending on the mode of scanning, e.g. the digest of the layer.
func overrideUID(t *testing.T, want, got *types.Report) {
	for i, result := range got.Results {
		for j, vuln := range result.Vulnerabilities {
			assert.NotEmptyf(t, vuln.PkgIdentifier.UID, "UID is empty: %s", vuln.VulnerabilityID)
			// Do not compare UID as the package metadata is slightly different between the tests,
			// causing different UIDs.
			got.Results[i].Vulnerabilities[j].PkgIdentifier.UID = ""
		}
	}
	for i, result := range want.Results {
		for j := range result.Vulnerabilities {
			want.Results[i].Vulnerabilities[j].PkgIdentifier.UID = ""
		}
	}
}

// overrideFingerprint only checks for the presence of the fingerprint and clears it;
// the fingerprint is calculated from artifactID, target, pkgID, and vulnerabilityID,
// but may not match as the artifactID can vary depending on the scanning context.
func overrideFingerprint(t *testing.T, want, got *types.Report) {
	for i, result := range got.Results {
		for j, vuln := range result.Vulnerabilities {
			assert.NotEmptyf(t, vuln.Fingerprint, "Fingerprint is empty: %s", vuln.VulnerabilityID)
			assert.Lenf(t, vuln.Fingerprint, 71, "Fingerprint should be 71 characters (sha256: + 64 hex chars): %s", vuln.VulnerabilityID)
			// Do not compare Fingerprint as the artifactID varies between tests
			got.Results[i].Vulnerabilities[j].Fingerprint = ""
		}
	}
	for i, result := range want.Results {
		for j := range result.Vulnerabilities {
			want.Results[i].Vulnerabilities[j].Fingerprint = ""
		}
	}
}

// overrideDockerRemovedFields clears image config fields that were removed from Docker API
// cf. https://github.com/moby/moby/blob/1f71f2217d2196239ca52685ce6b3c4f93a1cc07/api/docs/CHANGELOG.md
func overrideDockerRemovedFields(_ *testing.T, want, got *types.Report) {
	// Clear Container field (removed in Docker API v1.45)
	got.Metadata.ImageConfig.Container = ""
	want.Metadata.ImageConfig.Container = ""

	// Clear Image field (removed in Docker API v1.50)
	got.Metadata.ImageConfig.Config.Image = ""
	want.Metadata.ImageConfig.Config.Image = ""

	// Clear Hostname field (removed in Docker API v1.50)
	got.Metadata.ImageConfig.Config.Hostname = ""
	want.Metadata.ImageConfig.Config.Hostname = ""

	// Clear DockerVersion field (omitted in Docker API v1.52)
	want.Metadata.ImageConfig.DockerVersion = ""
}

// overrideServerInfo verifies that Server info exists and then clears it.
// Server info is only populated in client/server mode (empty in standalone mode).
// When golden files are shared with standalone tests, this override is needed
// because standalone tests don't produce server info.
func overrideServerInfo(t *testing.T, want, got *types.Report) {
	// Verify that server info was actually fetched
	assert.NotEmpty(t, got.Trivy.Server.Version, "Server version should be set in client/server mode")

	// Clear server info for comparison with shared golden files
	got.Trivy.Server = types.VersionInfo{}
	want.Trivy.Server = types.VersionInfo{}
}
