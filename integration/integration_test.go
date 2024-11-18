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
	"github.com/samber/lo"
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

	_ "modernc.org/sqlite"
)

var update = flag.Bool("update", false, "update golden files")

const SPDXSchema = "https://raw.githubusercontent.com/spdx/spdx-spec/support/v%s/schemas/spdx-schema.json"

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
		Version:    db.SchemaVersion,
		NextUpdate: time.Now().Add(24 * time.Hour),
		UpdatedAt:  time.Now(),
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

	// We don't compare repo tags because the archive doesn't support it
	report.Metadata.RepoTags = nil
	report.Metadata.RepoDigests = nil

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
// If outputFile is empty, the output file is created in a temporary directory.
// If update is true, the golden file is updated.
func runTest(t *testing.T, osArgs []string, wantFile, outputFile string, format types.Format, opts runOptions) {
	if opts.fakeUUID != "" {
		uuid.SetFakeUUID(t, opts.fakeUUID)
	}

	if outputFile == "" {
		// Set up the output file
		outputFile = filepath.Join(t.TempDir(), "output.json")
		if *update && opts.override == nil {
			outputFile = wantFile
		}
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
	assert.EqualValues(t, string(want), string(got))
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
		errs := lo.Map(result.Errors(), func(err gojsonschema.ResultError, _ int) string {
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
