//go:build integration || vm_integration || module_integration

package integration

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/jsonloader"
	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/types"

	_ "modernc.org/sqlite"
)

var update = flag.Bool("update", false, "update golden files")

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
	defer db.Close()

	dbDir := filepath.Dir(db.Path(cacheDir))

	metadataFile := filepath.Join(dbDir, "metadata.json")
	f, err := os.Create(metadataFile)
	require.NoError(t, err)

	err = json.NewEncoder(f).Encode(metadata.Metadata{
		Version:    db.SchemaVersion,
		NextUpdate: time.Now().Add(24 * time.Hour),
		UpdatedAt:  time.Now(),
	})
	require.NoError(t, err)

	dbtest.InitJavaDB(t, cacheDir)
	return cacheDir
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

	// We don't compare values which change each time an SBOM is generated
	bom.Metadata.Timestamp = ""
	bom.Metadata.Component.BOMRef = ""
	bom.SerialNumber = ""
	if bom.Components != nil {
		sort.Slice(*bom.Components, func(i, j int) bool {
			return (*bom.Components)[i].Name < (*bom.Components)[j].Name
		})
		for i := range *bom.Components {
			(*bom.Components)[i].BOMRef = ""
			sort.Slice(*(*bom.Components)[i].Properties, func(ii, jj int) bool {
				return (*(*bom.Components)[i].Properties)[ii].Name < (*(*bom.Components)[i].Properties)[jj].Name
			})
		}
	}
	if bom.Dependencies != nil {
		for j := range *bom.Dependencies {
			(*bom.Dependencies)[j].Ref = ""
			(*bom.Dependencies)[j].Dependencies = nil
		}
	}

	return bom
}

func readSpdxJson(t *testing.T, filePath string) *spdx.Document2_2 {
	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	bom, err := jsonloader.Load2_2(f)
	require.NoError(t, err)

	sort.Slice(bom.Relationships, func(i, j int) bool {
		if bom.Relationships[i].RefA.ElementRefID != bom.Relationships[j].RefA.ElementRefID {
			return bom.Relationships[i].RefA.ElementRefID < bom.Relationships[j].RefA.ElementRefID
		}
		return bom.Relationships[i].RefB.ElementRefID < bom.Relationships[j].RefB.ElementRefID
	})

	// We don't compare values which change each time an SBOM is generated
	bom.CreationInfo.Created = ""
	bom.CreationInfo.DocumentNamespace = ""

	return bom
}

func execute(osArgs []string) error {
	// Setup CLI App
	app := commands.NewApp("dev")
	app.SetOut(io.Discard)

	// Run Trivy
	app.SetArgs(osArgs)
	return app.Execute()
}

func compareReports(t *testing.T, wantFile, gotFile string) {
	want := readReport(t, wantFile)
	got := readReport(t, gotFile)
	assert.Equal(t, want, got)
}

func compareCycloneDX(t *testing.T, wantFile, gotFile string) {
	want := readCycloneDX(t, wantFile)
	got := readCycloneDX(t, gotFile)
	assert.Equal(t, want, got)
}

func compareSpdxJson(t *testing.T, wantFile, gotFile string) {
	want := readSpdxJson(t, wantFile)
	got := readSpdxJson(t, gotFile)
	assert.Equal(t, want, got)
}
