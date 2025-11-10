package bottlerocket_inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(newBottlerocketInventoryAnalyzer())
}

const analyzerVersion = 1

var requiredFiles = []string{
	"aarch64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/application-inventory.json",
	"x86_64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/application-inventory.json",
}

type bottlerocketInventoryAnalyzer struct{}

func newBottlerocketInventoryAnalyzer() *bottlerocketInventoryAnalyzer {
	return &bottlerocketInventoryAnalyzer{}
}

type ApplicationInventory struct {
	Content []struct {
		Name            string    `json:"Name"`
		Publisher       string    `json:"Publisher"`
		Version         string    `json:"Version"`
		Release         string    `json:"Release"`
		Epoch           string    `json:"Epoch"`
		InstalledTime   time.Time `json:"InstalledTime"`
		ApplicationType string    `json:"ApplicationType"`
		Architecture    string    `json:"Architecture"`
		URL             string    `json:"Url"`
		Summary         string    `json:"Summary"`
	} `json:"Content"`
}

func (a bottlerocketInventoryAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	parsedInventorys, err := a.parseApplicationInventory(ctx, input.Content)
	if err != nil {
		return nil, err
	}

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: parsedInventorys,
			},
		},
	}, nil
}

func (a bottlerocketInventoryAnalyzer) parseApplicationInventory(_ context.Context, r io.Reader) ([]types.Package, error) {
	var pkgs []types.Package

	var applicationInventory ApplicationInventory
	if err := json.NewDecoder(r).Decode(&applicationInventory); err != nil {
		return nil, err
	}

	for _, app := range applicationInventory.Content {
		epoch, err := strconv.Atoi(app.Epoch)
		if err != nil {
			return nil, err
		}
		pkg := types.Package{
			Arch:    app.Architecture,
			Epoch:   epoch,
			Name:    app.Name,
			Version: app.Version,
		}

		if pkg.Name != "" && pkg.Version != "" {
			pkg.ID = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func (a bottlerocketInventoryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a bottlerocketInventoryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeBottlerocketInventory
}

func (a bottlerocketInventoryAnalyzer) Version() int {
	return analyzerVersion
}

// StaticPaths returns a list of static file paths to analyze
func (a bottlerocketInventoryAnalyzer) StaticPaths() []string {
	return requiredFiles
}
