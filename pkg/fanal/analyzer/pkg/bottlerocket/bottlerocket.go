package bottlerocket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterAnalyzer(newBottlerocketPkgAnalyzer())
}

const analyzerVersion = 1

var requiredFiles = []string{
	"aarch64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/application-inventory.json",
	"x86_64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/application-inventory.json",
}

type bottlerocketPkgAnalyzer struct{}

func newBottlerocketPkgAnalyzer() *bottlerocketPkgAnalyzer { return &bottlerocketPkgAnalyzer{} }

type ApplicationInventory struct {
	Content []struct {
		Name            string    `json:"Name"`
		Publisher       string    `json:"Publisher"`
		Version         string    `json:"Version"`
		Release         string    `json:"Release"`
		InstalledTime   time.Time `json:"InstalledTime"`
		ApplicationType string    `json:"ApplicationType"`
		Architecture    string    `json:"Architecture"`
		URL             string    `json:"Url"`
		Summary         string    `json:"Summary"`
	} `json:"Content"`
}

func (a bottlerocketPkgAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	ctx = log.WithContextPrefix(ctx, "application-inventory")
	parsedPkgs, err := a.parseApplicationInventory(ctx, input.Content)
	if err != nil {
		return nil, err
	}

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: parsedPkgs,
			},
		},
	}, nil
}

func (a bottlerocketPkgAnalyzer) parseApplicationInventory(ctx context.Context, r io.Reader) ([]types.Package, error) {
	var pkgs []types.Package

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var applicationInventory ApplicationInventory
	err = json.Unmarshal(b, &applicationInventory)
	if err != nil {
		return nil, err
	}

	for _, app := range applicationInventory.Content {
		pkg := types.Package{
			Arch:    app.Architecture,
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

func (a bottlerocketPkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a bottlerocketPkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeBottlerocket
}

func (a bottlerocketPkgAnalyzer) Version() int {
	return analyzerVersion
}

// StaticPaths returns a list of static file paths to analyze
func (a bottlerocketPkgAnalyzer) StaticPaths() []string {
	return requiredFiles
}
